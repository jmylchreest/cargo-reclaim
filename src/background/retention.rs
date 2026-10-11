//! Retention for the service's own state files.
//!
//! Every background cycle writes a plan JSON and appends run-log records, and a
//! terminal `apply` writes a report. Without a bound those directories grow for as
//! long as the service runs — a reclaim tool filling the disk it exists to free.
//! This module enforces the bound: newest-first pruning of the timestamped plan and
//! report directories (by count, age, and total bytes) plus size-triggered rotation
//! of the append-only logs.
//!
//! Pruning never removes the newest file in a directory: the most recent plan is the
//! audit record for the run that just happened, and `scheduler service status` reads
//! it.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Plan files kept per instance when the config does not say otherwise.
pub const DEFAULT_KEEP_PLANS: usize = 32;
/// Age past which a plan file is pruned even if the count budget allows it.
pub const DEFAULT_MAX_PLAN_AGE: Duration = Duration::from_secs(14 * 24 * 60 * 60);
/// Total bytes the plans directory may occupy. A single plan for a large workspace
/// can reach hundreds of megabytes, so the byte budget — not the count — is usually
/// the binding constraint.
pub const DEFAULT_MAX_PLANS_BYTES: u64 = 1024 * 1024 * 1024;
/// Terminal `apply` reports kept.
pub const DEFAULT_KEEP_REPORTS: usize = 32;
/// Size at which `runs.jsonl` / `scheduler.log` are rotated.
pub const DEFAULT_MAX_LOG_BYTES: u64 = 64 * 1024 * 1024;
/// Rotated generations kept (`runs.jsonl.1`, `runs.jsonl.2`, …).
pub const DEFAULT_KEEP_ROTATED_LOGS: usize = 2;

/// Resolved retention limits. `None` on a budget means that budget is not enforced;
/// the remaining budgets still are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateRetentionPolicy {
    pub enabled: bool,
    pub keep_plans: Option<usize>,
    pub max_plan_age: Option<Duration>,
    pub max_plans_bytes: Option<u64>,
    pub keep_reports: Option<usize>,
    pub max_log_bytes: Option<u64>,
    pub keep_rotated_logs: usize,
}

impl Default for StateRetentionPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            keep_plans: Some(DEFAULT_KEEP_PLANS),
            max_plan_age: Some(DEFAULT_MAX_PLAN_AGE),
            max_plans_bytes: Some(DEFAULT_MAX_PLANS_BYTES),
            keep_reports: Some(DEFAULT_KEEP_REPORTS),
            max_log_bytes: Some(DEFAULT_MAX_LOG_BYTES),
            keep_rotated_logs: DEFAULT_KEEP_ROTATED_LOGS,
        }
    }
}

impl StateRetentionPolicy {
    /// A policy that keeps everything. Used when the operator sets
    /// `[scheduler.retention] enabled = false`.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::default()
        }
    }
}

/// What a prune pass actually removed. Callers surface this in the run log / status
/// so silent deletion of audit records never happens.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StateRetentionOutcome {
    pub removed_plans: usize,
    pub removed_reports: usize,
    pub reclaimed_bytes: u64,
    pub rotated_logs: usize,
}

impl StateRetentionOutcome {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    fn merge(&mut self, other: Self) {
        self.removed_plans += other.removed_plans;
        self.removed_reports += other.removed_reports;
        self.reclaimed_bytes = self.reclaimed_bytes.saturating_add(other.reclaimed_bytes);
        self.rotated_logs += other.rotated_logs;
    }
}

#[derive(Debug)]
pub enum StateRetentionError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl fmt::Display for StateRetentionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(
                    formatter,
                    "state retention failed for {}: {source}",
                    path.display()
                )
            }
        }
    }
}

impl Error for StateRetentionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
        }
    }
}

pub type StateRetentionResult<T> = Result<T, StateRetentionError>;

/// Prune the plans directory: newest-first, honouring count, age, and byte budgets.
/// The newest plan is always kept.
pub fn prune_plans_dir(
    plans_dir: &Path,
    policy: &StateRetentionPolicy,
    now: SystemTime,
) -> StateRetentionResult<StateRetentionOutcome> {
    if !policy.enabled {
        return Ok(StateRetentionOutcome::default());
    }
    let removed = prune_timestamped_dir(
        plans_dir,
        policy.keep_plans,
        policy.max_plan_age,
        policy.max_plans_bytes,
        now,
    )?;
    Ok(StateRetentionOutcome {
        removed_plans: removed.count,
        reclaimed_bytes: removed.bytes,
        ..StateRetentionOutcome::default()
    })
}

/// Prune the terminal-apply reports directory. Reports are small individually but
/// unbounded in number, so only the count and age budgets bind.
pub fn prune_reports_dir(
    reports_dir: &Path,
    policy: &StateRetentionPolicy,
    now: SystemTime,
) -> StateRetentionResult<StateRetentionOutcome> {
    if !policy.enabled {
        return Ok(StateRetentionOutcome::default());
    }
    let removed = prune_timestamped_dir(
        reports_dir,
        policy.keep_reports,
        policy.max_plan_age,
        policy.max_plans_bytes,
        now,
    )?;
    Ok(StateRetentionOutcome {
        removed_reports: removed.count,
        reclaimed_bytes: removed.bytes,
        ..StateRetentionOutcome::default()
    })
}

/// Rotate an append-only log once it exceeds the size budget: `log` becomes `log.1`,
/// `log.1` becomes `log.2`, and the oldest generation beyond the keep count is
/// dropped. Rotation is a rename, so a writer holding the old descriptor keeps
/// writing into the rotated file rather than losing records mid-line.
pub fn rotate_log(
    log_path: &Path,
    policy: &StateRetentionPolicy,
) -> StateRetentionResult<StateRetentionOutcome> {
    if !policy.enabled {
        return Ok(StateRetentionOutcome::default());
    }
    let Some(max_bytes) = policy.max_log_bytes else {
        return Ok(StateRetentionOutcome::default());
    };

    let size = match fs::metadata(log_path) {
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Ok(_) => return Ok(StateRetentionOutcome::default()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(StateRetentionOutcome::default());
        }
        Err(source) => return Err(io_error(log_path, source)),
    };
    if size <= max_bytes {
        return Ok(StateRetentionOutcome::default());
    }

    let mut reclaimed = 0_u64;
    // Drop the generation that would fall off the end, then shift the rest up.
    if policy.keep_rotated_logs == 0 {
        reclaimed = reclaimed.saturating_add(size);
        remove_file_if_present(log_path)?;
        return Ok(StateRetentionOutcome {
            reclaimed_bytes: reclaimed,
            rotated_logs: 1,
            ..StateRetentionOutcome::default()
        });
    }

    let oldest = rotated_log_path(log_path, policy.keep_rotated_logs);
    if let Some(size) = file_size_if_present(&oldest)? {
        reclaimed = reclaimed.saturating_add(size);
    }
    remove_file_if_present(&oldest)?;
    for generation in (1..policy.keep_rotated_logs).rev() {
        let from = rotated_log_path(log_path, generation);
        let to = rotated_log_path(log_path, generation + 1);
        rename_if_present(&from, &to)?;
    }
    rename_if_present(log_path, &rotated_log_path(log_path, 1))?;

    Ok(StateRetentionOutcome {
        reclaimed_bytes: reclaimed,
        rotated_logs: 1,
        ..StateRetentionOutcome::default()
    })
}

/// Apply every budget to one instance's state and log directories in a single pass.
pub fn prune_service_state(
    plans_dir: &Path,
    reports_dir: &Path,
    log_paths: &[&Path],
    policy: &StateRetentionPolicy,
    now: SystemTime,
) -> StateRetentionResult<StateRetentionOutcome> {
    let mut outcome = prune_plans_dir(plans_dir, policy, now)?;
    outcome.merge(prune_reports_dir(reports_dir, policy, now)?);
    for log_path in log_paths {
        outcome.merge(rotate_log(log_path, policy)?);
    }
    Ok(outcome)
}

#[derive(Debug, Default, Clone, Copy)]
struct PruneTally {
    count: usize,
    bytes: u64,
}

struct StateFile {
    path: PathBuf,
    modified: SystemTime,
    size: u64,
}

fn prune_timestamped_dir(
    dir: &Path,
    keep_count: Option<usize>,
    max_age: Option<Duration>,
    max_bytes: Option<u64>,
    now: SystemTime,
) -> StateRetentionResult<PruneTally> {
    let mut files = match read_state_files(dir)? {
        Some(files) => files,
        None => return Ok(PruneTally::default()),
    };
    // Newest first: budgets are spent on the most recent files, and index 0 — the
    // record for the run that just completed — is never a deletion candidate.
    files.sort_by_key(|file| std::cmp::Reverse(file.modified));

    let mut tally = PruneTally::default();
    let mut cumulative_bytes = 0_u64;
    for (index, file) in files.iter().enumerate() {
        cumulative_bytes = cumulative_bytes.saturating_add(file.size);
        if index == 0 {
            continue;
        }

        let over_count = keep_count.is_some_and(|keep| keep > 0 && index >= keep);
        let over_age = max_age.is_some_and(|max_age| {
            now.duration_since(file.modified)
                .is_ok_and(|age| age > max_age)
        });
        let over_bytes = max_bytes.is_some_and(|max_bytes| cumulative_bytes > max_bytes);
        if !(over_count || over_age || over_bytes) {
            continue;
        }

        match fs::remove_file(&file.path) {
            Ok(()) => {
                tally.count += 1;
                tally.bytes = tally.bytes.saturating_add(file.size);
                // The file is gone, so it no longer spends the byte budget for the
                // older files behind it.
                cumulative_bytes = cumulative_bytes.saturating_sub(file.size);
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                cumulative_bytes = cumulative_bytes.saturating_sub(file.size);
            }
            Err(source) => return Err(io_error(&file.path, source)),
        }
    }

    Ok(tally)
}

/// `Ok(None)` when the directory does not exist yet — nothing to prune, not an error.
fn read_state_files(dir: &Path) -> StateRetentionResult<Option<Vec<StateFile>>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error(dir, source)),
    };

    let mut files = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| io_error(dir, source))?;
        let path = entry.path();
        if path.extension().is_none_or(|extension| extension != "json") {
            continue;
        }
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            // Raced with another writer/pruner; the file is already gone.
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => return Err(io_error(&path, source)),
        };
        if !metadata.is_file() {
            continue;
        }
        let modified = metadata
            .modified()
            .map_err(|source| io_error(&path, source))?;
        files.push(StateFile {
            path,
            modified,
            size: metadata.len(),
        });
    }
    Ok(Some(files))
}

fn rotated_log_path(log_path: &Path, generation: usize) -> PathBuf {
    let mut name = log_path.as_os_str().to_os_string();
    name.push(format!(".{generation}"));
    PathBuf::from(name)
}

fn file_size_if_present(path: &Path) -> StateRetentionResult<Option<u64>> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata.len())),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(io_error(path, source)),
    }
}

fn remove_file_if_present(path: &Path) -> StateRetentionResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(path, source)),
    }
}

fn rename_if_present(from: &Path, to: &Path) -> StateRetentionResult<()> {
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error(from, source)),
    }
}

fn io_error(path: &Path, source: std::io::Error) -> StateRetentionError {
    StateRetentionError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let unique = format!(
                "cargo-reclaim-retention-{label}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            );
            let path = std::env::temp_dir().join(unique);
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn write_plan(dir: &Path, name: &str, size: usize, modified: SystemTime) -> PathBuf {
        fs::create_dir_all(dir).expect("create plans dir");
        let path = dir.join(name);
        let mut file = fs::File::create(&path).expect("create plan");
        file.write_all(&vec![b'x'; size]).expect("write plan");
        drop(file);
        let times = fs::FileTimes::new().set_modified(modified);
        let handle = fs::File::options()
            .write(true)
            .open(&path)
            .expect("open plan for times");
        handle.set_times(times).expect("set plan mtime");
        path
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .expect("read dir")
            .map(|entry| entry.expect("entry").file_name().to_string_lossy().into())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn keeps_only_the_newest_plans_by_count() {
        let temp = TempDir::new("count");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        for index in 0..5 {
            write_plan(
                &temp.path,
                &format!("plan-{index}.json"),
                16,
                now - Duration::from_secs(60 * (5 - index) as u64),
            );
        }
        let policy = StateRetentionPolicy {
            keep_plans: Some(2),
            max_plan_age: None,
            max_plans_bytes: None,
            ..StateRetentionPolicy::default()
        };

        let outcome = prune_plans_dir(&temp.path, &policy, now).expect("prune");

        assert_eq!(outcome.removed_plans, 3);
        assert_eq!(names(&temp.path), vec!["plan-3.json", "plan-4.json"]);
    }

    #[test]
    fn drops_plans_past_the_age_budget_but_keeps_the_newest() {
        let temp = TempDir::new("age");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        write_plan(&temp.path, "old.json", 16, now - Duration::from_secs(9_000));
        write_plan(
            &temp.path,
            "ancient.json",
            16,
            now - Duration::from_secs(90_000),
        );
        let policy = StateRetentionPolicy {
            keep_plans: None,
            max_plan_age: Some(Duration::from_secs(600)),
            max_plans_bytes: None,
            ..StateRetentionPolicy::default()
        };

        let outcome = prune_plans_dir(&temp.path, &policy, now).expect("prune");

        // `old.json` is past the age budget too, but it is the newest file and the
        // audit record for the last run, so it survives.
        assert_eq!(outcome.removed_plans, 1);
        assert_eq!(names(&temp.path), vec!["old.json"]);
    }

    #[test]
    fn enforces_the_total_byte_budget_newest_first() {
        let temp = TempDir::new("bytes");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        for index in 0..4 {
            write_plan(
                &temp.path,
                &format!("plan-{index}.json"),
                100,
                now - Duration::from_secs(60 * (4 - index) as u64),
            );
        }
        let policy = StateRetentionPolicy {
            keep_plans: None,
            max_plan_age: None,
            max_plans_bytes: Some(250),
            ..StateRetentionPolicy::default()
        };

        let outcome = prune_plans_dir(&temp.path, &policy, now).expect("prune");

        assert_eq!(outcome.removed_plans, 2);
        assert_eq!(outcome.reclaimed_bytes, 200);
        assert_eq!(names(&temp.path), vec!["plan-2.json", "plan-3.json"]);
    }

    #[test]
    fn a_single_oversized_plan_is_still_kept() {
        let temp = TempDir::new("oversize");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        write_plan(&temp.path, "huge.json", 4_096, now);
        let policy = StateRetentionPolicy {
            max_plans_bytes: Some(16),
            ..StateRetentionPolicy::default()
        };

        let outcome = prune_plans_dir(&temp.path, &policy, now).expect("prune");

        assert!(outcome.is_empty());
        assert_eq!(names(&temp.path), vec!["huge.json"]);
    }

    #[test]
    fn ignores_non_json_files_and_missing_directories() {
        let temp = TempDir::new("mixed");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        write_plan(
            &temp.path,
            "plan-0.json",
            16,
            now - Duration::from_secs(600),
        );
        write_plan(&temp.path, "plan-1.json", 16, now);
        fs::write(temp.path.join("service.lock"), b"{}").expect("write lock");
        let policy = StateRetentionPolicy {
            keep_plans: Some(1),
            max_plan_age: None,
            max_plans_bytes: None,
            ..StateRetentionPolicy::default()
        };

        let outcome = prune_plans_dir(&temp.path, &policy, now).expect("prune");
        assert_eq!(outcome.removed_plans, 1);
        assert_eq!(names(&temp.path), vec!["plan-1.json", "service.lock"]);

        let missing = temp.path.join("does-not-exist");
        assert!(
            prune_plans_dir(&missing, &policy, now)
                .expect("missing dir is not an error")
                .is_empty()
        );
    }

    #[test]
    fn rotates_the_run_log_and_drops_the_oldest_generation() {
        let temp = TempDir::new("rotate");
        let log_path = temp.path.join("runs.jsonl");
        fs::write(&log_path, vec![b'x'; 512]).expect("write log");
        fs::write(rotated_log_path(&log_path, 1), b"first").expect("write gen 1");
        fs::write(rotated_log_path(&log_path, 2), b"second").expect("write gen 2");
        let policy = StateRetentionPolicy {
            max_log_bytes: Some(256),
            keep_rotated_logs: 2,
            ..StateRetentionPolicy::default()
        };

        let outcome = rotate_log(&log_path, &policy).expect("rotate");

        assert_eq!(outcome.rotated_logs, 1);
        assert!(!log_path.exists());
        assert_eq!(
            fs::read(rotated_log_path(&log_path, 1)).expect("gen 1"),
            vec![b'x'; 512]
        );
        assert_eq!(
            fs::read(rotated_log_path(&log_path, 2)).expect("gen 2"),
            b"first"
        );
        assert!(!rotated_log_path(&log_path, 3).exists());
    }

    #[test]
    fn leaves_a_log_under_the_size_budget_alone() {
        let temp = TempDir::new("rotate-small");
        let log_path = temp.path.join("runs.jsonl");
        fs::write(&log_path, b"one line\n").expect("write log");
        let policy = StateRetentionPolicy {
            max_log_bytes: Some(1024),
            ..StateRetentionPolicy::default()
        };

        let outcome = rotate_log(&log_path, &policy).expect("rotate");

        assert!(outcome.is_empty());
        assert!(log_path.exists());
        assert!(!rotated_log_path(&log_path, 1).exists());
    }

    #[test]
    fn a_disabled_policy_removes_nothing() {
        let temp = TempDir::new("disabled");
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        for index in 0..4 {
            write_plan(
                &temp.path,
                &format!("plan-{index}.json"),
                4_096,
                now - Duration::from_secs(60 * 60 * 24 * 400),
            );
        }
        let log_path = temp.path.join("runs.jsonl");
        fs::write(&log_path, vec![b'x'; 4_096]).expect("write log");

        let policy = StateRetentionPolicy::disabled();
        let outcome =
            prune_service_state(&temp.path, &temp.path, &[&log_path], &policy, now).expect("prune");

        assert!(outcome.is_empty());
        assert_eq!(fs::read_dir(&temp.path).expect("read dir").count(), 5);
    }
}
