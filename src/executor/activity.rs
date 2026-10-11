use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::active_process::{
    ActiveObservationProvider, ActiveObservationScope, platform_active_observation_provider,
};
use crate::persistence::{PersistedPlan, PersistedPlanEntry};
use crate::planner::{ActiveObservation, TargetContext, active_skip_reason};
use crate::scanner::{ScanItem, ScannerOptions, scan_roots};

use super::report::{ApplyEntryResult, ApplyEntryStatus};
use super::revalidate::revalidate_entry;

/// Saved file snapshots cannot show that a different artifact in the same target
/// was written after planning. Refresh target activity before applying the plan.
pub(super) struct ApplyActivity {
    contexts: Vec<TargetContext>,
    observation: ActiveObservation,
    window: Option<Duration>,
    skipped: Vec<PathBuf>,
    now: SystemTime,
    error: Option<String>,
    checked: HashMap<PathBuf, Option<String>>,
}

impl ApplyActivity {
    pub(super) fn new(document: &PersistedPlan, now: SystemTime) -> Self {
        let saved = &document.body.invocation.scanner_options;
        let options = ScannerOptions {
            follow_symlinks: saved.follow_symlinks,
            allow_name_only_targets: saved.allow_name_only_targets,
            cross_filesystems: saved.cross_filesystems,
            ignored_paths: saved.ignored_paths.iter().map(PathBuf::from).collect(),
            skipped_paths: saved.skipped_paths.iter().map(PathBuf::from).collect(),
        };
        let mut contexts = Vec::new();
        let mut error = None;
        match scan_roots(
            document.body.plan.input.roots.iter().map(PathBuf::from),
            &options,
        ) {
            Ok(items) => {
                for item in items {
                    if let ScanItem::TargetCandidate(candidate) = item
                        && candidate.evidence.is_some()
                    {
                        let mut context = candidate
                            .target_context
                            .unwrap_or_else(|| TargetContext::new(&candidate.path));
                        match std::path::absolute(&context.target_root) {
                            Ok(path) => context.target_root = path,
                            Err(cause) => {
                                error = Some(format!("cannot resolve target path: {cause}"));
                                continue;
                            }
                        }
                        contexts.push(context);
                    }
                }
            }
            Err(cause) => error = Some(format!("cannot recheck target activity: {cause}")),
        }
        let observation = platform_active_observation_provider().observe(
            &ActiveObservationScope::from_target_contexts(contexts.clone()),
        );
        Self {
            contexts,
            observation,
            error,
            window: document
                .body
                .invocation
                .planner_options
                .recent_write_keep_window_seconds
                .map(Duration::from_secs),
            skipped: options.skipped_paths,
            now,
            checked: HashMap::new(),
        }
    }

    pub(super) fn revalidate(&mut self, entry: &PersistedPlanEntry) -> ApplyEntryResult {
        let result = revalidate_entry(entry);
        if result.status != ApplyEntryStatus::WouldDelete {
            return result;
        }
        if let Some(reason) = self.skip_reason(Path::new(&entry.snapshot.path)) {
            return ApplyEntryResult::new(
                entry.snapshot.path.clone(),
                entry.action.clone(),
                ApplyEntryStatus::SkipStalePlan,
                entry.snapshot.size_bytes,
                format!("skip_stale_plan: {reason}"),
            );
        }
        result
    }

    fn skip_reason(&mut self, path: &Path) -> Option<String> {
        if let Some(error) = &self.error {
            return Some(error.clone());
        }
        let path = match std::path::absolute(path) {
            Ok(path) => path,
            Err(error) => return Some(format!("cannot resolve planned path: {error}")),
        };
        let context = self
            .contexts
            .iter()
            .filter(|context| path.starts_with(&context.target_root))
            .max_by_key(|context| context.target_root.components().count());
        let Some(context) = context else {
            return self
                .window
                .map(|_| "cannot identify the target for recent-write revalidation".to_string());
        };
        let root = &context.target_root;
        if let Some(reason) = self.checked.get(root) {
            return reason.clone();
        }
        let reason = active_skip_reason(Some(context), &self.observation).or_else(|| {
            self.window.and_then(|window| {
                match has_recent_write(root, &self.skipped, self.now, window) {
                    Ok(true) => Some(
                        "target was written within the recent-write keep window after planning"
                            .to_string(),
                    ),
                    Ok(false) => None,
                    Err(error) => Some(format!("cannot recheck target writes: {error}")),
                }
            })
        });
        self.checked.insert(root.clone(), reason.clone());
        reason
    }
}

fn has_recent_write(
    root: &Path,
    skipped: &[PathBuf],
    now: SystemTime,
    window: Duration,
) -> std::io::Result<bool> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        if skipped.iter().any(|skip| path.starts_with(skip)) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        let modified = metadata.modified()?;
        if now
            .duration_since(modified)
            .map_or(true, |age| age <= window)
        {
            return Ok(true);
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planner::{CargoTool, ObservedCargoProcess};

    fn guard(observation: ActiveObservation) -> ApplyActivity {
        let root = std::env::temp_dir().join("reclaim-activity-unit");
        ApplyActivity {
            contexts: vec![TargetContext::new(root.join("target")).with_project_root(&root)],
            observation,
            window: None,
            skipped: Vec::new(),
            now: SystemTime::now(),
            error: None,
            checked: HashMap::new(),
        }
    }

    #[test]
    fn fresh_process_observation_blocks_the_matching_target() {
        let root = std::env::temp_dir().join("reclaim-activity-unit");
        let observation =
            ActiveObservation::complete([
                ObservedCargoProcess::new(CargoTool::Cargo).with_cwd(&root)
            ]);
        let mut activity = guard(observation);
        let reason = activity.skip_reason(&root.join("target/debug/deps/old.rlib"));
        assert!(reason.is_some_and(|reason| reason.contains("observed Cargo or rustc")));
    }

    #[test]
    fn failed_process_inspection_preserves_the_target() {
        let root = std::env::temp_dir().join("reclaim-activity-unit");
        let mut activity = guard(ActiveObservation::failed("procfs unavailable"));
        let reason = activity.skip_reason(&root.join("target/debug/deps/old.rlib"));
        assert!(reason.is_some_and(|reason| reason.contains("procfs unavailable")));
    }

    #[test]
    fn an_unrelated_process_does_not_block_the_target() {
        let root = std::env::temp_dir().join("reclaim-activity-unit");
        let observation =
            ActiveObservation::complete([ObservedCargoProcess::new(CargoTool::Cargo)
                .with_cwd(std::env::temp_dir().join("other-project"))]);
        let mut activity = guard(observation);
        assert!(
            activity
                .skip_reason(&root.join("target/debug/deps/old.rlib"))
                .is_none()
        );
    }
}
