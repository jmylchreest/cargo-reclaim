use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::background::StateRetentionPolicy;

use super::error::ConfigError;
use super::parse::{
    BackgroundDocument, ConfigDocument, PlannerConfig, PolicyConfig, TriggerDocument,
};
use super::values::{
    parse_config_duration, parse_config_percentage_basis_points, parse_config_size,
    resolve_config_path,
};

/// Firing cadence used when a background block omits `every`.
const DEFAULT_BACKGROUND_CHECK_EVERY: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimConfig {
    pub version: u16,
    pub roots: Vec<PathBuf>,
    pub ignored_paths: Vec<PathBuf>,
    pub skipped_paths: Vec<PathBuf>,
    pub policy: Option<String>,
    pub whole_target: Option<WholeTargetConfig>,
    pub allow_unattended_whole_target_delete: Option<bool>,
    pub policy_thresholds: PolicyThresholdConfig,
    pub background: BackgroundConfig,
    pub scanner: ScannerConfig,
    pub scheduler: SchedulerConfig,
    pub recent_write_keep_window: Option<Duration>,
    /// Age below which the `sweep` policy will not reclaim a final binary.
    pub sweep_older_than: Option<Duration>,
    pub keep_size_bytes: Option<u64>,
    pub keep_rustc_hashes: Vec<u64>,
    pub keep_installed_toolchains: bool,
    pub keep_toolchains: Vec<String>,
    /// Non-fatal deprecation notices gathered while parsing (e.g. flat
    /// `[background]` keys). Callers should surface these to the user.
    pub deprecations: Vec<String>,
}

impl ReclaimConfig {
    pub(super) fn from_document(
        document: ConfigDocument,
        relative_base: Option<&Path>,
    ) -> Result<Self, ConfigError> {
        let mut deprecations = Vec::new();
        let ConfigDocument {
            version,
            roots,
            ignore,
            skip,
            policy,
            scanner,
            planner,
            scheduler,
            background,
        } = document;
        if version != 1 {
            return Err(ConfigError::UnsupportedVersion(version));
        }

        let policy_keep_recent_projects = policy
            .as_ref()
            .and_then(|policy| policy.keep_recent_projects.as_deref())
            .map(parse_config_duration)
            .transpose()?;
        let PlannerConfig {
            recent_write_keep_window,
            sweep_older_than,
            keep_days,
            keep_size,
            keep_rustc_hashes,
            keep_installed_toolchains,
            keep_toolchains,
        } = planner.unwrap_or_default();
        let planner_recent_write_keep_window = recent_write_keep_window
            .as_deref()
            .map(parse_config_duration)
            .transpose()?;
        let planner_sweep_older_than = sweep_older_than
            .as_deref()
            .map(parse_config_duration)
            .transpose()?;
        let planner_keep_days_window = keep_days
            .map(|days| {
                if days == 0 {
                    return Err(ConfigError::InvalidDuration(days.to_string()));
                }
                Ok(Duration::from_secs(days.saturating_mul(24 * 60 * 60)))
            })
            .transpose()?;
        let planner_keep_size_bytes = keep_size.as_deref().map(parse_config_size).transpose()?;
        let policy_thresholds = policy
            .as_ref()
            .map(PolicyThresholdConfig::from_document)
            .transpose()?
            .unwrap_or_default();
        let scheduler = scheduler.unwrap_or_default().resolve_paths(relative_base);
        // Surface a malformed retention budget at load time rather than mid-run,
        // when the service is already holding the lock.
        scheduler.retention.resolve()?;
        let background = background
            .map(|document| {
                BackgroundConfig::from_document(
                    document,
                    policy_thresholds.max_target_size_bytes,
                    &mut deprecations,
                )
            })
            .transpose()?
            .unwrap_or_default();

        Ok(Self {
            version,
            roots: roots
                .into_iter()
                .map(|path| resolve_config_path(path, relative_base))
                .collect(),
            ignored_paths: ignore
                .into_iter()
                .map(|path| resolve_config_path(path, relative_base))
                .collect(),
            skipped_paths: skip
                .into_iter()
                .map(|path| resolve_config_path(path, relative_base))
                .collect(),
            policy: policy.as_ref().and_then(|policy| policy.mode.clone()),
            whole_target: policy
                .as_ref()
                .and_then(|policy| policy.whole_target.as_deref())
                .map(WholeTargetConfig::parse)
                .transpose()?,
            allow_unattended_whole_target_delete: policy
                .as_ref()
                .and_then(|policy| policy.allow_unattended_whole_target_delete),
            policy_thresholds,
            background,
            scanner: scanner.unwrap_or_default(),
            scheduler,
            recent_write_keep_window: planner_recent_write_keep_window
                .or(planner_keep_days_window)
                .or(policy_keep_recent_projects),
            sweep_older_than: planner_sweep_older_than,
            keep_size_bytes: planner_keep_size_bytes,
            keep_rustc_hashes,
            keep_installed_toolchains,
            keep_toolchains,
            deprecations,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WholeTargetConfig {
    Off,
    Confirm,
    Delete,
}

impl WholeTargetConfig {
    fn parse(value: &str) -> Result<Self, ConfigError> {
        match value {
            "off" => Ok(Self::Off),
            "confirm" => Ok(Self::Confirm),
            "delete" => Ok(Self::Delete),
            _ => Err(ConfigError::InvalidWholeTargetMode(value.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PolicyThresholdConfig {
    pub max_target_size_bytes: Option<u64>,
    pub target_size_goal_bytes: Option<u64>,
    pub unattended_allowed: Option<bool>,
}

impl PolicyThresholdConfig {
    fn from_document(document: &PolicyConfig) -> Result<Self, ConfigError> {
        Ok(Self {
            max_target_size_bytes: document
                .max_target_size
                .as_deref()
                .map(parse_config_size)
                .transpose()?,
            target_size_goal_bytes: document
                .target_size_goal
                .as_deref()
                .map(parse_config_size)
                .transpose()?,
            unattended_allowed: document.unattended_allowed,
        })
    }
}

/// Resident background watcher configuration: any number of independent
/// [`triggers`](Self::triggers). Each trigger owns its own cadence, limiter,
/// policy, and disruptiveness, so a config can mix (say) a safe 30-minute
/// routine trim with an aggressive disk-pressure trigger that stops builds and
/// nukes targets. `target_free_disk_bytes` is a budget goal shared by limited runs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BackgroundConfig {
    pub enabled: Option<bool>,
    pub target_free_disk_bytes: Option<u64>,
    pub triggers: Vec<BackgroundTrigger>,
}

/// One background trigger. A firing cadence plus, independently configurable:
/// an optional limiter gate (when it cleans), an optional policy override (what
/// it removes), an optional whole-target override, and its disruptiveness toward
/// active builds. A trigger with no limiter fires on every `every`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackgroundTrigger {
    pub every: Duration,
    pub policy: Option<String>,
    /// Per-trigger whole-target override (defaults to the global `[policy]` value).
    pub whole_target: Option<WholeTargetConfig>,
    /// Delete in-use artifacts / whole targets even while a build runs (the build
    /// then fails when its files vanish). Off by default; safe triggers protect
    /// active builds entirely.
    pub interrupt_active_build: bool,
    /// Before cleaning, terminate the `cargo`/`rustc` processes building targets
    /// under the config roots (SIGTERM, brief grace, then SIGKILL), so the disk
    /// fill stops and there is no active build to protect. Implies disruptive.
    pub kill_active_builds: bool,
    pub limiter: BackgroundLimiter,
}

/// The threshold gate applied to a fired run. Empty ⇒ always clean; otherwise
/// clean only when a threshold is breached, and do nothing when it passes.
///
/// `disk_free_below_basis_points` and `min_free_disk_bytes` are measured from a
/// cheap free-space check. `max_target_size_bytes` is a per-target high-water
/// mark; a block that sets it makes its poll scan target sizes, so leave it
/// unset for a cheap disk-only trigger.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BackgroundLimiter {
    pub max_target_size_bytes: Option<u64>,
    pub disk_free_below_basis_points: Option<u16>,
    pub min_free_disk_bytes: Option<u64>,
}

impl BackgroundLimiter {
    /// No limiter configured, so a fired run always cleans.
    pub fn is_empty(&self) -> bool {
        self.max_target_size_bytes.is_none()
            && self.disk_free_below_basis_points.is_none()
            && self.min_free_disk_bytes.is_none()
    }

    /// Whether evaluating this limiter needs a target-size scan.
    pub fn needs_target_scan(&self) -> bool {
        self.max_target_size_bytes.is_some()
    }
}

impl BackgroundTrigger {
    fn from_document(document: TriggerDocument) -> Result<Self, ConfigError> {
        let every = document
            .every
            .as_deref()
            .map(parse_config_duration)
            .transpose()?
            .unwrap_or(DEFAULT_BACKGROUND_CHECK_EVERY);
        Ok(Self {
            every,
            policy: document.policy,
            whole_target: document
                .whole_target
                .as_deref()
                .map(WholeTargetConfig::parse)
                .transpose()?,
            interrupt_active_build: document.interrupt_active_build,
            kill_active_builds: document.kill_active_builds,
            limiter: BackgroundLimiter {
                max_target_size_bytes: document
                    .max_target_size
                    .as_deref()
                    .map(parse_config_size)
                    .transpose()?,
                disk_free_below_basis_points: document
                    .only_when_disk_free_below
                    .as_deref()
                    .map(parse_config_percentage_basis_points)
                    .transpose()?,
                min_free_disk_bytes: document
                    .min_free_disk
                    .as_deref()
                    .map(parse_config_size)
                    .transpose()?,
            },
        })
    }
}

impl BackgroundConfig {
    pub(super) fn from_document(
        document: BackgroundDocument,
        policy_max_target_size_bytes: Option<u64>,
        deprecations: &mut Vec<String>,
    ) -> Result<Self, ConfigError> {
        let mut triggers = Vec::new();
        for trigger in document.trigger {
            triggers.push(BackgroundTrigger::from_document(trigger)?);
        }

        // Backward compatibility: the flat pre-0.3 `mode`/`check_every`/threshold
        // keys normalize into a single trigger appended to the list.
        let uses_flat = document.mode.is_some()
            || document.check_every.is_some()
            || document.only_when_disk_free_below.is_some()
            || document.min_free_disk.is_some();
        if uses_flat {
            deprecations.push(
                "[background] flat `mode`/`check_every`/`only_when_disk_free_below`/`min_free_disk` \
                 are deprecated; use one or more [[background.trigger]] blocks"
                    .to_string(),
            );
            let mode = document.mode.map(BackgroundMode::parse).transpose()?;
            let every = document
                .check_every
                .as_deref()
                .map(parse_config_duration)
                .transpose()?
                .unwrap_or(DEFAULT_BACKGROUND_CHECK_EVERY);
            // Parse the disk keys unconditionally so invalid values are always
            // rejected, even under a `periodic` mode that ignores them.
            let disk_free_below_basis_points = document
                .only_when_disk_free_below
                .as_deref()
                .map(parse_config_percentage_basis_points)
                .transpose()?;
            let min_free_disk_bytes = document
                .min_free_disk
                .as_deref()
                .map(parse_config_size)
                .transpose()?;
            // Old `threshold` mode cleaned only when a limiter was breached (also
            // honoring `[policy].max_target_size`); `periodic`/unspecified always cleaned.
            let limiter = match mode {
                Some(BackgroundMode::Threshold) => BackgroundLimiter {
                    max_target_size_bytes: policy_max_target_size_bytes,
                    disk_free_below_basis_points,
                    min_free_disk_bytes,
                },
                _ => BackgroundLimiter::default(),
            };
            triggers.push(BackgroundTrigger {
                every,
                policy: None,
                whole_target: None,
                interrupt_active_build: false,
                kill_active_builds: false,
                limiter,
            });
        }

        Ok(Self {
            enabled: document.enabled,
            target_free_disk_bytes: document
                .target_free_disk
                .as_deref()
                .map(parse_config_size)
                .transpose()?,
            triggers,
        })
    }
}

/// Only retained to parse the deprecated flat `mode` string; removed in 0.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackgroundMode {
    Periodic,
    Threshold,
}

impl BackgroundMode {
    fn parse(value: String) -> Result<Self, ConfigError> {
        match value.as_str() {
            "periodic" => Ok(Self::Periodic),
            "threshold" => Ok(Self::Threshold),
            _ => Err(ConfigError::InvalidBackgroundMode(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScannerConfig {
    pub follow_symlinks: Option<bool>,
    pub allow_name_only_targets: Option<bool>,
    pub cross_filesystems: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerConfig {
    pub name: Option<String>,
    pub at: Option<String>,
    pub mode: Option<String>,
    pub policy: Option<String>,
    pub allow_unattended_cleanup: Option<bool>,
    pub allow_unattended_high_policy: Option<bool>,
    pub state_dir: Option<PathBuf>,
    pub log_dir: Option<PathBuf>,
    #[serde(default)]
    pub retention: SchedulerRetentionConfig,
}

impl SchedulerConfig {
    pub(super) fn resolve_paths(mut self, relative_base: Option<&Path>) -> Self {
        self.state_dir = self
            .state_dir
            .map(|path| resolve_config_path(path, relative_base));
        self.log_dir = self
            .log_dir
            .map(|path| resolve_config_path(path, relative_base));
        self
    }
}

/// `[scheduler.retention]` — how much of the service's own state (plan snapshots,
/// apply reports, run logs) is kept. Every budget has a default, so an existing
/// config with no `[scheduler.retention]` block is still bounded.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchedulerRetentionConfig {
    /// Set `false` to keep every state file forever. The directories then grow
    /// without bound; only do this when something external prunes them.
    pub enabled: Option<bool>,
    /// Plan snapshots kept. `0` disables the count budget.
    pub keep_plans: Option<usize>,
    /// Age past which a plan snapshot or apply report is pruned, e.g. `"14d"`.
    pub max_plan_age: Option<String>,
    /// Total size the plans directory may occupy, e.g. `"1GiB"`. A single plan for a
    /// large workspace can be hundreds of megabytes, so this is usually the budget
    /// that binds.
    pub max_plans_size: Option<String>,
    /// Terminal `apply` reports kept. `0` disables the count budget.
    pub keep_reports: Option<usize>,
    /// Size at which `runs.jsonl` and `scheduler.log` are rotated, e.g. `"64MiB"`.
    pub max_log_size: Option<String>,
    /// Rotated log generations kept (`runs.jsonl.1`, …). `0` discards on rotation.
    pub keep_rotated_logs: Option<usize>,
}

impl SchedulerRetentionConfig {
    /// Resolve into the policy the service enforces, applying defaults for every
    /// budget the config leaves out.
    pub fn resolve(&self) -> Result<StateRetentionPolicy, ConfigError> {
        let defaults = StateRetentionPolicy::default();
        if !self.enabled.unwrap_or(true) {
            return Ok(StateRetentionPolicy::disabled());
        }
        Ok(StateRetentionPolicy {
            enabled: true,
            keep_plans: budget_count(self.keep_plans, defaults.keep_plans),
            max_plan_age: match self.max_plan_age.as_deref() {
                Some(value) => Some(parse_config_duration(value)?),
                None => defaults.max_plan_age,
            },
            max_plans_bytes: match self.max_plans_size.as_deref() {
                Some(value) => Some(parse_config_size(value)?),
                None => defaults.max_plans_bytes,
            },
            keep_reports: budget_count(self.keep_reports, defaults.keep_reports),
            max_log_bytes: match self.max_log_size.as_deref() {
                Some(value) => Some(parse_config_size(value)?),
                None => defaults.max_log_bytes,
            },
            keep_rotated_logs: self.keep_rotated_logs.unwrap_or(defaults.keep_rotated_logs),
        })
    }
}

/// `0` means "no count budget"; an omitted key means "use the default".
fn budget_count(configured: Option<usize>, default: Option<usize>) -> Option<usize> {
    match configured {
        Some(0) => None,
        Some(count) => Some(count),
        None => default,
    }
}
