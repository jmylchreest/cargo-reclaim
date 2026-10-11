use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::SystemTime;

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::inventory::InventoryOptions;
use crate::model::{
    ArtifactClass, PLAN_SCHEMA_VERSION, PathKind, PathSnapshot, Plan, PlanAction, PlanEntry,
    PlanInput, PlanSkip, PlanSkipReason, PlanTotals, TargetEvidence,
};
use crate::planner::{PlannerOptions, WholeTargetMode};
use crate::policy::PolicyKind;
use crate::scanner::ScannerOptions;

use super::PERSISTED_PLAN_SCHEMA_VERSION;
use super::error::{PlanPersistenceError, PlanPersistenceResult};
use super::fingerprint_path;
use super::id::PlanId;
use super::time::PersistedTimestamp;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedPlan {
    pub schema_version: u16,
    pub id: PlanId,
    #[serde(flatten)]
    pub body: PersistedPlanBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedPlanBody {
    pub created_at: PersistedTimestamp,
    pub expires_at: PersistedTimestamp,
    pub interactive_selection_modified: bool,
    pub invocation: PlanInvocation,
    pub plan: PersistedPlanSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavePlanOptions {
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub interactive_selection_modified: bool,
    pub invocation: PlanInvocation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanInvocation {
    pub command: PlanCommandKind,
    pub policy: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_version: Option<u16>,
    pub scanner_options: PersistedScannerOptions,
    pub inventory_options: PersistedInventoryOptions,
    #[serde(default)]
    pub planner_options: PersistedPlannerOptions,
}

impl PlanInvocation {
    pub fn new(
        command: PlanCommandKind,
        policy: PolicyKind,
        scanner_options: &ScannerOptions,
        inventory_options: &InventoryOptions,
        planner_options: &PlannerOptions,
    ) -> Self {
        Self {
            command,
            policy: policy_label(policy).to_string(),
            config_path: None,
            config_version: None,
            scanner_options: PersistedScannerOptions::from_options(scanner_options),
            inventory_options: PersistedInventoryOptions::from_options(inventory_options),
            planner_options: PersistedPlannerOptions::from_options(planner_options),
        }
    }

    pub fn with_config(mut self, path: &Path, version: u16) -> Self {
        self.config_path = Some(path_string(path));
        self.config_version = Some(version);
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanCommandKind {
    Plan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedScannerOptions {
    pub follow_symlinks: bool,
    pub allow_name_only_targets: bool,
    pub cross_filesystems: bool,
    pub ignored_paths: Vec<String>,
    pub skipped_paths: Vec<String>,
}

impl PersistedScannerOptions {
    fn from_options(options: &ScannerOptions) -> Self {
        Self {
            follow_symlinks: options.follow_symlinks,
            allow_name_only_targets: options.allow_name_only_targets,
            cross_filesystems: options.cross_filesystems,
            ignored_paths: options.ignored_paths.iter().map(path_string).collect(),
            skipped_paths: options.skipped_paths.iter().map(path_string).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedInventoryOptions {
    pub follow_symlinks: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub deep_target_scan: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub deep_directory_measurement: bool,
}

impl PersistedInventoryOptions {
    fn from_options(options: &InventoryOptions) -> Self {
        Self {
            follow_symlinks: options.follow_symlinks,
            deep_target_scan: options.deep_target_scan,
            deep_directory_measurement: options.deep_directory_measurement,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PersistedPlannerOptions {
    pub recent_write_keep_window_seconds: Option<u64>,
    pub keep_size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_size_goal_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_free_disk_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_reclaim_bytes: Option<u64>,
    #[serde(default)]
    pub keep_rustc_hashes: Vec<u64>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub keep_installed_toolchains: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keep_toolchains: Vec<String>,
    #[serde(default, skip_serializing_if = "is_default_whole_target_mode")]
    pub whole_target_mode: PersistedWholeTargetMode,
}

impl PersistedPlannerOptions {
    fn from_options(options: &PlannerOptions) -> Self {
        Self {
            recent_write_keep_window_seconds: options
                .recent_write_keep_window
                .map(|duration| duration.as_secs()),
            keep_size_bytes: options.keep_size_bytes,
            target_size_goal_bytes: options.target_size_goal_bytes,
            target_free_disk_bytes: options.target_free_disk_bytes,
            minimum_reclaim_bytes: options.minimum_reclaim_bytes,
            keep_rustc_hashes: options.keep_rustc_hashes.clone(),
            keep_installed_toolchains: options.keep_installed_toolchains,
            keep_toolchains: options.keep_toolchains.clone(),
            whole_target_mode: PersistedWholeTargetMode::from_mode(options.whole_target_mode),
        }
    }
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistedWholeTargetMode {
    #[default]
    Off,
    Confirm,
    DeleteConfirmed,
}

impl PersistedWholeTargetMode {
    fn from_mode(mode: WholeTargetMode) -> Self {
        match mode {
            WholeTargetMode::Off => Self::Off,
            WholeTargetMode::Confirm => Self::Confirm,
            WholeTargetMode::DeleteConfirmed => Self::DeleteConfirmed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedPlanSnapshot {
    pub schema_version: u16,
    pub input: PersistedPlanInput,
    pub entries: Vec<PersistedPlanEntry>,
    /// Targets that were protected wholesale because a build was touching them.
    /// The planner reaches that verdict once per target but records it on every
    /// file inside; persisting those per-file entries is what made plans enormous
    /// (a busy workspace produced tens of thousands of them, none actionable),
    /// so they are summarized here instead. `totals` still counts every entry.
    pub active_skips: Vec<PersistedActiveSkip>,
    pub skipped_paths: Vec<PersistedPlanSkip>,
    pub totals: PersistedPlanTotals,
}

impl PersistedPlanSnapshot {
    fn from_plan(plan: &Plan, summarize_active_skips: bool) -> PlanPersistenceResult<Self> {
        let (entries, active_skips) = if summarize_active_skips {
            collapse_active_skips(&plan.entries)?
        } else {
            (
                plan.entries
                    .par_iter()
                    .map(PersistedPlanEntry::from_entry)
                    .collect::<PlanPersistenceResult<Vec<_>>>()?,
                Vec::new(),
            )
        };
        Ok(Self {
            schema_version: plan.schema_version,
            input: PersistedPlanInput::from_input(&plan.input),
            entries,
            active_skips,
            skipped_paths: plan
                .skipped_paths
                .iter()
                .map(PersistedPlanSkip::from_skip)
                .collect(),
            totals: PersistedPlanTotals::from_totals(plan.totals),
        })
    }
}

/// Split the plan's entries into the ones worth persisting individually and a
/// per-target summary of the active-build skips. An active skip with no known
/// target root cannot be attributed to a target, so it is persisted as an entry
/// rather than dropped.
fn collapse_active_skips(
    entries: &[PlanEntry],
) -> PlanPersistenceResult<(Vec<PersistedPlanEntry>, Vec<PersistedActiveSkip>)> {
    let mut summaries: Vec<PersistedActiveSkip> = Vec::new();
    let mut index_by_target: HashMap<&Path, usize> = HashMap::new();
    let mut kept = Vec::new();

    for entry in entries {
        let target_root = match (&entry.action, entry.target_root.as_deref()) {
            (PlanAction::SkipActive, Some(target_root)) => target_root,
            _ => {
                kept.push(entry);
                continue;
            }
        };

        let index = *index_by_target.entry(target_root).or_insert_with(|| {
            summaries.push(PersistedActiveSkip {
                target: path_string(target_root),
                entry_count: 0,
                total_bytes: 0,
                reasons: Vec::new(),
            });
            summaries.len() - 1
        });
        let summary = &mut summaries[index];
        summary.entry_count += 1;
        summary.total_bytes = summary
            .total_bytes
            .saturating_add(entry.snapshot.size_bytes);
        if !summary
            .reasons
            .iter()
            .any(|reason| reason == &entry.policy_reason)
        {
            summary.reasons.push(entry.policy_reason.clone());
        }
    }

    let entries = kept
        .into_par_iter()
        .map(PersistedPlanEntry::from_entry)
        .collect::<PlanPersistenceResult<Vec<_>>>()?;
    Ok((entries, summaries))
}

/// One target protected wholesale by active-build detection, standing in for the
/// per-file entries the planner produced for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedActiveSkip {
    pub target: String,
    pub entry_count: usize,
    pub total_bytes: u64,
    /// The distinct policy reasons recorded across the collapsed entries — which
    /// active-build signal fired (process scan, target keep window, recent write).
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedPlanInput {
    pub roots: Vec<String>,
}

impl PersistedPlanInput {
    fn from_input(input: &PlanInput) -> Self {
        Self {
            roots: input.roots.iter().map(path_string).collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedPlanSkip {
    pub path: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl PersistedPlanSkip {
    fn from_skip(skip: &PlanSkip) -> Self {
        Self {
            path: path_string(&skip.path),
            reason: skip_reason_label(skip.reason).to_string(),
            message: skip.message.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedPlanEntry {
    pub snapshot: PersistedPathSnapshot,
    pub artifact_class: String,
    pub evidence: PersistedEvidence,
    pub action: String,
    pub policy_reason: String,
    pub requires_confirmation: bool,
}

impl PersistedPlanEntry {
    fn from_entry(entry: &PlanEntry) -> PlanPersistenceResult<Self> {
        Ok(Self {
            snapshot: PersistedPathSnapshot::from_snapshot(
                &entry.snapshot,
                content_fingerprint_for_entry(entry)?,
            ),
            artifact_class: artifact_label(entry.artifact_class).to_string(),
            evidence: PersistedEvidence::from_evidence(&entry.evidence),
            action: action_label(&entry.action).to_string(),
            policy_reason: entry.policy_reason.clone(),
            requires_confirmation: entry.requires_confirmation,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedPathSnapshot {
    pub path: String,
    pub size_bytes: u64,
    pub path_kind: String,
    pub modified: Option<PersistedTimestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_fingerprint: Option<String>,
}

impl PersistedPathSnapshot {
    fn from_snapshot(snapshot: &PathSnapshot, content_fingerprint: Option<String>) -> Self {
        Self {
            path: path_string(&snapshot.path),
            size_bytes: snapshot.size_bytes,
            path_kind: path_kind_label(snapshot.path_kind).to_string(),
            modified: snapshot
                .modified
                .and_then(|modified| PersistedTimestamp::from_system_time(modified).ok()),
            content_fingerprint,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedPlanTotals {
    pub entry_count: usize,
    pub total_bytes: u64,
    pub preserved_count: usize,
    pub delete_candidate_count: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub skipped_path_count: usize,
}

impl PersistedPlanTotals {
    fn from_totals(totals: PlanTotals) -> Self {
        Self {
            entry_count: totals.entry_count,
            total_bytes: totals.total_bytes,
            preserved_count: totals.preserved_count,
            delete_candidate_count: totals.delete_candidate_count,
            skipped_path_count: totals.skipped_path_count,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedEvidence {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marker: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project_manifest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matched_name: Option<String>,
}

impl PersistedEvidence {
    fn from_evidence(evidence: &TargetEvidence) -> Self {
        match evidence {
            TargetEvidence::StrongMarker { marker } => Self {
                kind: "strong_marker".to_string(),
                marker: Some(marker.clone()),
                source: None,
                project_manifest: None,
                matched_name: None,
            },
            TargetEvidence::ConfiguredPath { source } => Self {
                kind: "configured_path".to_string(),
                marker: None,
                source: Some(source.clone()),
                project_manifest: None,
                matched_name: None,
            },
            TargetEvidence::ProjectContext { project_manifest } => Self {
                kind: "project_context".to_string(),
                marker: None,
                source: None,
                project_manifest: Some(path_string(project_manifest)),
                matched_name: None,
            },
            TargetEvidence::WeakNameOnly { matched_name } => Self {
                kind: "weak_name_only".to_string(),
                marker: None,
                source: None,
                project_manifest: None,
                matched_name: Some(matched_name.clone()),
            },
        }
    }
}

/// Persist a plan the user can still act on: every entry is written out, so
/// `edit-plan` can reselect anything the planner protected — including a target
/// skipped for an active build.
pub fn persist_plan(plan: &Plan, options: SavePlanOptions) -> PlanPersistenceResult<PersistedPlan> {
    persist_plan_with_options(plan, options, false)
}

/// Persist a plan as a background-run audit record. Targets protected wholesale by
/// active-build detection are summarized per target instead of listing every file
/// inside them: the background service writes a plan on every cycle forever, and on
/// a busy workspace those per-file skips were the overwhelming majority of the
/// document while never being actionable — a run's plan is a record of what
/// happened, not a document to edit.
pub fn persist_audit_plan(
    plan: &Plan,
    options: SavePlanOptions,
) -> PlanPersistenceResult<PersistedPlan> {
    persist_plan_with_options(plan, options, true)
}

fn persist_plan_with_options(
    plan: &Plan,
    options: SavePlanOptions,
    summarize_active_skips: bool,
) -> PlanPersistenceResult<PersistedPlan> {
    if options.expires_at <= options.created_at {
        return Err(PlanPersistenceError::InvalidTimeRange);
    }

    let body = PersistedPlanBody {
        created_at: PersistedTimestamp::from_system_time(options.created_at)?,
        expires_at: PersistedTimestamp::from_system_time(options.expires_at)?,
        interactive_selection_modified: options.interactive_selection_modified,
        invocation: options.invocation,
        plan: PersistedPlanSnapshot::from_plan(plan, summarize_active_skips)?,
    };
    let id = PlanId::from_body(&body)?;

    Ok(PersistedPlan {
        schema_version: PERSISTED_PLAN_SCHEMA_VERSION,
        id,
        body,
    })
}

fn content_fingerprint_for_entry(entry: &PlanEntry) -> PlanPersistenceResult<Option<String>> {
    if !requires_content_fingerprint(entry) {
        return Ok(None);
    }

    let path = &entry.snapshot.path;
    let metadata = fs::symlink_metadata(path).map_err(|error| PlanPersistenceError::Io {
        path: path.clone(),
        message: error.to_string(),
    })?;
    Ok(Some(fingerprint_path(path, &metadata)?))
}

fn requires_content_fingerprint(entry: &PlanEntry) -> bool {
    matches!(
        entry.action,
        PlanAction::Delete | PlanAction::RequiresConfirmation
    ) && entry.artifact_class != ArtifactClass::WholeTarget
        && entry.artifact_class != ArtifactClass::StaleDeps
        && entry.artifact_class != ArtifactClass::StaleIncremental
        && entry.artifact_class != ArtifactClass::DepsOutput
        && entry.snapshot.path_kind == PathKind::File
}

pub fn ensure_plan_usable(document: &PersistedPlan, now: SystemTime) -> PlanPersistenceResult<()> {
    if document.schema_version != PERSISTED_PLAN_SCHEMA_VERSION {
        return Err(PlanPersistenceError::PersistenceSchemaMismatch {
            found: document.schema_version,
            expected: PERSISTED_PLAN_SCHEMA_VERSION,
        });
    }

    if document.body.plan.schema_version != PLAN_SCHEMA_VERSION {
        return Err(PlanPersistenceError::PlanSchemaMismatch {
            found: document.body.plan.schema_version,
            expected: PLAN_SCHEMA_VERSION,
        });
    }

    let expected_id = PlanId::from_body(&document.body)?;
    if expected_id != document.id {
        return Err(PlanPersistenceError::PlanIdMismatch {
            expected: expected_id.0,
            found: document.id.0.clone(),
        });
    }

    if now >= document.body.expires_at.to_system_time() {
        return Err(PlanPersistenceError::PlanExpired);
    }

    Ok(())
}

fn policy_label(policy: PolicyKind) -> &'static str {
    match policy {
        PolicyKind::Observe => "observe",
        PolicyKind::Conservative => "conservative",
        PolicyKind::Balanced => "balanced",
        PolicyKind::Aggressive => "aggressive",
        PolicyKind::Sweep => "sweep",
        PolicyKind::Custom => "custom",
    }
}

fn action_label(action: &PlanAction) -> &'static str {
    match action {
        PlanAction::Delete => "delete",
        PlanAction::Preserve => "preserve",
        PlanAction::SkipActive => "skip_active",
        PlanAction::SkipLocked => "skip_locked",
        PlanAction::Unknown => "unknown",
        PlanAction::RequiresConfirmation => "requires_confirmation",
    }
}

fn artifact_label(artifact_class: ArtifactClass) -> &'static str {
    artifact_class.label()
}

fn skip_reason_label(reason: PlanSkipReason) -> &'static str {
    reason.label()
}

fn is_default_whole_target_mode(mode: &PersistedWholeTargetMode) -> bool {
    *mode == PersistedWholeTargetMode::Off
}

fn path_kind_label(path_kind: PathKind) -> &'static str {
    match path_kind {
        PathKind::File => "file",
        PathKind::Directory => "directory",
        PathKind::Symlink => "symlink",
        PathKind::Unknown => "unknown",
    }
}

fn path_string(path: impl AsRef<Path>) -> String {
    path.as_ref().display().to_string()
}
