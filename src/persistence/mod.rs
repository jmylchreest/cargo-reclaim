mod document;
mod document_kind;
mod error;
mod fingerprint;
mod fs;
mod id;
mod time;
mod wire;

pub use document::{
    PersistedActiveSkip, PersistedEvidence, PersistedInventoryOptions, PersistedPathSnapshot,
    PersistedPlan, PersistedPlanBody, PersistedPlanEntry, PersistedPlanInput, PersistedPlanSkip,
    PersistedPlanSnapshot, PersistedPlanTotals, PersistedPlannerOptions, PersistedScannerOptions,
    PersistedWholeTargetMode, PlanCommandKind, PlanInvocation, SavePlanOptions, ensure_plan_usable,
    persist_audit_plan, persist_plan,
};
pub(crate) use document_kind::deserialize_plan_document;
pub use error::{PlanPersistenceError, PlanPersistenceResult};
pub(crate) use fingerprint::fingerprint_path;
pub use fs::{load_plan_from_path, save_plan_to_path};
pub use id::PlanId;
pub use time::PersistedTimestamp;

/// Bumped to 2 for the dictionary-encoded snapshot and per-target active-skip
/// summaries. Plans carry an expiry and are revalidated against the filesystem
/// before apply, so a version-1 file is rejected rather than migrated.
pub const PERSISTED_PLAN_SCHEMA_VERSION: u16 = 2;
