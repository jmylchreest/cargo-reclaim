//! On-disk encoding for the plan snapshot.
//!
//! A plan entry is mostly repetition: across tens of thousands of entries there are
//! only a handful of distinct policy reasons, evidence objects, artifact classes,
//! actions, and path kinds, and every absolute path re-spells a directory the plan
//! already named. Serializing each entry as a standalone object therefore spent most
//! of the file on strings that are identical thousands of times over.
//!
//! The wire form hoists those values into dictionaries at the snapshot level and
//! leaves each entry holding indexes into them, plus its own basename. It is a pure
//! encoding change: [`PersistedPlanSnapshot`] is unchanged in memory, so plan
//! editing, revalidation, and apply see exactly the same entries they always did,
//! and the encoding round-trips byte-for-byte on the paths it reconstructs.
//!
//! Decoding rejects an out-of-range index rather than silently substituting a
//! default — a plan that cannot be reconstructed exactly must not be applied.

use std::collections::HashMap;

use serde::de::Error as DeserializeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::document::{
    PersistedActiveSkip, PersistedEvidence, PersistedPathSnapshot, PersistedPlanEntry,
    PersistedPlanInput, PersistedPlanSkip, PersistedPlanSnapshot, PersistedPlanTotals,
};
use super::time::PersistedTimestamp;

impl Serialize for PersistedPlanSnapshot {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        WireSnapshot::from_snapshot(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PersistedPlanSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        WireSnapshot::deserialize(deserializer)?
            .into_snapshot()
            .map_err(D::Error::custom)
    }
}

#[derive(Serialize, Deserialize)]
struct WireSnapshot {
    schema_version: u16,
    input: PersistedPlanInput,
    #[serde(default)]
    dictionaries: WireDictionaries,
    entries: Vec<WireEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    active_skips: Vec<PersistedActiveSkip>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    skipped_paths: Vec<PersistedPlanSkip>,
    totals: PersistedPlanTotals,
}

/// The repeated values hoisted out of the entries. Every entry field that is drawn
/// from a small fixed vocabulary lives here exactly once.
#[derive(Default, Serialize, Deserialize)]
struct WireDictionaries {
    /// Directory prefixes, each including its trailing separator, so a path is
    /// rebuilt by plain concatenation and survives either platform's separator.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    directories: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    path_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    artifact_classes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    policy_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    evidence: Vec<PersistedEvidence>,
}

#[derive(Serialize, Deserialize)]
struct WireEntry {
    /// Index into `dictionaries.directories`; absent when the path has no
    /// directory component.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dir: Option<usize>,
    name: String,
    size_bytes: u64,
    path_kind: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    modified: Option<PersistedTimestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content_fingerprint: Option<String>,
    artifact_class: usize,
    evidence: usize,
    action: usize,
    policy_reason: usize,
    #[serde(default, skip_serializing_if = "is_false")]
    requires_confirmation: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

impl WireSnapshot {
    fn from_snapshot(snapshot: &PersistedPlanSnapshot) -> Self {
        let mut builder = DictionaryBuilder::default();
        let entries = snapshot
            .entries
            .iter()
            .map(|entry| builder.encode_entry(entry))
            .collect();
        Self {
            schema_version: snapshot.schema_version,
            input: snapshot.input.clone(),
            dictionaries: builder.finish(),
            entries,
            active_skips: snapshot.active_skips.clone(),
            skipped_paths: snapshot.skipped_paths.clone(),
            totals: snapshot.totals.clone(),
        }
    }

    fn into_snapshot(self) -> Result<PersistedPlanSnapshot, String> {
        let dictionaries = self.dictionaries;
        let entries = self
            .entries
            .into_iter()
            .map(|entry| decode_entry(entry, &dictionaries))
            .collect::<Result<Vec<_>, String>>()?;
        Ok(PersistedPlanSnapshot {
            schema_version: self.schema_version,
            input: self.input,
            entries,
            active_skips: self.active_skips,
            skipped_paths: self.skipped_paths,
            totals: self.totals,
        })
    }
}

#[derive(Default)]
struct DictionaryBuilder {
    directories: Interner,
    path_kinds: Interner,
    artifact_classes: Interner,
    actions: Interner,
    policy_reasons: Interner,
    evidence: Vec<PersistedEvidence>,
}

impl DictionaryBuilder {
    fn encode_entry(&mut self, entry: &PersistedPlanEntry) -> WireEntry {
        let (directory, name) = split_directory(&entry.snapshot.path);
        WireEntry {
            dir: directory.map(|directory| self.directories.intern(directory)),
            name: name.to_owned(),
            size_bytes: entry.snapshot.size_bytes,
            path_kind: self.path_kinds.intern(&entry.snapshot.path_kind),
            modified: entry.snapshot.modified,
            content_fingerprint: entry.snapshot.content_fingerprint.clone(),
            artifact_class: self.artifact_classes.intern(&entry.artifact_class),
            evidence: self.intern_evidence(&entry.evidence),
            action: self.actions.intern(&entry.action),
            policy_reason: self.policy_reasons.intern(&entry.policy_reason),
            requires_confirmation: entry.requires_confirmation,
        }
    }

    /// Evidence is a small struct rather than a string, and its cardinality is tiny
    /// (one per distinct project/marker), so a linear scan beats hashing it.
    fn intern_evidence(&mut self, evidence: &PersistedEvidence) -> usize {
        if let Some(index) = self
            .evidence
            .iter()
            .position(|candidate| candidate == evidence)
        {
            return index;
        }
        self.evidence.push(evidence.clone());
        self.evidence.len() - 1
    }

    fn finish(self) -> WireDictionaries {
        WireDictionaries {
            directories: self.directories.finish(),
            path_kinds: self.path_kinds.finish(),
            artifact_classes: self.artifact_classes.finish(),
            actions: self.actions.finish(),
            policy_reasons: self.policy_reasons.finish(),
            evidence: self.evidence,
        }
    }
}

#[derive(Default)]
struct Interner {
    values: Vec<String>,
    indexes: HashMap<String, usize>,
}

impl Interner {
    fn intern(&mut self, value: &str) -> usize {
        if let Some(index) = self.indexes.get(value) {
            return *index;
        }
        let index = self.values.len();
        self.values.push(value.to_owned());
        self.indexes.insert(value.to_owned(), index);
        index
    }

    fn finish(self) -> Vec<String> {
        self.values
    }
}

fn decode_entry(
    entry: WireEntry,
    dictionaries: &WireDictionaries,
) -> Result<PersistedPlanEntry, String> {
    let path = match entry.dir {
        Some(index) => {
            let directory = lookup(&dictionaries.directories, index, "directories")?;
            format!("{directory}{}", entry.name)
        }
        None => entry.name,
    };
    Ok(PersistedPlanEntry {
        snapshot: PersistedPathSnapshot {
            path,
            size_bytes: entry.size_bytes,
            path_kind: lookup(&dictionaries.path_kinds, entry.path_kind, "path_kinds")?.to_owned(),
            modified: entry.modified,
            content_fingerprint: entry.content_fingerprint,
        },
        artifact_class: lookup(
            &dictionaries.artifact_classes,
            entry.artifact_class,
            "artifact_classes",
        )?
        .to_owned(),
        evidence: dictionaries
            .evidence
            .get(entry.evidence)
            .cloned()
            .ok_or_else(|| index_error("evidence", entry.evidence, dictionaries.evidence.len()))?,
        action: lookup(&dictionaries.actions, entry.action, "actions")?.to_owned(),
        policy_reason: lookup(
            &dictionaries.policy_reasons,
            entry.policy_reason,
            "policy_reasons",
        )?
        .to_owned(),
        requires_confirmation: entry.requires_confirmation,
    })
}

fn lookup<'a>(values: &'a [String], index: usize, table: &str) -> Result<&'a str, String> {
    values
        .get(index)
        .map(String::as_str)
        .ok_or_else(|| index_error(table, index, values.len()))
}

fn index_error(table: &str, index: usize, len: usize) -> String {
    format!("plan dictionary `{table}` has no entry {index} (length {len})")
}

/// Split a path into its directory prefix (separator included) and its final
/// component. Splitting on the raw string rather than through `Path` keeps the
/// round-trip exact for paths written on the other platform.
fn split_directory(path: &str) -> (Option<&str>, &str) {
    match path.rfind(['/', '\\']) {
        Some(index) => {
            let (directory, name) = path.split_at(index + 1);
            (Some(directory), name)
        }
        None => (None, path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, action: &str, reason: &str) -> PersistedPlanEntry {
        PersistedPlanEntry {
            snapshot: PersistedPathSnapshot {
                path: path.to_owned(),
                size_bytes: 64,
                path_kind: "file".to_owned(),
                modified: Some(PersistedTimestamp {
                    unix_seconds: 100,
                    nanoseconds: 0,
                }),
                content_fingerprint: None,
            },
            artifact_class: "incremental".to_owned(),
            evidence: PersistedEvidence {
                kind: "strong_marker".to_owned(),
                marker: Some("CACHEDIR.TAG".to_owned()),
                source: None,
                project_manifest: None,
                matched_name: None,
            },
            action: action.to_owned(),
            policy_reason: reason.to_owned(),
            requires_confirmation: false,
        }
    }

    fn snapshot(entries: Vec<PersistedPlanEntry>) -> PersistedPlanSnapshot {
        PersistedPlanSnapshot {
            schema_version: 1,
            input: PersistedPlanInput {
                roots: vec!["/projects".to_owned()],
            },
            totals: PersistedPlanTotals {
                entry_count: entries.len(),
                total_bytes: 64 * entries.len() as u64,
                preserved_count: 0,
                delete_candidate_count: entries.len(),
                skipped_path_count: 0,
            },
            entries,
            active_skips: Vec::new(),
            skipped_paths: Vec::new(),
        }
    }

    #[test]
    fn round_trips_through_the_dictionary_encoding() {
        let original = snapshot(vec![
            entry("/projects/a/target/debug/x.o", "delete", "policy permits"),
            entry("/projects/a/target/debug/y.o", "delete", "policy permits"),
            entry("/projects/b/target/debug/z.o", "preserve", "kept"),
        ]);

        let json = serde_json::to_string(&original).expect("serialize");
        let decoded: PersistedPlanSnapshot = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded, original);
    }

    #[test]
    fn repeated_values_are_stored_once() {
        let original = snapshot(vec![
            entry("/projects/a/target/debug/x.o", "delete", "policy permits"),
            entry("/projects/a/target/debug/y.o", "delete", "policy permits"),
        ]);

        let wire: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&original).expect("serialize"))
                .expect("value");
        let dictionaries = &wire["dictionaries"];

        assert_eq!(dictionaries["directories"].as_array().unwrap().len(), 1);
        assert_eq!(dictionaries["policy_reasons"].as_array().unwrap().len(), 1);
        assert_eq!(dictionaries["evidence"].as_array().unwrap().len(), 1);
        // The shared directory is named once, and each entry keeps only its basename.
        assert_eq!(wire["entries"][0]["name"], "x.o");
        assert_eq!(wire["entries"][0]["dir"], 0);
        assert_eq!(wire["entries"][1]["dir"], 0);
    }

    #[test]
    fn the_encoding_is_smaller_than_standalone_entries() {
        let entries: Vec<_> = (0..500)
            .map(|index| {
                entry(
                    &format!("/projects/a/target/debug/deps/lib{index}.rmeta"),
                    "delete",
                    "policy permits deletion for this classified removable artifact",
                )
            })
            .collect();
        let original = snapshot(entries);

        let encoded = serde_json::to_string(&original).expect("serialize").len();
        let standalone = serde_json::to_string(&original.entries)
            .expect("serialize entries")
            .len();

        assert!(
            encoded * 2 < standalone,
            "dictionary encoding should more than halve entry bytes: {encoded} vs {standalone}"
        );
    }

    #[test]
    fn a_path_without_a_directory_round_trips() {
        let original = snapshot(vec![entry("plan.json", "preserve", "kept")]);

        let json = serde_json::to_string(&original).expect("serialize");
        let decoded: PersistedPlanSnapshot = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(decoded, original);
        assert_eq!(decoded.entries[0].snapshot.path, "plan.json");
    }

    #[test]
    fn windows_separators_round_trip_unchanged() {
        let original = snapshot(vec![entry(
            r"C:\projects\a\target\debug\x.o",
            "delete",
            "policy permits",
        )]);

        let json = serde_json::to_string(&original).expect("serialize");
        let decoded: PersistedPlanSnapshot = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(
            decoded.entries[0].snapshot.path,
            r"C:\projects\a\target\debug\x.o"
        );
    }

    #[test]
    fn an_out_of_range_dictionary_index_is_rejected() {
        let original = snapshot(vec![entry("/projects/a/x.o", "delete", "policy permits")]);
        let mut wire: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&original).expect("serialize"))
                .expect("value");
        wire["entries"][0]["policy_reason"] = serde_json::json!(9);

        let error = serde_json::from_value::<PersistedPlanSnapshot>(wire)
            .expect_err("out-of-range index must not decode");

        assert!(
            error.to_string().contains("policy_reasons"),
            "unexpected error: {error}"
        );
    }
}
