//! Core Seedpass domain model and validation.
//!
//! This crate owns durable concepts and lifecycle/state-machine rules. It must
//! not perform filesystem IO, prompt users, or emit credentials.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Component, Path};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

pub const SCHEME_V1: &str = "seedpass-v1";
pub const RECIPES_FORMAT_V1: &str = "seedpass-recipes-v1";
pub const DIRECTORY_FORMAT_V1: &str = "seedpass-directory-v1";
pub const RECIPE_FORMAT_V1: &str = "seedpass-recipe-v1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CoreError {
    #[error("alias not found: {0}")]
    AliasNotFound(String),
    #[error("alias already exists: {0}")]
    AliasAlreadyExists(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    HardError,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: Severity,
    pub message: String,
}

impl Diagnostic {
    pub fn hard(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::HardError,
            message: message.into(),
        }
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            severity: Severity::Warning,
            message: message.into(),
        }
    }
}

pub trait Validate {
    fn validate(&self) -> Vec<Diagnostic>;

    fn hard_errors(&self) -> Vec<Diagnostic> {
        self.validate()
            .into_iter()
            .filter(|diagnostic| diagnostic.severity == Severity::HardError)
            .collect()
    }

    fn is_valid(&self) -> bool {
        self.hard_errors().is_empty()
    }
}

macro_rules! string_newtype {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl From<&str> for $name {
            fn from(value: &str) -> Self {
                Self(value.to_owned())
            }
        }

        impl From<String> for $name {
            fn from(value: String) -> Self {
                Self(value)
            }
        }
    };
}

string_newtype!(CredentialUid);
string_newtype!(Alias);
string_newtype!(SeedLabel);
string_newtype!(SeedFingerprint);
string_newtype!(Scheme);
string_newtype!(PublicSalt);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    WebPassword,
}

/// Lifecycle status for one credential version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VersionStatus {
    Pending,
    Active,
    Retired,
    Failed,
    Revoked,
}

impl VersionStatus {
    /// Returns whether a transition is allowed by the MVP state machine.
    pub const fn can_transition_to(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Pending, Self::Active)
                | (Self::Pending, Self::Failed)
                | (Self::Active, Self::Retired)
                | (Self::Active, Self::Revoked)
                | (Self::Retired, Self::Revoked)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ProfileSnapshot {
    Password {
        length: u16,
        min_uppercase: u16,
        min_lowercase: u16,
        min_digits: u16,
        min_symbols: u16,
        symbols: String,
    },
}

impl ProfileSnapshot {
    pub fn validate_profile(&self) -> Vec<Diagnostic> {
        match self {
            Self::Password {
                length,
                min_uppercase,
                min_lowercase,
                min_digits,
                min_symbols,
                symbols,
            } => validate_password_profile(
                *length,
                *min_uppercase,
                *min_lowercase,
                *min_digits,
                *min_symbols,
                symbols,
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialVersion {
    pub number: u32,
    pub status: VersionStatus,
    pub seed: SeedLabel,
    pub scheme: Scheme,
    pub public_salt: PublicSalt,
    pub profile_snapshot: ProfileSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub uid: CredentialUid,
    pub alias: Alias,
    pub purpose: Purpose,
    pub versions: Vec<CredentialVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedRecord {
    pub fingerprint: SeedFingerprint,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipesFile {
    pub format: String,
    pub seeds: BTreeMap<SeedLabel, SeedRecord>,
    pub credentials: Vec<CredentialRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub alias: Alias,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryFile {
    pub format: String,
    pub entries: BTreeMap<CredentialUid, DirectoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileTemplate {
    pub profile: ProfileSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfilesFile {
    pub format: String,
    pub profiles: BTreeMap<String, ProfileTemplate>,
}

/// Derivation-critical view of a credential version.
///
/// This intentionally excludes alias, seed label, seed path, seed fingerprint,
/// service, username, tags, notes, timestamps, and profile template names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivationRecipeV1 {
    pub format: String,
    pub scheme: Scheme,
    pub credential_uid: CredentialUid,
    pub purpose: Purpose,
    pub version: u32,
    pub public_salt: PublicSalt,
    pub profile_snapshot: ProfileSnapshot,
}

impl DerivationRecipeV1 {
    pub fn from_record_version(record: &CredentialRecord, version: &CredentialVersion) -> Self {
        Self {
            format: RECIPE_FORMAT_V1.to_owned(),
            scheme: version.scheme.clone(),
            credential_uid: record.uid.clone(),
            purpose: record.purpose.clone(),
            version: version.number,
            public_salt: version.public_salt.clone(),
            profile_snapshot: version.profile_snapshot.clone(),
        }
    }
}

impl DirectoryFile {
    pub fn rename_alias(&mut self, old: &Alias, new: Alias) -> Result<(), CoreError> {
        if self.entries.values().any(|entry| entry.alias == new) {
            return Err(CoreError::AliasAlreadyExists(new.0));
        }

        let entry = self
            .entries
            .values_mut()
            .find(|entry| &entry.alias == old)
            .ok_or_else(|| CoreError::AliasNotFound(old.0.clone()))?;
        entry.alias = new;
        Ok(())
    }
}

impl Validate for DirectoryFile {
    fn validate(&self) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();
        if self.format != DIRECTORY_FORMAT_V1 {
            diagnostics.push(Diagnostic::hard(format!(
                "unsupported directory format: {}",
                self.format
            )));
        }

        let mut aliases = BTreeSet::new();
        for entry in self.entries.values() {
            diagnostics.extend(validate_token("directory alias", entry.alias.as_str()));
            if !aliases.insert(entry.alias.clone()) {
                diagnostics.push(Diagnostic::hard(format!(
                    "duplicate directory alias: {}",
                    entry.alias.as_str()
                )));
            }
        }
        diagnostics
    }
}

impl RecipesFile {
    pub fn validate_with_directory(&self, directory: Option<&DirectoryFile>) -> Vec<Diagnostic> {
        let mut diagnostics = self.validate();
        if let Some(directory) = directory {
            diagnostics.extend(directory.validate());
            let known_uids: BTreeSet<_> =
                self.credentials.iter().map(|record| &record.uid).collect();
            for uid in directory.entries.keys() {
                if !known_uids.contains(uid) {
                    diagnostics.push(Diagnostic::hard(format!(
                        "directory entry references unknown credential UID: {}",
                        uid.as_str()
                    )));
                }
            }
        }
        diagnostics
    }
}

impl Validate for RecipesFile {
    fn validate(&self) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();
        if self.format != RECIPES_FORMAT_V1 {
            diagnostics.push(Diagnostic::hard(format!(
                "unsupported recipes format: {}",
                self.format
            )));
        }

        let mut uids = BTreeSet::new();
        let mut aliases = BTreeSet::new();
        let mut public_salts = BTreeSet::new();

        diagnostics.extend(validate_seed_records(&self.seeds));

        for record in &self.credentials {
            diagnostics.extend(validate_token("credential alias", record.alias.as_str()));
            diagnostics.extend(validate_token("credential UID", record.uid.as_str()));
            if !uids.insert(record.uid.clone()) {
                diagnostics.push(Diagnostic::hard(format!(
                    "duplicate credential UID: {}",
                    record.uid.as_str()
                )));
            }
            if !aliases.insert(record.alias.clone()) {
                diagnostics.push(Diagnostic::hard(format!(
                    "duplicate credential alias: {}",
                    record.alias.as_str()
                )));
            }

            diagnostics.extend(validate_versions(record, &self.seeds, &mut public_salts));
        }

        diagnostics
    }
}

fn validate_seed_records(seeds: &BTreeMap<SeedLabel, SeedRecord>) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for (label, seed) in seeds {
        diagnostics.extend(validate_token("seed label", label.as_str()));
        diagnostics.extend(validate_token(
            "seed fingerprint",
            seed.fingerprint.as_str(),
        ));
        if !is_safe_seed_path(&seed.path) {
            diagnostics.push(Diagnostic::hard(format!(
                "seed {} has unsafe path: {}",
                label.as_str(),
                seed.path
            )));
        }
    }
    diagnostics
}

fn is_safe_seed_path(value: &str) -> bool {
    let path = Path::new(value);
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Normal(first)) if first == "seeds") {
        return false;
    }
    if components.next().is_none() {
        return false;
    }
    path.components()
        .all(|component| matches!(component, Component::Normal(_)))
}

fn validate_token(kind: &str, value: &str) -> Vec<Diagnostic> {
    if value.is_empty() || value.chars().any(char::is_control) {
        vec![Diagnostic::hard(format!(
            "{kind} contains empty or control-character data"
        ))]
    } else {
        Vec::new()
    }
}

fn validate_versions(
    record: &CredentialRecord,
    seeds: &BTreeMap<SeedLabel, SeedRecord>,
    public_salts: &mut BTreeSet<PublicSalt>,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let active_count = record
        .versions
        .iter()
        .filter(|version| version.status == VersionStatus::Active)
        .count();
    let pending_count = record
        .versions
        .iter()
        .filter(|version| version.status == VersionStatus::Pending)
        .count();

    if active_count > 1 {
        diagnostics.push(Diagnostic::hard(format!(
            "credential {} has more than one active version",
            record.uid.as_str()
        )));
    }
    if pending_count > 1 {
        diagnostics.push(Diagnostic::hard(format!(
            "credential {} has more than one pending version",
            record.uid.as_str()
        )));
    }
    if active_count == 0 && pending_count != 1 {
        diagnostics.push(Diagnostic::hard(format!(
            "credential {} must have one active version or exactly one pending version",
            record.uid.as_str()
        )));
    }

    let max_non_pending = record
        .versions
        .iter()
        .filter(|version| version.status != VersionStatus::Pending)
        .map(|version| version.number)
        .max()
        .unwrap_or(0);

    for version in &record.versions {
        if !seeds.contains_key(&version.seed) {
            diagnostics.push(Diagnostic::hard(format!(
                "credential {} version {} references unknown seed: {}",
                record.uid.as_str(),
                version.number,
                version.seed.as_str()
            )));
        }
        if version.scheme.as_str() != SCHEME_V1 {
            diagnostics.push(Diagnostic::hard(format!(
                "credential {} version {} uses unsupported scheme: {}",
                record.uid.as_str(),
                version.number,
                version.scheme.as_str()
            )));
        }
        if !public_salts.insert(version.public_salt.clone()) {
            diagnostics.push(Diagnostic::hard(format!(
                "duplicate public salt globally in recipes.yaml: {}",
                version.public_salt.as_str()
            )));
        }
        if decode_public_salt(&version.public_salt).is_none() {
            diagnostics.push(Diagnostic::hard(format!(
                "credential {} version {} has invalid public salt",
                record.uid.as_str(),
                version.number
            )));
        }
        if version.status == VersionStatus::Pending && version.number <= max_non_pending {
            diagnostics.push(Diagnostic::hard(format!(
                "credential {} pending version {} is not greater than previous versions",
                record.uid.as_str(),
                version.number
            )));
        }
        diagnostics.extend(version.profile_snapshot.validate_profile());
        diagnostics.extend(validate_timestamps(record, version));
    }

    diagnostics
}

fn decode_public_salt(public_salt: &PublicSalt) -> Option<[u8; 16]> {
    if public_salt.as_str().contains('=') {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(public_salt.as_str()).ok()?;
    decoded.try_into().ok()
}

fn validate_timestamps(record: &CredentialRecord, version: &CredentialVersion) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for (name, value) in [
        ("created_at", &version.created_at),
        ("confirmed_at", &version.confirmed_at),
        ("failed_at", &version.failed_at),
        ("retired_at", &version.retired_at),
        ("revoked_at", &version.revoked_at),
    ] {
        if let Some(value) = value {
            if OffsetDateTime::parse(value, &Rfc3339).is_err() {
                diagnostics.push(Diagnostic::hard(format!(
                    "credential {} version {} has invalid RFC3339 timestamp {}",
                    record.uid.as_str(),
                    version.number,
                    name
                )));
            }
        }
    }
    diagnostics
}

fn validate_password_profile(
    length: u16,
    min_uppercase: u16,
    min_lowercase: u16,
    min_digits: u16,
    min_symbols: u16,
    symbols: &str,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    if !(8..=256).contains(&length) {
        diagnostics.push(Diagnostic::hard(format!(
            "password length must be between 8 and 256, got {length}"
        )));
    }

    let minimum_sum = u32::from(min_uppercase)
        + u32::from(min_lowercase)
        + u32::from(min_digits)
        + u32::from(min_symbols);
    if minimum_sum > u32::from(length) {
        diagnostics.push(Diagnostic::hard(
            "password profile minimum counts exceed length",
        ));
    }

    if min_symbols > 0 && symbols.is_empty() {
        diagnostics.push(Diagnostic::hard(
            "password profile requires symbols but symbol set is empty",
        ));
    }

    let mut seen = HashSet::new();
    for ch in symbols.chars() {
        if !ch.is_ascii_graphic() || ch.is_ascii_whitespace() {
            diagnostics.push(Diagnostic::hard(format!(
                "symbol set contains non-printable or whitespace character: {ch:?}"
            )));
        }
        if ch.is_ascii_alphanumeric() {
            diagnostics.push(Diagnostic::hard(format!(
                "symbol set overlaps fixed alphanumeric classes: {ch:?}"
            )));
        }
        if !seen.insert(ch) {
            diagnostics.push(Diagnostic::hard(format!(
                "symbol set contains duplicate character: {ch:?}"
            )));
        }
    }

    if length > 0
        && min_uppercase == 0
        && min_lowercase == 0
        && min_digits == 0
        && min_symbols == 0
        && symbols.is_empty()
    {
        // Fixed lower/upper/digit classes are always in the allowed union for password profiles.
        // This branch is unreachable with the current profile model, but documents the invariant.
    }

    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn valid_recipes() -> RecipesFile {
        serde_yaml::from_str(
            r#"
format: seedpass-recipes-v1
seeds:
  personal:
    fingerprint: SPSEED-PSXY-OUAH-G6VN-YYDC-Y3JE-L337-5Q
    path: seeds/personal.seed
credentials:
  - uid: cred_01HX8K8M9G6TD9CZQK7BW6MQD2
    alias: github-personal
    purpose: web-password
    versions:
      - number: 1
        status: pending
        seed: personal
        scheme: seedpass-v1
        public_salt: EBESExQVFhcYGRobHB0eHw
        profile_snapshot:
          kind: password
          length: 24
          min_uppercase: 1
          min_lowercase: 1
          min_digits: 1
          min_symbols: 1
          symbols: "-_.!@#$%^&*"
        created_at: "2026-05-10T00:00:00Z"
"#,
        )
        .expect("valid recipes fixture")
    }

    fn valid_directory() -> DirectoryFile {
        serde_yaml::from_str(
            r#"
format: seedpass-directory-v1
entries:
  cred_01HX8K8M9G6TD9CZQK7BW6MQD2:
    alias: github-personal
    service: github.com
    username: alice@example.com
    tags: [dev, critical]
"#,
        )
        .expect("valid directory fixture")
    }

    #[test]
    fn lifecycle_transitions_match_plan() {
        assert!(VersionStatus::Pending.can_transition_to(VersionStatus::Active));
        assert!(VersionStatus::Pending.can_transition_to(VersionStatus::Failed));
        assert!(VersionStatus::Active.can_transition_to(VersionStatus::Retired));
        assert!(VersionStatus::Active.can_transition_to(VersionStatus::Revoked));
        assert!(VersionStatus::Retired.can_transition_to(VersionStatus::Revoked));

        assert!(!VersionStatus::Failed.can_transition_to(VersionStatus::Active));
        assert!(!VersionStatus::Revoked.can_transition_to(VersionStatus::Active));
    }

    proptest! {
        #[test]
        fn terminal_statuses_never_transition_to_any_status(next in any::<u8>()) {
            let statuses = [
                VersionStatus::Pending,
                VersionStatus::Active,
                VersionStatus::Retired,
                VersionStatus::Failed,
                VersionStatus::Revoked,
            ];
            let next = statuses[usize::from(next) % statuses.len()];
            prop_assert!(!VersionStatus::Failed.can_transition_to(next));
            prop_assert!(!VersionStatus::Revoked.can_transition_to(next));
        }
    }

    #[test]
    fn valid_pending_only_record_is_workspace_valid() {
        let recipes = valid_recipes();
        let directory = valid_directory();
        assert_eq!(
            recipes.validate_with_directory(Some(&directory)),
            Vec::new()
        );
    }

    #[test]
    fn invalid_manifests_from_vectors_are_rejected() {
        for path in [
            "../../tests/vectors/invalid/duplicate-public-salt.yaml",
            "../../tests/vectors/invalid/two-active-versions.yaml",
            "../../tests/vectors/invalid/unknown-scheme.yaml",
        ] {
            let yaml = std::fs::read_to_string(path).expect("invalid vector readable");
            let recipes: RecipesFile = serde_yaml::from_str(&yaml).expect("invalid vector parses");
            assert!(
                !recipes.is_valid(),
                "invalid vector unexpectedly valid: {path}"
            );
        }
    }

    #[test]
    fn unsafe_seed_paths_are_invalid() {
        let mut recipes = valid_recipes();
        recipes
            .seeds
            .get_mut(&SeedLabel::from("personal"))
            .expect("seed exists")
            .path = "../personal.seed".to_owned();
        assert!(recipes
            .validate()
            .iter()
            .any(|diagnostic| diagnostic.message.contains("unsafe path")));
    }

    #[test]
    fn control_characters_in_aliases_are_invalid() {
        let mut recipes = valid_recipes();
        recipes.credentials[0].alias = Alias::from("bad\nalias");
        assert!(recipes
            .validate()
            .iter()
            .any(|diagnostic| diagnostic.message.contains("control-character")));
    }

    #[test]
    fn directory_entries_must_reference_known_uids() {
        let recipes = valid_recipes();
        let mut directory = valid_directory();
        directory.entries.insert(
            CredentialUid::from("cred_01UNKNOWN"),
            DirectoryEntry {
                alias: Alias::from("unknown"),
                service: None,
                username: None,
                tags: Vec::new(),
            },
        );
        assert!(recipes
            .validate_with_directory(Some(&directory))
            .iter()
            .any(|diagnostic| diagnostic.message.contains("unknown credential UID")));
    }

    #[test]
    fn alias_rename_changes_directory_only() {
        let recipes = valid_recipes();
        let mut directory = valid_directory();
        let before_recipes = recipes.clone();
        directory
            .rename_alias(&Alias::from("github-personal"), Alias::from("github-main"))
            .expect("rename succeeds");
        assert_eq!(recipes, before_recipes);
        assert_eq!(
            directory
                .entries
                .get(&CredentialUid::from("cred_01HX8K8M9G6TD9CZQK7BW6MQD2"))
                .expect("entry exists")
                .alias,
            Alias::from("github-main")
        );
    }

    #[test]
    fn metadata_edits_do_not_affect_derivation_recipe() {
        let record = valid_recipes().credentials.remove(0);
        let version = record.versions.first().expect("version");
        let before = DerivationRecipeV1::from_record_version(&record, version);

        let mut changed = record.clone();
        changed.alias = Alias::from("renamed");
        let after = DerivationRecipeV1::from_record_version(&changed, version);

        assert_eq!(before, after);
    }

    #[test]
    fn timestamp_edits_do_not_affect_derivation_recipe() {
        let mut record = valid_recipes().credentials.remove(0);
        let before = DerivationRecipeV1::from_record_version(&record, &record.versions[0]);

        record.versions[0].created_at = Some("2030-01-01T00:00:00Z".to_owned());
        record.versions[0].failed_at = Some("2030-01-02T00:00:00Z".to_owned());
        let after = DerivationRecipeV1::from_record_version(&record, &record.versions[0]);

        assert_eq!(before, after);
    }

    #[test]
    fn seed_label_edits_do_not_affect_derivation_recipe() {
        let mut record = valid_recipes().credentials.remove(0);
        let before = DerivationRecipeV1::from_record_version(&record, &record.versions[0]);

        record.versions[0].seed = SeedLabel::from("renamed-personal");
        let after = DerivationRecipeV1::from_record_version(&record, &record.versions[0]);

        assert_eq!(before, after);
    }
}
