//! Filesystem persistence for Seedpass.
//!
//! Recipes and directory files are authoritative. The event log is diagnostic
//! and best-effort by default.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use directories::ProjectDirs;
use seedpass_codec::reject_duplicate_yaml_keys;
use seedpass_core::{Diagnostic, DirectoryFile, ProfilesFile, RecipesFile, Severity};
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

pub const CONFIG_FILE: &str = "seedpass.yaml";
pub const RECIPES_FILE: &str = "recipes.yaml";
pub const DIRECTORY_FILE: &str = "directory.yaml";
pub const PROFILES_FILE: &str = "profiles.yaml";
pub const SEEDS_DIR: &str = "seeds";
pub const HISTORY_DIR: &str = "history";
pub const EVENT_LOG_FILE: &str = "history/recipe-events.log";
pub const LOCK_FILE: &str = ".seedpass.lock";

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("could not resolve platform config directory")]
    ConfigDirUnavailable,
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("YAML error in {path}: {source}")]
    Yaml {
        path: PathBuf,
        source: serde_yaml::Error,
    },
    #[error("strict codec error in {path}: {source}")]
    Codec {
        path: PathBuf,
        source: seedpass_codec::CodecError,
    },
    #[error("workspace is already locked: {0}")]
    AlreadyLocked(PathBuf),
    #[error("unsafe seed path in recipes.yaml: {0}")]
    UnsafeSeedPath(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePaths {
    pub config_dir: PathBuf,
}

impl WorkspacePaths {
    pub fn new(config_dir: impl Into<PathBuf>) -> Self {
        Self {
            config_dir: config_dir.into(),
        }
    }

    pub fn platform_default() -> Result<Self, StorageError> {
        let dirs = ProjectDirs::from("org", "seedpass", "seedpass")
            .ok_or(StorageError::ConfigDirUnavailable)?;
        Ok(Self::new(dirs.config_dir()))
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join(CONFIG_FILE)
    }

    pub fn recipes_file(&self) -> PathBuf {
        self.config_dir.join(RECIPES_FILE)
    }

    pub fn directory_file(&self) -> PathBuf {
        self.config_dir.join(DIRECTORY_FILE)
    }

    pub fn profiles_file(&self) -> PathBuf {
        self.config_dir.join(PROFILES_FILE)
    }

    pub fn seeds_dir(&self) -> PathBuf {
        self.config_dir.join(SEEDS_DIR)
    }

    pub fn history_dir(&self) -> PathBuf {
        self.config_dir.join(HISTORY_DIR)
    }

    pub fn event_log_file(&self) -> PathBuf {
        self.config_dir.join(EVENT_LOG_FILE)
    }

    pub fn lock_file(&self) -> PathBuf {
        self.config_dir.join(LOCK_FILE)
    }

    pub fn seed_file(&self, relative_path: &str) -> PathBuf {
        self.config_dir.join(relative_path)
    }

    pub fn resolve_seed_file(&self, relative_path: &str) -> Result<PathBuf, StorageError> {
        validate_seed_path(relative_path)?;
        let path = self.seed_file(relative_path);
        match fs::canonicalize(&path) {
            Ok(canonical_path) => {
                let canonical_root =
                    fs::canonicalize(&self.config_dir).map_err(|source| StorageError::Io {
                        path: self.config_dir.clone(),
                        source,
                    })?;
                if !canonical_path.starts_with(&canonical_root) {
                    return Err(StorageError::UnsafeSeedPath(relative_path.to_owned()));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(StorageError::Io {
                    path: path.clone(),
                    source,
                });
            }
        }
        Ok(path)
    }
}

#[derive(Debug)]
pub struct WorkspaceLock {
    path: PathBuf,
}

impl WorkspaceLock {
    pub fn acquire(paths: &WorkspacePaths) -> Result<Self, StorageError> {
        ensure_private_dir(&paths.config_dir)?;
        let path = paths.lock_file();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&path).map_err(|source| {
            if source.kind() == std::io::ErrorKind::AlreadyExists {
                StorageError::AlreadyLocked(path.clone())
            } else {
                StorageError::Io {
                    path: path.clone(),
                    source,
                }
            }
        })?;
        writeln!(file, "{}", std::process::id()).map_err(|source| StorageError::Io {
            path: path.clone(),
            source,
        })?;
        file.sync_all().map_err(|source| StorageError::Io {
            path: path.clone(),
            source,
        })?;
        Ok(Self { path })
    }
}

impl Drop for WorkspaceLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    pub recipes: RecipesFile,
    pub directory: Option<DirectoryFile>,
    pub profiles: Option<ProfilesFile>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationReport {
    pub diagnostics: Vec<Diagnostic>,
}

impl ValidationReport {
    pub fn hard_errors(&self) -> Vec<&Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::HardError)
            .collect()
    }

    pub fn warnings(&self) -> Vec<&Diagnostic> {
        self.diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.severity == Severity::Warning)
            .collect()
    }

    pub fn is_hard_valid(&self) -> bool {
        self.hard_errors().is_empty()
    }
}

impl Workspace {
    pub fn validate(&self, paths: Option<&WorkspacePaths>) -> ValidationReport {
        let mut diagnostics = self
            .recipes
            .validate_with_directory(self.directory.as_ref());

        if let Some(paths) = paths {
            diagnostics.extend(seed_permission_diagnostics(paths, &self.recipes));
        }

        ValidationReport { diagnostics }
    }

    pub fn ensure_derivation_allowed(
        &self,
        paths: Option<&WorkspacePaths>,
    ) -> Result<(), Vec<Diagnostic>> {
        let report = self.validate(paths);
        let hard_errors = report
            .diagnostics
            .into_iter()
            .filter(|diagnostic| diagnostic.severity == Severity::HardError)
            .collect::<Vec<_>>();
        if hard_errors.is_empty() {
            Ok(())
        } else {
            Err(hard_errors)
        }
    }
}

pub fn load_workspace(paths: &WorkspacePaths) -> Result<Workspace, StorageError> {
    Ok(Workspace {
        recipes: load_yaml_strict(&paths.recipes_file())?,
        directory: load_optional_yaml_strict(&paths.directory_file())?,
        profiles: load_optional_yaml_strict(&paths.profiles_file())?,
    })
}

pub fn load_yaml_strict<T: DeserializeOwned>(path: &Path) -> Result<T, StorageError> {
    let text = fs::read_to_string(path).map_err(|source| StorageError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    reject_duplicate_yaml_keys(&text).map_err(|source| StorageError::Codec {
        path: path.to_path_buf(),
        source,
    })?;
    serde_yaml::from_str(&text).map_err(|source| StorageError::Yaml {
        path: path.to_path_buf(),
        source,
    })
}

pub fn load_optional_yaml_strict<T: DeserializeOwned>(
    path: &Path,
) -> Result<Option<T>, StorageError> {
    match fs::metadata(path) {
        Ok(_) => load_yaml_strict(path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(StorageError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

pub fn save_yaml_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), StorageError> {
    let yaml = serde_yaml::to_string(value).map_err(|source| StorageError::Yaml {
        path: path.to_path_buf(),
        source,
    })?;
    atomic_write(path, yaml.as_bytes(), false)
}

pub fn save_seed_atomic(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    atomic_write(path, bytes, true)
}

pub fn atomic_write(path: &Path, bytes: &[u8], secret: bool) -> Result<(), StorageError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| StorageError::Io {
        path: parent.to_path_buf(),
        source,
    })?;

    let temp_path = path.with_extension(format!("tmp.{}.{}", std::process::id(), unique_suffix()));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if secret {
        options.mode(0o600);
    }

    let mut file = options
        .open(&temp_path)
        .map_err(|source| StorageError::Io {
            path: temp_path.clone(),
            source,
        })?;
    file.write_all(bytes).map_err(|source| StorageError::Io {
        path: temp_path.clone(),
        source,
    })?;
    file.sync_all().map_err(|source| StorageError::Io {
        path: temp_path.clone(),
        source,
    })?;
    drop(file);

    fs::rename(&temp_path, path).map_err(|source| StorageError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

pub fn append_event_best_effort(
    paths: &WorkspacePaths,
    event_yaml: &str,
) -> Result<(), StorageError> {
    ensure_private_dir(&paths.history_dir())?;
    let path = paths.event_log_file();
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&path).map_err(|source| StorageError::Io {
        path: path.clone(),
        source,
    })?;
    file.write_all(event_yaml.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|source| StorageError::Io { path, source })
}

fn seed_permission_diagnostics(paths: &WorkspacePaths, recipes: &RecipesFile) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    for seed in recipes.seeds.values() {
        let path = match paths.resolve_seed_file(&seed.path) {
            Ok(path) => path,
            Err(error) => {
                diagnostics.push(Diagnostic::hard(error.to_string()));
                continue;
            }
        };
        match fs::metadata(&path) {
            Ok(metadata) => {
                #[cfg(unix)]
                {
                    let mode = metadata.permissions().mode() & 0o777;
                    if mode & 0o077 != 0 {
                        diagnostics.push(Diagnostic::warning(format!(
                            "seed file permissions are too broad: {} mode {:o}",
                            path.display(),
                            mode
                        )));
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                diagnostics.push(Diagnostic::hard(format!(
                    "missing seed file: {}",
                    path.display()
                )));
            }
            Err(error) => diagnostics.push(Diagnostic::hard(format!(
                "cannot inspect seed file {}: {}",
                path.display(),
                error
            ))),
        }
    }
    diagnostics
}

pub fn ensure_private_dir(path: &Path) -> Result<(), StorageError> {
    fs::create_dir_all(path).map_err(|source| StorageError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|source| {
        StorageError::Io {
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(())
}

fn validate_seed_path(relative_path: &str) -> Result<(), StorageError> {
    let path = Path::new(relative_path);
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::Normal(first)) if first == "seeds") {
        return Err(StorageError::UnsafeSeedPath(relative_path.to_owned()));
    }
    if components.next().is_none() {
        return Err(StorageError::UnsafeSeedPath(relative_path.to_owned()));
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(StorageError::UnsafeSeedPath(relative_path.to_owned()));
    }
    Ok(())
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seedpass_core::{Alias, CredentialUid, DirectoryEntry};
    use tempfile::tempdir;

    fn recipes_yaml() -> &'static str {
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
"#
    }

    fn directory_yaml() -> &'static str {
        r#"
format: seedpass-directory-v1
entries:
  cred_01HX8K8M9G6TD9CZQK7BW6MQD2:
    alias: github-personal
    service: github.com
    username: alice@example.com
    tags: [dev]
"#
    }

    #[test]
    fn workspace_paths_resolve_expected_files() {
        let paths = WorkspacePaths::new("/tmp/example-seedpass");
        assert!(paths.recipes_file().ends_with(RECIPES_FILE));
        assert!(paths.directory_file().ends_with(DIRECTORY_FILE));
        assert!(paths.profiles_file().ends_with(PROFILES_FILE));
        assert!(paths.event_log_file().ends_with(EVENT_LOG_FILE));
    }

    #[test]
    fn load_workspace_strictly_and_validate() {
        let dir = tempdir().expect("tempdir");
        let paths = WorkspacePaths::new(dir.path());
        fs::create_dir_all(paths.seeds_dir()).expect("seeds dir");
        fs::write(paths.recipes_file(), recipes_yaml()).expect("recipes");
        fs::write(paths.directory_file(), directory_yaml()).expect("directory");
        save_seed_atomic(&paths.seed_file("seeds/personal.seed"), b"not a real seed")
            .expect("seed write");

        let workspace = load_workspace(&paths).expect("workspace loads");
        assert!(workspace.validate(Some(&paths)).is_hard_valid());
    }

    #[test]
    fn duplicate_yaml_keys_are_rejected() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join(RECIPES_FILE);
        fs::write(&path, "format: a\nformat: b\n").expect("write");
        assert!(matches!(
            load_yaml_strict::<RecipesFile>(&path),
            Err(StorageError::Codec { .. })
        ));
    }

    #[test]
    fn atomic_write_replaces_content_without_partial_file() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("file.txt");
        atomic_write(&path, b"first", false).expect("first");
        atomic_write(&path, b"second", false).expect("second");
        assert_eq!(fs::read(&path).expect("read"), b"second");
    }

    #[test]
    fn lock_prevents_second_mutator() {
        let dir = tempdir().expect("tempdir");
        let paths = WorkspacePaths::new(dir.path());
        let _lock = WorkspaceLock::acquire(&paths).expect("first lock");
        assert!(matches!(
            WorkspaceLock::acquire(&paths),
            Err(StorageError::AlreadyLocked(_))
        ));
    }

    #[test]
    fn unsafe_seed_paths_are_rejected_before_joining() {
        let dir = tempdir().expect("tempdir");
        let paths = WorkspacePaths::new(dir.path());
        assert!(matches!(
            paths.resolve_seed_file("../outside.seed"),
            Err(StorageError::UnsafeSeedPath(_))
        ));
        assert!(matches!(
            paths.resolve_seed_file("/tmp/outside.seed"),
            Err(StorageError::UnsafeSeedPath(_))
        ));
        assert!(matches!(
            paths.resolve_seed_file("seeds/personal.seed"),
            Ok(path) if path.ends_with("seeds/personal.seed")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_seed_escape_is_rejected() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().expect("tempdir");
        let outside = tempdir().expect("outside");
        let paths = WorkspacePaths::new(dir.path());
        fs::create_dir_all(paths.seeds_dir()).expect("seeds dir");
        fs::write(outside.path().join("seed"), b"outside").expect("outside seed");
        symlink(
            outside.path().join("seed"),
            paths.seeds_dir().join("linked.seed"),
        )
        .expect("symlink");

        assert!(matches!(
            paths.resolve_seed_file("seeds/linked.seed"),
            Err(StorageError::UnsafeSeedPath(_))
        ));
    }

    #[test]
    fn event_log_append_is_written() {
        let dir = tempdir().expect("tempdir");
        let paths = WorkspacePaths::new(dir.path());
        append_event_best_effort(&paths, "- event: test").expect("append");
        let log = fs::read_to_string(paths.event_log_file()).expect("log");
        assert!(log.contains("event: test"));
    }

    #[test]
    fn validation_fails_for_missing_seed_file() {
        let dir = tempdir().expect("tempdir");
        let paths = WorkspacePaths::new(dir.path());
        fs::write(paths.recipes_file(), recipes_yaml()).expect("recipes");
        fs::write(paths.directory_file(), directory_yaml()).expect("directory");
        let workspace = load_workspace(&paths).expect("workspace loads");
        assert!(!workspace.validate(Some(&paths)).is_hard_valid());
    }

    #[test]
    fn save_yaml_atomic_round_trips_directory() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join(DIRECTORY_FILE);
        let mut entries = std::collections::BTreeMap::new();
        entries.insert(
            CredentialUid::from("cred_01HX8K8M9G6TD9CZQK7BW6MQD2"),
            DirectoryEntry {
                alias: Alias::from("github-personal"),
                service: Some("github.com".to_owned()),
                username: None,
                tags: Vec::new(),
            },
        );
        let directory = DirectoryFile {
            format: seedpass_core::DIRECTORY_FORMAT_V1.to_owned(),
            entries,
        };
        save_yaml_atomic(&path, &directory).expect("save");
        let loaded: DirectoryFile = load_yaml_strict(&path).expect("load");
        assert_eq!(loaded, directory);
    }
}
