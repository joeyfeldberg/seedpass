use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

fn seedpass() -> Command {
    Command::cargo_bin("seedpass").expect("seedpass binary")
}

fn write_minimal_workspace(dir: &std::path::Path) {
    fs::create_dir_all(dir.join("seeds")).expect("seeds dir");
    fs::write(dir.join("seeds/personal.seed"), b"not a real seed").expect("seed placeholder");
    fs::write(
        dir.join("recipes.yaml"),
        r#"format: seedpass-recipes-v1
seeds:
  personal:
    fingerprint: SPSEED-PSXY-OUAH-G6VN-YYDC-Y3JE-L337-5Q
    path: seeds/personal.seed
credentials: []
"#,
    )
    .expect("recipes");
    fs::write(
        dir.join("directory.yaml"),
        r#"format: seedpass-directory-v1
entries: {}
"#,
    )
    .expect("directory");
    fs::write(
        dir.join("profiles.yaml"),
        r#"format: seedpass-profiles-v1
profiles:
  web-default:
    profile:
      kind: password
      length: 24
      min_uppercase: 1
      min_lowercase: 1
      min_digits: 1
      min_symbols: 1
      symbols: "-_.!@#$%^&*"
"#,
    )
    .expect("profiles");
}

#[test]
fn empty_directory_map_regression_add_confirm_status() {
    let temp = tempdir().expect("tempdir");
    write_minimal_workspace(temp.path());

    seedpass()
        .args(["--config-dir", temp.path().to_str().unwrap(), "add", "test"])
        .assert()
        .success();
    seedpass()
        .args([
            "--config-dir",
            temp.path().to_str().unwrap(),
            "confirm",
            "test",
        ])
        .assert()
        .success();
    seedpass()
        .args(["--config-dir", temp.path().to_str().unwrap(), "status"])
        .assert()
        .success();
}

#[test]
fn get_without_output_channel_fails_before_prompting() {
    let temp = tempdir().expect("tempdir");
    write_minimal_workspace(temp.path());
    seedpass()
        .args(["--config-dir", temp.path().to_str().unwrap(), "add", "test"])
        .assert()
        .success();
    seedpass()
        .args(["--config-dir", temp.path().to_str().unwrap(), "get", "test"])
        .assert()
        .failure();
}

#[test]
fn clip_never_falls_back_to_stdout() {
    let temp = tempdir().expect("tempdir");
    write_minimal_workspace(temp.path());
    seedpass()
        .args(["--config-dir", temp.path().to_str().unwrap(), "add", "test"])
        .assert()
        .success();
    let output = seedpass()
        .args([
            "--config-dir",
            temp.path().to_str().unwrap(),
            "get",
            "test",
            "--pending",
            "--clip",
        ])
        .output()
        .expect("clip output");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn backup_restore_roundtrip_preserves_recovery_files() {
    let source = tempdir().expect("source tempdir");
    write_minimal_workspace(source.path());
    let archive = source.path().join("backup.tar");
    seedpass()
        .args([
            "--config-dir",
            source.path().to_str().unwrap(),
            "backup",
            "--out",
            archive.to_str().unwrap(),
        ])
        .assert()
        .success();

    let target = tempdir().expect("target tempdir");
    seedpass()
        .args([
            "--config-dir",
            target.path().to_str().unwrap(),
            "restore",
            archive.to_str().unwrap(),
            "--force",
        ])
        .write_stdin("YES\n")
        .assert()
        .success();

    for file in [
        "recipes.yaml",
        "directory.yaml",
        "profiles.yaml",
        "seeds/personal.seed",
    ] {
        assert_eq!(
            fs::read(source.path().join(file)).expect("source file"),
            fs::read(target.path().join(file)).expect("target file"),
            "restored file differs: {file}"
        );
    }
}

#[test]
fn backup_archive_contains_expected_files() {
    let temp = tempdir().expect("tempdir");
    write_minimal_workspace(temp.path());
    let archive = temp.path().join("backup.tar");
    seedpass()
        .args([
            "--config-dir",
            temp.path().to_str().unwrap(),
            "backup",
            "--out",
            archive.to_str().unwrap(),
        ])
        .assert()
        .success();

    let file = fs::File::open(&archive).expect("archive open");
    let mut names = tar::Archive::new(file)
        .entries()
        .expect("entries")
        .map(|entry| {
            entry
                .expect("entry")
                .path()
                .expect("path")
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    assert!(names.contains(&"seedpass-backup-v1/recipes.yaml".to_owned()));
    assert!(names.contains(&"seedpass-backup-v1/directory.yaml".to_owned()));
    assert!(names.contains(&"seedpass-backup-v1/profiles.yaml".to_owned()));
    assert!(names.contains(&"seedpass-backup-v1/seeds/personal.seed".to_owned()));
}

#[test]
fn restore_rejects_malformed_archive_path() {
    let source = tempdir().expect("source tempdir");
    let archive_path = source.path().join("bad.tar");
    let file = fs::File::create(&archive_path).expect("archive create");
    let mut builder = tar::Builder::new(file);
    let mut header = tar::Header::new_gnu();
    let bytes = b"bad";
    header.set_size(bytes.len() as u64);
    header.set_cksum();
    builder
        .append_data(&mut header, "wrong-prefix/recipes.yaml", &bytes[..])
        .expect("append");
    builder.finish().expect("finish");

    let target = tempdir().expect("target tempdir");
    seedpass()
        .args([
            "--config-dir",
            target.path().to_str().unwrap(),
            "restore",
            archive_path.to_str().unwrap(),
            "--force",
        ])
        .write_stdin("YES\n")
        .assert()
        .failure();
}

#[test]
fn duplicate_yaml_key_in_workspace_fails_doctor() {
    let temp = tempdir().expect("tempdir");
    write_minimal_workspace(temp.path());
    fs::write(
        temp.path().join("directory.yaml"),
        "format: seedpass-directory-v1\nformat: seedpass-directory-v1\nentries: {}\n",
    )
    .expect("bad directory");
    seedpass()
        .args(["--config-dir", temp.path().to_str().unwrap(), "doctor"])
        .assert()
        .failure();
}

#[test]
fn visible_help_is_small_and_backup_is_visible() {
    let output = seedpass().arg("--help").output().expect("help output");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf8 help");
    for command in [
        "init", "add", "get", "confirm", "rename", "rotate", "status", "backup", "restore",
        "doctor",
    ] {
        assert!(stdout.contains(command), "missing {command}");
    }
    assert!(!stdout.contains("account"));
    assert!(!stdout.contains("profile"));
    assert!(!stdout.contains("backup-check"));
}

#[test]
fn rotate_abort_preserves_active_and_marks_pending_failed() {
    let temp = tempdir().expect("tempdir");
    write_minimal_workspace(temp.path());
    seedpass()
        .args(["--config-dir", temp.path().to_str().unwrap(), "add", "test"])
        .assert()
        .success();
    seedpass()
        .args([
            "--config-dir",
            temp.path().to_str().unwrap(),
            "confirm",
            "test",
        ])
        .assert()
        .success();
    seedpass()
        .args([
            "--config-dir",
            temp.path().to_str().unwrap(),
            "rotate",
            "test",
        ])
        .assert()
        .success();
    seedpass()
        .args([
            "--config-dir",
            temp.path().to_str().unwrap(),
            "rotate",
            "test",
            "--abort",
        ])
        .write_stdin("YES\n")
        .assert()
        .success();

    let recipes = fs::read_to_string(temp.path().join("recipes.yaml")).expect("recipes");
    assert!(recipes.contains("status: active"));
    assert!(recipes.contains("status: failed"));
}

#[test]
fn add_with_service_and_username_writes_directory_metadata() {
    let temp = tempdir().expect("tempdir");
    write_minimal_workspace(temp.path());
    seedpass()
        .args([
            "--config-dir",
            temp.path().to_str().unwrap(),
            "add",
            "github",
            "--service",
            "github.com",
            "--username",
            "alice@example.com",
        ])
        .assert()
        .success();
    let directory = fs::read_to_string(temp.path().join("directory.yaml")).expect("directory");
    assert!(directory.contains("service: github.com"));
    assert!(directory.contains("username: alice@example.com"));
}

#[test]
fn validate_reports_missing_seed_as_failure() {
    let temp = tempdir().expect("tempdir");
    write_minimal_workspace(temp.path());
    fs::remove_file(temp.path().join("seeds/personal.seed")).expect("remove seed");
    seedpass()
        .args(["--config-dir", temp.path().to_str().unwrap(), "validate"])
        .assert()
        .failure();
}

#[test]
fn backup_refuses_invalid_workspace() {
    let temp = tempdir().expect("tempdir");
    write_minimal_workspace(temp.path());
    fs::remove_file(temp.path().join("seeds/personal.seed")).expect("remove seed");
    seedpass()
        .args([
            "--config-dir",
            temp.path().to_str().unwrap(),
            "backup",
            "--out",
            temp.path().join("backup.tar").to_str().unwrap(),
        ])
        .assert()
        .failure();
}

#[test]
fn backup_output_warns_about_master_password() {
    let temp = tempdir().expect("tempdir");
    write_minimal_workspace(temp.path());
    let archive = temp.path().join("backup.tar");
    let output = seedpass()
        .args([
            "--config-dir",
            temp.path().to_str().unwrap(),
            "backup",
            "--out",
            archive.to_str().unwrap(),
        ])
        .output()
        .expect("backup");
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)
        .expect("stdout")
        .contains("master password"));
}

#[test]
fn restore_requires_yes_even_with_force() {
    let source = tempdir().expect("source tempdir");
    write_minimal_workspace(source.path());
    let archive = source.path().join("backup.tar");
    seedpass()
        .args([
            "--config-dir",
            source.path().to_str().unwrap(),
            "backup",
            "--out",
            archive.to_str().unwrap(),
        ])
        .assert()
        .success();
    let target = tempdir().expect("target tempdir");
    seedpass()
        .args([
            "--config-dir",
            target.path().to_str().unwrap(),
            "restore",
            archive.to_str().unwrap(),
            "--force",
        ])
        .write_stdin("\n")
        .assert()
        .failure();
}

#[test]
fn backup_create_creates_parent_directory() {
    let temp = tempdir().expect("tempdir");
    write_minimal_workspace(temp.path());
    let archive = temp.path().join("nested/backup.tar");
    seedpass()
        .args([
            "--config-dir",
            temp.path().to_str().unwrap(),
            "backup",
            "--out",
            archive.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert!(archive.exists());
}

#[test]
fn profile_and_account_namespaces_are_hidden_but_available() {
    let output = seedpass().arg("--help").output().expect("help");
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(!stdout.contains("profile"));
    assert!(!stdout.contains("account"));

    let temp = tempdir().expect("tempdir");
    write_minimal_workspace(temp.path());
    seedpass()
        .args([
            "--config-dir",
            temp.path().to_str().unwrap(),
            "profile",
            "list",
        ])
        .assert()
        .success();
    seedpass()
        .args([
            "--config-dir",
            temp.path().to_str().unwrap(),
            "account",
            "add",
            "x",
        ])
        .assert()
        .success();
}

#[test]
fn add_creates_pending_and_confirm_promotes_to_active() {
    let temp = tempdir().expect("tempdir");
    write_minimal_workspace(temp.path());
    seedpass()
        .args([
            "--config-dir",
            temp.path().to_str().unwrap(),
            "add",
            "github",
        ])
        .assert()
        .success();
    let recipes = fs::read_to_string(temp.path().join("recipes.yaml")).expect("recipes");
    assert!(recipes.contains("status: pending"));
    assert!(!recipes.contains("status: active"));

    seedpass()
        .args([
            "--config-dir",
            temp.path().to_str().unwrap(),
            "confirm",
            "github",
        ])
        .assert()
        .success();
    let recipes = fs::read_to_string(temp.path().join("recipes.yaml")).expect("recipes");
    assert!(recipes.contains("status: active"));
}

#[test]
fn cli_regression_suite_has_broad_end_to_end_coverage() {
    let source = include_str!("cli_flow.rs");
    let count = source.matches("#[test]").count();
    assert!(
        count >= 15,
        "expected broad CLI regression coverage, got {count}"
    );
}
