use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use clap::{Args, Parser, Subcommand};
use rand::random;
use seedpass_core::{
    Alias, CredentialRecord, CredentialUid, CredentialVersion, DerivationRecipeV1, DirectoryEntry,
    DirectoryFile, ProfileSnapshot, ProfileTemplate, ProfilesFile, PublicSalt, Purpose,
    RecipesFile, Scheme, SeedFingerprint, SeedLabel, SeedRecord, VersionStatus,
    DIRECTORY_FORMAT_V1, RECIPES_FORMAT_V1, SCHEME_V1,
};
use seedpass_crypto::{
    decrypt_seed, encrypt_seed, kdf_parameter_warnings, seed_fingerprint_display,
    verify_seed_fingerprint, RootSeed, SeedEnvelopeV1,
};
use seedpass_derive::{derive_password, recipe_hash};
use seedpass_storage::{
    append_event_best_effort, atomic_write, ensure_private_dir, load_workspace, save_seed_atomic,
    save_yaml_atomic, WorkspaceLock, WorkspacePaths,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use ulid::Ulid;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Parser)]
#[command(name = "seedpass")]
#[command(version)]
#[command(about = "Spec-first, seed-backed deterministic credential compiler")]
struct Cli {
    /// Override config directory.
    #[arg(long, global = true)]
    config_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Initialize a Seedpass workspace.
    Init,
    /// Add a login.
    Add(AccountAddArgs),
    /// Get a password. Requires --show for terminal output.
    Get(PassArgs),
    /// Confirm that a pending password was accepted by the site.
    Confirm { alias: String },
    /// Rename a login.
    Rename {
        old_alias: String,
        new_alias: String,
    },
    /// Rotate a password.
    Rotate(RotateArgs),
    /// Show workspace status and recovery files.
    Status,
    /// Create a recovery backup archive.
    Backup(BackupArgs),
    /// Restore from a backup archive.
    Restore(RestoreArgs),
    /// Check for problems.
    Doctor,

    /// Advanced backup-check commands.
    #[command(hide = true)]
    BackupCheck {
        #[command(subcommand)]
        command: BackupCommand,
    },

    /// Validate workspace correctness. Hard errors exit nonzero.
    #[command(hide = true)]
    Validate,
    /// Advanced profile/rule commands.
    #[command(hide = true)]
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Advanced account commands.
    #[command(hide = true)]
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
    /// Advanced alias for `get`.
    #[command(hide = true)]
    Pass(PassArgs),
    /// Explain a credential without revealing secrets.
    #[command(hide = true)]
    Explain { alias: String },
    /// Seed lifecycle commands.
    #[command(hide = true)]
    Seed {
        #[command(subcommand)]
        command: SeedCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ProfileCommand {
    Add(ProfileAddArgs),
    List,
    Show { name: String },
}

#[derive(Debug, Args)]
struct ProfileAddArgs {
    name: String,
    #[arg(long)]
    length: u16,
    #[arg(long, default_value_t = 1)]
    min_uppercase: u16,
    #[arg(long, default_value_t = 1)]
    min_lowercase: u16,
    #[arg(long, default_value_t = 1)]
    min_digits: u16,
    #[arg(long, default_value_t = 1)]
    min_symbols: u16,
    #[arg(long, default_value = "-_.!@#$%^&*")]
    symbols: String,
}

#[derive(Debug, Subcommand)]
enum AccountCommand {
    Add(AccountAddArgs),
    Rename {
        old_alias: String,
        new_alias: String,
    },
    Confirm {
        alias: String,
    },
}

#[derive(Debug, Args)]
struct AccountAddArgs {
    alias: String,
    #[arg(long)]
    service: Option<String>,
    #[arg(long)]
    username: Option<String>,
    #[arg(long, default_value = "web-default")]
    profile: String,
}

#[derive(Debug, Args)]
struct PassArgs {
    alias: String,
    #[arg(long)]
    pending: bool,
    #[arg(long)]
    show: bool,
    #[arg(long)]
    clip: bool,
    #[arg(long)]
    strict: bool,
    #[arg(long)]
    version: Option<u32>,
    #[arg(long)]
    allow_retired: bool,
}

#[derive(Debug, Args)]
struct RotateArgs {
    alias: String,
    #[arg(long)]
    confirm: bool,
    #[arg(long)]
    abort: bool,
}

#[derive(Debug, Subcommand)]
enum SeedCommand {
    Fingerprint {
        path: PathBuf,
    },
    Verify {
        path: PathBuf,
        expected_fingerprint: String,
    },
    Rewrap {
        path: PathBuf,
    },
}

#[derive(Debug, Args)]
struct BackupArgs {
    /// Output tar file.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Debug, Args)]
struct RestoreArgs {
    /// Backup tar file to restore.
    archive: PathBuf,
    /// Replace an existing config directory.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Subcommand)]
enum BackupCommand {
    Status,
    Test { path: PathBuf },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let paths = match cli.config_dir {
        Some(path) => WorkspacePaths::new(path),
        None => WorkspacePaths::platform_default()?,
    };

    match cli.command {
        Some(Command::Init) => run_init(&paths)?,
        Some(Command::Validate) => run_validate(&paths)?,
        Some(Command::Doctor) => run_doctor(&paths)?,
        Some(Command::Add(args)) => run_account(&paths, AccountCommand::Add(args))?,
        Some(Command::Get(args)) => run_pass(&paths, args)?,
        Some(Command::Confirm { alias }) => run_account(&paths, AccountCommand::Confirm { alias })?,
        Some(Command::Rename {
            old_alias,
            new_alias,
        }) => run_account(
            &paths,
            AccountCommand::Rename {
                old_alias,
                new_alias,
            },
        )?,
        Some(Command::Profile { command }) => run_profile(&paths, command)?,
        Some(Command::Account { command }) => run_account(&paths, command)?,
        Some(Command::Pass(args)) => run_pass(&paths, args)?,
        Some(Command::Rotate(args)) => run_rotate(&paths, args)?,
        Some(Command::Status) => run_backup_check(&paths, BackupCommand::Status)?,
        Some(Command::Backup(args)) => run_backup_create(&paths, args)?,
        Some(Command::Restore(args)) => run_restore(&paths, args)?,
        Some(Command::Explain { alias }) => run_explain(&paths, &alias)?,
        Some(Command::Seed { command }) => run_seed(command)?,
        Some(Command::BackupCheck { command }) => run_backup_check(&paths, command)?,
        None => println!("Seedpass workspace scaffold is ready. Use --help for commands."),
    }

    Ok(())
}

fn run_init(paths: &WorkspacePaths) -> anyhow::Result<()> {
    let _lock = WorkspaceLock::acquire(paths)?;
    ensure_private_dir(&paths.config_dir)?;
    ensure_private_dir(&paths.seeds_dir())?;
    ensure_private_dir(&paths.history_dir())?;

    let mut master = Zeroizing::new(rpassword::prompt_password("New master password: ")?);
    let confirm = Zeroizing::new(rpassword::prompt_password("Confirm master password: ")?);
    if master.as_str() != confirm.as_str() {
        anyhow::bail!("master passwords do not match");
    }

    let seed = RootSeed::generate();
    let envelope = encrypt_seed(&seed, master.as_bytes())?;
    master.zeroize();
    let fingerprint = seed_fingerprint_display(&seed)?;
    save_seed_atomic(
        &paths.seed_file("seeds/personal.seed"),
        &serde_json::to_vec_pretty(&envelope)?,
    )?;

    let mut seeds = BTreeMap::new();
    seeds.insert(
        SeedLabel::from("personal"),
        SeedRecord {
            fingerprint: SeedFingerprint::from(fingerprint.clone()),
            path: "seeds/personal.seed".to_owned(),
        },
    );
    let recipes = RecipesFile {
        format: RECIPES_FORMAT_V1.to_owned(),
        seeds,
        credentials: Vec::new(),
    };
    save_yaml_atomic(&paths.recipes_file(), &recipes)?;

    let directory = DirectoryFile {
        format: DIRECTORY_FORMAT_V1.to_owned(),
        entries: BTreeMap::new(),
    };
    save_yaml_atomic(&paths.directory_file(), &directory)?;

    let mut profiles = BTreeMap::new();
    profiles.insert(
        "web-default".to_owned(),
        ProfileTemplate {
            profile: default_profile(),
        },
    );
    save_yaml_atomic(
        &paths.profiles_file(),
        &ProfilesFile {
            format: "seedpass-profiles-v1".to_owned(),
            profiles,
        },
    )?;

    println!(
        "Created Seedpass workspace at {}",
        paths.config_dir.display()
    );
    println!("Seed fingerprint: {fingerprint}");
    println!("Back up recipes.yaml, directory.yaml, and seeds/personal.seed");
    Ok(())
}

fn run_validate(paths: &WorkspacePaths) -> anyhow::Result<()> {
    let workspace = load_workspace(paths)?;
    let report = workspace.validate(Some(paths));
    for diagnostic in &report.diagnostics {
        println!("{:?}: {}", diagnostic.severity, diagnostic.message);
    }
    if report.is_hard_valid() {
        println!("Workspace valid.");
        Ok(())
    } else {
        anyhow::bail!("workspace has hard validation errors")
    }
}

fn run_doctor(paths: &WorkspacePaths) -> anyhow::Result<()> {
    let workspace = load_workspace(paths)?;
    let report = workspace.validate(Some(paths));
    let mut any = false;
    for diagnostic in report.diagnostics {
        any = true;
        println!("{:?}: {}", diagnostic.severity, diagnostic.message);
    }
    for warning in doctor_warnings(paths, &workspace)? {
        any = true;
        println!("Warning: {warning}");
    }
    if !any {
        println!("No issues found.");
    }
    Ok(())
}

fn run_profile(paths: &WorkspacePaths, command: ProfileCommand) -> anyhow::Result<()> {
    match command {
        ProfileCommand::Add(args) => {
            let _lock = WorkspaceLock::acquire(paths)?;
            let mut profiles = load_profiles_or_default(paths)?;
            if profiles.profiles.contains_key(&args.name) {
                anyhow::bail!("profile already exists: {}", args.name);
            }
            let profile = ProfileSnapshot::Password {
                length: args.length,
                min_uppercase: args.min_uppercase,
                min_lowercase: args.min_lowercase,
                min_digits: args.min_digits,
                min_symbols: args.min_symbols,
                symbols: args.symbols,
            };
            let errors = profile.validate_profile();
            if !errors.is_empty() {
                anyhow::bail!("invalid profile: {}", errors[0].message);
            }
            profiles
                .profiles
                .insert(args.name.clone(), ProfileTemplate { profile });
            save_yaml_atomic(&paths.profiles_file(), &profiles)?;
            println!("Added profile: {}", args.name);
        }
        ProfileCommand::List => {
            let profiles = load_profiles_or_default(paths)?;
            for name in profiles.profiles.keys() {
                println!("{name}");
            }
        }
        ProfileCommand::Show { name } => {
            let profiles = load_profiles_or_default(paths)?;
            let profile = profiles
                .profiles
                .get(&name)
                .ok_or_else(|| anyhow::anyhow!("profile not found: {name}"))?;
            println!("{}", serde_yaml::to_string(profile)?);
        }
    }
    Ok(())
}

fn run_account(paths: &WorkspacePaths, command: AccountCommand) -> anyhow::Result<()> {
    let _lock = WorkspaceLock::acquire(paths)?;
    let mut workspace = load_workspace(paths)?;
    match command {
        AccountCommand::Add(args) => {
            if workspace
                .recipes
                .credentials
                .iter()
                .any(|record| record.alias.as_str() == args.alias)
            {
                anyhow::bail!("alias already exists: {}", args.alias);
            }
            let profiles = load_profiles_or_default(paths)?;
            let profile = profiles
                .profiles
                .get(&args.profile)
                .ok_or_else(|| anyhow::anyhow!("profile not found: {}", args.profile))?
                .profile
                .clone();
            let uid = CredentialUid::from(format!("cred_{}", Ulid::new()));
            let salt: [u8; 16] = random();
            let seed = workspace
                .recipes
                .seeds
                .keys()
                .next()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("no seed configured"))?;
            workspace.recipes.credentials.push(CredentialRecord {
                uid: uid.clone(),
                alias: Alias::from(args.alias.clone()),
                purpose: Purpose::WebPassword,
                versions: vec![CredentialVersion {
                    number: 1,
                    status: VersionStatus::Pending,
                    seed,
                    scheme: Scheme::from(SCHEME_V1),
                    public_salt: PublicSalt::from(URL_SAFE_NO_PAD.encode(salt)),
                    profile_snapshot: profile,
                    created_at: Some(now_rfc3339()),
                    confirmed_at: None,
                    failed_at: None,
                    retired_at: None,
                    revoked_at: None,
                }],
            });
            let directory = workspace.directory.get_or_insert_with(|| DirectoryFile {
                format: DIRECTORY_FORMAT_V1.to_owned(),
                entries: BTreeMap::new(),
            });
            directory.entries.insert(
                uid.clone(),
                DirectoryEntry {
                    alias: Alias::from(args.alias.clone()),
                    service: args.service,
                    username: args.username,
                    tags: Vec::new(),
                },
            );
            save_workspace(paths, &workspace)?;
            let mut event = BTreeMap::new();
            event.insert("alias", args.alias.clone());
            event.insert("at", now_rfc3339());
            event.insert("credential_uid", uid.as_str().to_owned());
            event.insert("event", "credential.created".to_owned());
            let _ = append_event_best_effort(paths, &serde_yaml::to_string(&vec![event])?);
            println!("Created pending credential:");
            println!("  alias:   {}", args.alias);
            println!("  uid:     {}", uid.as_str());
            println!("  version: 1 pending");
        }
        AccountCommand::Rename {
            old_alias,
            new_alias,
        } => {
            let record = find_record_mut(&mut workspace.recipes, &old_alias)?;
            record.alias = Alias::from(new_alias.clone());
            if let Some(directory) = &mut workspace.directory {
                directory.rename_alias(
                    &Alias::from(old_alias.as_str()),
                    Alias::from(new_alias.clone()),
                )?;
            }
            save_workspace(paths, &workspace)?;
            println!("Renamed account {old_alias} -> {new_alias}");
        }
        AccountCommand::Confirm { alias } => {
            confirm_pending(&mut workspace.recipes, &alias)?;
            save_workspace(paths, &workspace)?;
            println!("Confirmed pending credential for {alias}");
        }
    }
    Ok(())
}

fn run_pass(paths: &WorkspacePaths, args: PassArgs) -> anyhow::Result<()> {
    if !args.show && !args.clip {
        anyhow::bail!("no output channel requested; use --show or --clip");
    }
    if args.clip {
        anyhow::bail!(
            "clipboard output is not implemented in this MVP build; use --show explicitly"
        );
    }
    let workspace = load_workspace(paths)?;
    workspace
        .ensure_derivation_allowed(Some(paths))
        .map_err(|errors| {
            anyhow::anyhow!(
                "workspace has hard validation errors: {}",
                errors
                    .into_iter()
                    .map(|d| d.message)
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        })?;
    let (record, version) = select_version(&workspace.recipes, &args)?;
    let seed_record = workspace
        .recipes
        .seeds
        .get(&version.seed)
        .ok_or_else(|| anyhow::anyhow!("seed not found"))?;
    let envelope = read_seed_envelope(&paths.resolve_seed_file(&seed_record.path)?)?;
    let mut master = Zeroizing::new(rpassword::prompt_password("Master password: ")?);
    if !verify_seed_fingerprint(
        &envelope,
        master.as_bytes(),
        seed_record.fingerprint.as_str(),
    )? {
        anyhow::bail!("seed fingerprint mismatch");
    }
    let seed = decrypt_seed(&envelope, master.as_bytes())?;
    master.zeroize();
    let recipe = DerivationRecipeV1::from_record_version(record, version);
    let password = Zeroizing::new(derive_password(&seed, &recipe)?);
    println!("{}", password.as_str());
    Ok(())
}

fn run_rotate(paths: &WorkspacePaths, args: RotateArgs) -> anyhow::Result<()> {
    if args.confirm && args.abort {
        anyhow::bail!("choose only one of --confirm or --abort");
    }
    let _lock = WorkspaceLock::acquire(paths)?;
    let mut workspace = load_workspace(paths)?;
    if args.confirm {
        confirm_prompt(
            "Confirm pending rotation? The previous active version will become retired.",
        )?;
        confirm_pending(&mut workspace.recipes, &args.alias)?;
        println!("Confirmed rotation for {}", args.alias);
    } else if args.abort {
        confirm_prompt("Abort pending rotation? The pending version will be marked failed.")?;
        let record = find_record_mut(&mut workspace.recipes, &args.alias)?;
        let pending = record
            .versions
            .iter_mut()
            .find(|version| version.status == VersionStatus::Pending)
            .ok_or_else(|| anyhow::anyhow!("no pending version for {}", args.alias))?;
        pending.status = VersionStatus::Failed;
        pending.failed_at = Some(now_rfc3339());
        println!("Aborted pending rotation for {}", args.alias);
    } else {
        let record = find_record_mut(&mut workspace.recipes, &args.alias)?;
        if record
            .versions
            .iter()
            .any(|version| version.status == VersionStatus::Pending)
        {
            anyhow::bail!("pending version already exists for {}", args.alias);
        }
        let active = record
            .versions
            .iter()
            .find(|version| version.status == VersionStatus::Active)
            .ok_or_else(|| anyhow::anyhow!("no active version for {}", args.alias))?
            .clone();
        let next = record
            .versions
            .iter()
            .map(|version| version.number)
            .max()
            .unwrap_or(0)
            + 1;
        let salt: [u8; 16] = random();
        record.versions.push(CredentialVersion {
            number: next,
            status: VersionStatus::Pending,
            seed: active.seed,
            scheme: active.scheme,
            public_salt: PublicSalt::from(URL_SAFE_NO_PAD.encode(salt)),
            profile_snapshot: active.profile_snapshot,
            created_at: Some(now_rfc3339()),
            confirmed_at: None,
            failed_at: None,
            retired_at: None,
            revoked_at: None,
        });
        println!("Created pending version {next} for {}", args.alias);
    }
    save_workspace(paths, &workspace)?;
    Ok(())
}

fn run_explain(paths: &WorkspacePaths, alias: &str) -> anyhow::Result<()> {
    let workspace = load_workspace(paths)?;
    let record = find_record(&workspace.recipes, alias)?;
    println!("Alias:      {}", record.alias.as_str());
    println!("Credential: {}", record.uid.as_str());
    for version in &record.versions {
        let recipe = DerivationRecipeV1::from_record_version(record, version);
        println!("Version:    {} {:?}", version.number, version.status);
        println!("Seed:       {}", version.seed.as_str());
        println!("Recipe SHA: {}", hex(&recipe_hash(&recipe)?));
    }
    Ok(())
}

fn run_seed(command: SeedCommand) -> anyhow::Result<()> {
    match command {
        SeedCommand::Fingerprint { path } => {
            let envelope = read_seed_envelope(&path)?;
            let mut master = Zeroizing::new(rpassword::prompt_password("Master password: ")?);
            let seed = decrypt_seed(&envelope, master.as_bytes())?;
            master.zeroize();
            println!("{}", seed_fingerprint_display(&seed)?);
        }
        SeedCommand::Verify {
            path,
            expected_fingerprint,
        } => {
            let envelope = read_seed_envelope(&path)?;
            let mut master = Zeroizing::new(rpassword::prompt_password("Master password: ")?);
            let verified =
                verify_seed_fingerprint(&envelope, master.as_bytes(), &expected_fingerprint)?;
            master.zeroize();
            if verified {
                println!("Seed fingerprint verified: {expected_fingerprint}");
            } else {
                anyhow::bail!("seed fingerprint mismatch");
            }
        }
        SeedCommand::Rewrap { path } => {
            confirm_prompt("Rewrap this seed file? Derived credentials remain unchanged, but the seed file will be replaced.")?;
            let envelope = read_seed_envelope(&path)?;
            let mut old_master =
                Zeroizing::new(rpassword::prompt_password("Old master password: ")?);
            let seed = decrypt_seed(&envelope, old_master.as_bytes())?;
            old_master.zeroize();
            let fingerprint = seed_fingerprint_display(&seed)?;
            let mut new_master =
                Zeroizing::new(rpassword::prompt_password("New master password: ")?);
            let confirm =
                Zeroizing::new(rpassword::prompt_password("Confirm new master password: ")?);
            if new_master.as_str() != confirm.as_str() {
                anyhow::bail!("new master passwords do not match");
            }
            let new_envelope = encrypt_seed(&seed, new_master.as_bytes())?;
            let after = decrypt_seed(&new_envelope, new_master.as_bytes())?;
            new_master.zeroize();
            if fingerprint != seed_fingerprint_display(&after)? {
                anyhow::bail!("internal error: rewrap changed seed fingerprint");
            }
            save_seed_atomic(&path, &serde_json::to_vec_pretty(&new_envelope)?)?;
            println!("Seed rewrapped.");
            println!("Fingerprint unchanged: {fingerprint}");
            println!("Derived credentials are unchanged.");
        }
    }
    Ok(())
}

fn run_backup_create(paths: &WorkspacePaths, args: BackupArgs) -> anyhow::Result<()> {
    let workspace = load_workspace(paths)?;
    let report = workspace.validate(Some(paths));
    if !report.is_hard_valid() {
        anyhow::bail!("workspace has hard validation errors; run `seedpass doctor` first");
    }

    if let Some(parent) = args.out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let file = fs::File::create(&args.out)?;
    let mut archive = tar::Builder::new(file);
    append_if_exists(
        &mut archive,
        &paths.recipes_file(),
        "seedpass-backup-v1/recipes.yaml",
    )?;
    append_if_exists(
        &mut archive,
        &paths.directory_file(),
        "seedpass-backup-v1/directory.yaml",
    )?;
    append_if_exists(
        &mut archive,
        &paths.profiles_file(),
        "seedpass-backup-v1/profiles.yaml",
    )?;
    for seed in workspace.recipes.seeds.values() {
        let seed_path = paths.resolve_seed_file(&seed.path)?;
        let archive_path = format!("seedpass-backup-v1/{}", seed.path);
        append_if_exists(&mut archive, &seed_path, &archive_path)?;
    }
    archive.finish()?;

    println!("Backup created: {}", args.out.display());
    println!("This backup contains your encrypted seed file.");
    println!("You still need your master password to recover passwords.");
    Ok(())
}

fn run_restore(paths: &WorkspacePaths, args: RestoreArgs) -> anyhow::Result<()> {
    if paths.config_dir.exists() && !args.force {
        anyhow::bail!(
            "config directory already exists: {} (use --force to replace files)",
            paths.config_dir.display()
        );
    }
    confirm_prompt("Restore this backup into the config directory?")?;
    ensure_private_dir(&paths.config_dir)?;

    let file = fs::File::open(&args.archive)?;
    let mut archive = tar::Archive::new(file);
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let entry_path = entry.path()?.into_owned();
        let relative = backup_relative_path(&entry_path)?;
        let target = paths.config_dir.join(&relative);
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut bytes)?;
        let secret = relative.starts_with("seeds/");
        atomic_write(&target, &bytes, secret)?;
    }

    println!("Restored backup into {}", paths.config_dir.display());
    println!("Run `seedpass doctor` to check the restored workspace.");
    Ok(())
}

fn append_if_exists(
    archive: &mut tar::Builder<fs::File>,
    source: &Path,
    archive_path: &str,
) -> anyhow::Result<()> {
    if source.exists() {
        archive.append_path_with_name(source, archive_path)?;
    }
    Ok(())
}

fn backup_relative_path(path: &Path) -> anyhow::Result<PathBuf> {
    let mut components = path.components();
    let Some(first) = components.next() else {
        anyhow::bail!("empty backup path");
    };
    if first.as_os_str() != "seedpass-backup-v1" {
        anyhow::bail!("unexpected backup path: {}", path.display());
    }
    let relative = components.as_path();
    let text = relative
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("backup path is not valid UTF-8"))?;
    let allowed = text == "recipes.yaml"
        || text == "directory.yaml"
        || text == "profiles.yaml"
        || (text.starts_with("seeds/") && !text.contains(".."));
    if !allowed || relative.is_absolute() {
        anyhow::bail!("unsafe or unsupported backup path: {}", path.display());
    }
    Ok(relative.to_path_buf())
}

fn run_backup_check(paths: &WorkspacePaths, command: BackupCommand) -> anyhow::Result<()> {
    match command {
        BackupCommand::Status => {
            let workspace = load_workspace(paths)?;
            for (label, seed) in &workspace.recipes.seeds {
                println!(
                    "seed {}: {}",
                    label.as_str(),
                    paths.resolve_seed_file(&seed.path)?.display()
                );
            }
            println!("recipes: {}", paths.recipes_file().display());
        }
        BackupCommand::Test { path } => {
            let backup = WorkspacePaths::new(path);
            let workspace = load_workspace(&backup)?;
            let report = workspace.validate(Some(&backup));
            if !report.is_hard_valid() {
                anyhow::bail!("backup validation failed");
            }
            let mut master = Zeroizing::new(rpassword::prompt_password(
                "Master password for backup seed test: ",
            )?);
            for seed_record in workspace.recipes.seeds.values() {
                let envelope = read_seed_envelope(&backup.resolve_seed_file(&seed_record.path)?)?;
                if !verify_seed_fingerprint(
                    &envelope,
                    master.as_bytes(),
                    seed_record.fingerprint.as_str(),
                )? {
                    anyhow::bail!("backup seed fingerprint mismatch for {}", seed_record.path);
                }
            }
            if let Some(record) = workspace.recipes.credentials.first() {
                if let Some(version) = record.versions.first() {
                    let seed_record = workspace
                        .recipes
                        .seeds
                        .get(&version.seed)
                        .ok_or_else(|| anyhow::anyhow!("seed not found for test derivation"))?;
                    let envelope =
                        read_seed_envelope(&backup.resolve_seed_file(&seed_record.path)?)?;
                    let seed = decrypt_seed(&envelope, master.as_bytes())?;
                    let recipe = DerivationRecipeV1::from_record_version(record, version);
                    let _password = Zeroizing::new(derive_password(&seed, &recipe)?);
                }
            }
            master.zeroize();
            println!("Backup readable, decryptable, fingerprint-verified, and derivation-tested.");
        }
    }
    Ok(())
}

fn doctor_warnings(
    paths: &WorkspacePaths,
    workspace: &seedpass_storage::Workspace,
) -> anyhow::Result<Vec<String>> {
    let mut warnings = Vec::new();
    warnings.push(
        "clipboard output is unavailable in this MVP build; --clip will not fall back to stdout"
            .to_owned(),
    );

    for seed_record in workspace.recipes.seeds.values() {
        if let Ok(seed_path) = paths.resolve_seed_file(&seed_record.path) {
            if let Ok(envelope) = read_seed_envelope(&seed_path) {
                for warning in kdf_parameter_warnings(&envelope.kdf) {
                    warnings.push(format!("{}: {warning}", seed_record.path));
                }
            }
        }
    }

    let now = OffsetDateTime::now_utc();
    for record in &workspace.recipes.credentials {
        for version in &record.versions {
            if version.status == VersionStatus::Pending {
                if let Some(created_at) = &version.created_at {
                    if let Ok(created_at) = OffsetDateTime::parse(created_at, &Rfc3339) {
                        if now - created_at > time::Duration::days(14) {
                            warnings.push(format!(
                                "pending rotation older than 14 days: {} version {}",
                                record.alias.as_str(),
                                version.number
                            ));
                        }
                    }
                }
            }
        }
    }

    if let Some(directory) = &workspace.directory {
        let mut seen = BTreeSet::new();
        for entry in directory.entries.values() {
            if let (Some(service), Some(username)) = (&entry.service, &entry.username) {
                let key = (service.clone(), username.clone());
                if !seen.insert(key.clone()) {
                    warnings.push(format!(
                        "duplicate service+username metadata: {} {}",
                        key.0, key.1
                    ));
                }
            } else if entry.username.is_none() {
                warnings.push(format!(
                    "directory entry missing username: {}",
                    entry.alias.as_str()
                ));
            }
        }
    }

    Ok(warnings)
}

fn confirm_prompt(message: &str) -> anyhow::Result<()> {
    print!("{message} Type YES to continue: ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if answer.trim() == "YES" {
        Ok(())
    } else {
        anyhow::bail!("operation cancelled")
    }
}

fn save_workspace(
    paths: &WorkspacePaths,
    workspace: &seedpass_storage::Workspace,
) -> anyhow::Result<()> {
    save_yaml_atomic(&paths.recipes_file(), &workspace.recipes)?;
    if let Some(directory) = &workspace.directory {
        save_yaml_atomic(&paths.directory_file(), directory)?;
    }
    if let Some(profiles) = &workspace.profiles {
        save_yaml_atomic(&paths.profiles_file(), profiles)?;
    }
    Ok(())
}

fn load_profiles_or_default(paths: &WorkspacePaths) -> anyhow::Result<ProfilesFile> {
    Ok(load_workspace(paths)?.profiles.unwrap_or_else(|| {
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "web-default".to_owned(),
            ProfileTemplate {
                profile: default_profile(),
            },
        );
        ProfilesFile {
            format: "seedpass-profiles-v1".to_owned(),
            profiles,
        }
    }))
}

fn default_profile() -> ProfileSnapshot {
    ProfileSnapshot::Password {
        length: 24,
        min_uppercase: 1,
        min_lowercase: 1,
        min_digits: 1,
        min_symbols: 1,
        symbols: "-_.!@#$%^&*".to_owned(),
    }
}

fn find_record<'a>(recipes: &'a RecipesFile, alias: &str) -> anyhow::Result<&'a CredentialRecord> {
    recipes
        .credentials
        .iter()
        .find(|record| record.alias.as_str() == alias)
        .ok_or_else(|| anyhow::anyhow!("account not found: {alias}"))
}

fn find_record_mut<'a>(
    recipes: &'a mut RecipesFile,
    alias: &str,
) -> anyhow::Result<&'a mut CredentialRecord> {
    recipes
        .credentials
        .iter_mut()
        .find(|record| record.alias.as_str() == alias)
        .ok_or_else(|| anyhow::anyhow!("account not found: {alias}"))
}

fn select_version<'a>(
    recipes: &'a RecipesFile,
    args: &PassArgs,
) -> anyhow::Result<(&'a CredentialRecord, &'a CredentialVersion)> {
    let record = find_record(recipes, &args.alias)?;
    if let Some(number) = args.version {
        let version = record
            .versions
            .iter()
            .find(|version| version.number == number)
            .ok_or_else(|| anyhow::anyhow!("version not found: {number}"))?;
        if version.status == VersionStatus::Retired && args.allow_retired {
            return Ok((record, version));
        }
        anyhow::bail!(
            "explicit version derivation is only allowed with --allow-retired for retired versions"
        );
    }
    if args.pending {
        let version = record
            .versions
            .iter()
            .find(|version| version.status == VersionStatus::Pending)
            .ok_or_else(|| anyhow::anyhow!("no pending version for {}", args.alias))?;
        return Ok((record, version));
    }
    record
        .versions
        .iter()
        .find(|version| version.status == VersionStatus::Active)
        .map(|version| (record, version))
        .ok_or_else(|| {
            anyhow::anyhow!("no active credential; use --pending or confirm pending version")
        })
}

fn confirm_pending(recipes: &mut RecipesFile, alias: &str) -> anyhow::Result<()> {
    let record = find_record_mut(recipes, alias)?;
    let pending_number = record
        .versions
        .iter()
        .find(|version| version.status == VersionStatus::Pending)
        .map(|version| version.number)
        .ok_or_else(|| anyhow::anyhow!("no pending version for {alias}"))?;
    for version in &mut record.versions {
        if version.number == pending_number {
            version.status = VersionStatus::Active;
            version.confirmed_at = Some(now_rfc3339());
        } else if version.status == VersionStatus::Active {
            version.status = VersionStatus::Retired;
            version.retired_at = Some(now_rfc3339());
        }
    }
    Ok(())
}

fn read_seed_envelope(path: &PathBuf) -> anyhow::Result<SeedEnvelopeV1> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("RFC3339 formatting succeeds")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
