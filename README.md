# Seedpass

Seedpass is a local password tool that derives reproducible credentials from an encrypted seed and public recipe files. It does not store generated passwords.

## Install

```bash
cargo install --path crates/seedpass-cli --force
```

## Quick start

```bash
seedpass init
seedpass add github --service github.com --username alice@example.com
seedpass get github --pending --show
seedpass confirm github
seedpass get github --show
seedpass backup --out ~/seedpass-backup.tar
```

## How it works

Seedpass needs three things to reproduce a password:

```text
encrypted seed + master password + recipe
```

The master password unlocks the seed. The seed and recipe derive the credential. The master password is not used directly as the password source, so you can change it later without changing site passwords.

Recipes contain public derivation data such as credential IDs, salts, versions, and password rule snapshots. They do not contain generated passwords, but they are required for recovery.

## Everyday commands

```bash
seedpass add <name>       # add a login
seedpass get <name>       # get a password; use --show for terminal output
seedpass confirm <name>   # mark a pending password as accepted
seedpass rotate <name>    # create a pending replacement
seedpass backup --out <file>
seedpass restore <file>
seedpass status           # show recovery files
seedpass doctor           # check for problems
```

## Recovery

Create a backup archive:

```bash
seedpass backup --out ~/seedpass-backup.tar
```

Restore it later with:

```bash
seedpass restore ~/seedpass-backup.tar
```

The backup contains:

```text
recipes.yaml
directory.yaml
profiles.yaml
seeds/personal.seed
```

You also need your master password. Without `recipes.yaml`, many credentials may not be recoverable even if you still have the seed.

## Development

```bash
cargo fmt --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```
