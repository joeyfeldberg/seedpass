# CLI-BEHAVIOR

Status: `seedpass-v1-draft`.

## Secret output

`seedpass pass <alias>` without an explicit output channel emits no credential and exits with guidance.

Allowed output channels:

```bash
seedpass pass <alias> --show
seedpass pass <alias> --clip
```

`--clip` must not silently fall back to stdout. Clipboard clearing is best-effort only and must not be described as guaranteed.

No CLI command may print secrets in error messages.

## Validation commands

```bash
seedpass validate
seedpass doctor
```

`validate` is machine-ish and returns nonzero on hard errors. `doctor` is human-ish and reports hard errors plus warnings.

`pass` refuses hard validation errors and may continue with warnings unless `--strict` is passed.

## Friendly MVP commands

These are the preferred user-facing commands:

```bash
seedpass init
seedpass add <alias>
seedpass get <alias> --show|--clip
seedpass confirm <alias>
seedpass rename <old> <new>
seedpass rotate <alias>
seedpass rotate <alias> --confirm
seedpass rotate <alias> --abort
seedpass backup --out <archive.tar>
seedpass restore <archive.tar>
seedpass status
seedpass doctor
seedpass explain <alias>
```

Advanced/namespaced forms remain available:

```bash
seedpass profile add <name>
seedpass profile list
seedpass profile show <name>
seedpass account add <alias>
seedpass account rename <old> <new>
seedpass account confirm <alias>
seedpass pass <alias> --show|--clip
seedpass validate
seedpass backup-check status
seedpass backup-check test --path <backup>
seedpass seed fingerprint <seed>
seedpass seed verify <seed>
seedpass seed rewrap <seed>
```

## No active credential behavior

If a credential has zero active versions and one pending version:

```text
seedpass pass <alias>
```

fails with guidance to use `--pending` or confirm the pending version.

## Explain

`explain` never shows generated credentials. It may show:

- UID.
- alias.
- service/username metadata.
- version status.
- seed label and fingerprint.
- canonical recipe hash.
- profile snapshot hash.
