# CANONICALIZATION

Status: `seedpass-v1-draft`.

Canonicalization is a security boundary. Implementations must produce the exact bytes in `tests/vectors/`.

## Canonical recipe format

Seedpass v1 uses canonical JSON over a closed derivation struct. Do not canonicalize arbitrary user YAML.

Rules:

- UTF-8 output.
- Object keys sorted lexicographically by Unicode scalar value.
- No insignificant whitespace.
- No `null` values.
- No floats.
- Integers are decimal without leading zeroes.
- Arrays preserve order.
- Binary fields use base64url without padding.
- Derivation-critical strings are ASCII-only for MVP.
- Unknown fields in derivation-critical records are hard errors.

## CanonicalRecipeV1 fields

The object contains exactly:

```text
credential_uid
format
profile_snapshot
public_salt
purpose
scheme
version
```

`profile_snapshot` for password credentials contains exactly:

```text
kind
length
min_digits
min_lowercase
min_symbols
min_uppercase
symbols
```

## Explicit exclusions

In `seedpass-v1`, these are never canonical recipe fields and never derivation inputs:

```text
alias
service
username
tags
notes
timestamps
paths
seed labels
seed paths
seed fingerprints
profile template names
```

The root seed itself is the secret input. Changing a version to a different seed changes output because the root seed changes, not because seed metadata is hashed.

## Example

See `tests/vectors/v1-draft-001.json` field `canonical_recipe_json`.
