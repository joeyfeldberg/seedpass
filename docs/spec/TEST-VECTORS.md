# TEST-VECTORS

Status: `seedpass-v1-draft`.

Vectors are the compatibility contract. Before 1.0 they may change; after 1.0 `seedpass-v1` output must not change.

## Current vectors

- `tests/vectors/v1-draft-001.json`

This vector includes:

- fixed root seed.
- fixed master password for seed-envelope testing.
- canonical recipe JSON bytes.
- recipe SHA-256.
- credential key.
- deterministic password output.
- seed fingerprint.
- seed envelope with deterministic test-only Argon2id/AES-GCM inputs.

## Warning

Draft vectors are for implementation alignment only. They are not production examples. Some KDF parameters are intentionally weak to keep tests fast.
