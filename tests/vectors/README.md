# Seedpass test vectors

Status: `seedpass-v1-draft`.

Vectors are the compatibility contract. Before 1.0 they may change; after 1.0 `seedpass-v1` output must not change.

## Files

- `v1-draft-001.json`
  - fixed root seed.
  - fixed master password for seed-envelope testing.
  - canonical recipe JSON bytes.
  - recipe SHA-256.
  - credential key.
  - deterministic password output.
  - seed fingerprint.
  - seed envelope with deterministic test-only Argon2id/AES-GCM inputs.
- `metadata-invariance-v1-draft-001.json`
  - metadata fields that must not affect canonical recipe bytes.
- `rotation-state-machine-v1-draft-001.yaml`
  - expected lifecycle transition examples.
- `invalid/*.yaml`
  - manifests that strict validators must reject.

## How to use from another implementation

1. Read `docs/spec/*.md`.
2. Load `v1-draft-001.json`.
3. Reconstruct the canonical recipe from the specified derivation fields.
4. Assert canonical bytes exactly equal `canonical_recipe_json` as UTF-8.
5. Assert SHA-256 equals `canonical_recipe_sha256`.
6. Assert HKDF credential key equals `credential_key_hex`.
7. Assert password generation equals `password`.
8. Decrypt `seed_envelope` with `master_password` and assert `root_seed_hex`.
9. Assert seed fingerprint raw/display values.
10. Load invalid manifests and reject them with hard validation errors.

Draft vectors are not production examples. Some KDF parameters are intentionally weak to keep tests fast.
