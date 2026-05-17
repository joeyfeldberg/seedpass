# Security review notes

Status: MVP hardening pass.

## Secret handling

- `RootSeed` uses `zeroize` and redacted `Debug`.
- CLI master-password strings are wrapped in `Zeroizing` where practical.
- Generated passwords are wrapped in `Zeroizing` before explicit output.
- Seed decrypt/encrypt keys and decrypted plaintext buffers are wrapped for best-effort zeroization, including failure paths where practical.
- Error messages should identify state, files, or fingerprints only; they must not include master passwords, root seeds, derived keys, or generated credentials.

## Crypto crate review

Current crypto-critical crates:

- `argon2`: password KDF implementation.
- `aes-gcm`: AEAD seed encryption.
- `hkdf`, `hmac`, `sha2`: derivation and deterministic stream.
- `rand`: OS-backed random generation through crate APIs.
- `subtle`: constant-time fingerprint comparison where cheap.
- `zeroize`: best-effort memory clearing.

These are common RustCrypto/Rust ecosystem crates. Before public release, run `cargo audit` or `cargo deny` in CI and pin/review advisories.

## MVP hardening implemented

- Seed rewrap uses the same atomic, `0600` seed writer as initial seed creation.
- Workspace config, seed, lock, and history directories are created with private permissions on Unix.
- Recipe seed paths are constrained to workspace-relative `seeds/...` paths and existing seed files are checked for symlink/canonicalization escape.
- Argon2 envelope parameters have upper bounds to avoid attacker-controlled memory/CPU exhaustion.
- Seed envelope ciphertext size is bounded before decryption.
- YAML loading rejects duplicate keys plus flow mappings, tabs, anchors, aliases, and merge keys in the supported Seedpass YAML subset.
- Event-log entries created by the CLI are serialized as YAML instead of interpolating untrusted strings.

## Fuzzing targets to add

- strict YAML duplicate-key preflight.
- recipe/profile manifest loaders.
- canonical recipe encoder equivalence against vectors.
- password profile validation.

## Known limitations

- Rust cannot guarantee all password `String` temporaries are never copied by allocator/runtime internals.
- Clipboard support is disabled in this MVP build rather than pretending clearing is reliable.
- Event log append is diagnostic and best-effort; recipes remain authoritative.
- Legacy/vector seed envelopes with KDF parameters below current recommendations remain readable; `doctor` warns and rewrap uses current recommended parameters.
