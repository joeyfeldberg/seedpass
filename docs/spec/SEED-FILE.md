# SEED-FILE

Status: `seedpass-v1-draft`.

## Root seed

A root seed is at least 32 random bytes. MVP creates 32-byte root seeds.

## Envelope JSON shape

```json
{
  "format": "seedpass-seed-v1",
  "kdf": {
    "name": "argon2id",
    "version": 19,
    "memory_kib": 262144,
    "iterations": 3,
    "parallelism": 4,
    "salt": "base64url-no-padding"
  },
  "cipher": {
    "name": "aes-256-gcm",
    "nonce": "base64url-no-padding"
  },
  "ciphertext": "base64url-no-padding"
}
```

`ciphertext` is AES-GCM ciphertext with tag appended as produced by the AEAD API.

Duplicate JSON keys are hard errors.

## Argon2id parameters

Stored fields:

- Argon2 version: `19`.
- Memory cost: `memory_kib`.
- Time cost: `iterations`.
- Parallelism: `parallelism`.
- Salt: 16 random bytes minimum, base64url without padding.
- Output key length: 32 bytes.

Current recommended creation parameters:

```text
memory_kib = 262144
iterations = 3
parallelism = 4
salt_len = 16
key_len = 32
```

Draft test vectors may use weaker parameters to keep tests fast.

`doctor` behavior:

- Below minimum for new seeds: reject.
- Below minimum but decryptable existing seed: warning.
- Below current recommendation: warning and suggest `seedpass seed rewrap`.

## AEAD

Cipher: AES-256-GCM.

AAD is canonical JSON for the protected header, excluding `ciphertext`:

```json
{
  "format": "seedpass-seed-v1",
  "kdf": { ... },
  "cipher": { ... }
}
```

The exact bytes are canonicalized using the same JSON byte rules: sorted keys and no insignificant whitespace.

## Rewrap

`seedpass seed rewrap <seed>`:

1. Decrypts the old envelope with the old master password.
2. Re-encrypts the same root seed with the new master password.
3. Generates a new KDF salt and AEAD nonce.
4. Verifies the seed fingerprint is unchanged.
5. Writes atomically.

Derived credentials are unchanged.

## Vector

See `tests/vectors/v1-draft-001.json`.
