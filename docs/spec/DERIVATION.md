# DERIVATION

Status: `seedpass-v1-draft`.

## Recipe hash

```text
recipe_hash = SHA-256(canonical_recipe_bytes)
```

## Credential key

```text
credential_key = HKDF-SHA-256(
  ikm = root_seed,
  salt = recipe_hash,
  info = UTF-8("seedpass-v1/credential-key"),
  length = 32
)
```

## Deterministic byte stream

```text
stream_block_i = HMAC-SHA-256(
  key = credential_key,
  message = UTF-8("seedpass-v1/stream") || uint64_be(i)
)

i starts at 0. Blocks are concatenated in increasing i.
```

## Seed fingerprint

```text
fingerprint_raw = HKDF-SHA-256(
  ikm = root_seed,
  salt = empty,
  info = UTF-8("seedpass-v1/seed-fingerprint"),
  length = 16
)
```

Display encoding:

```text
SPSEED-<base32-without-padding-grouped-in-4-char-groups>
```

The fingerprint is public and is used to verify that the selected seed file matches the recipe seed record before derivation.

## Vectors

See `tests/vectors/v1-draft-001.json`.
