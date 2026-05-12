# RECIPES

Status: `seedpass-v1-draft`.

`recipes.yaml` is derivation-critical public state. It contains no generated credentials, but losing it may prevent recovery.

Duplicate YAML keys are hard errors.

## Seed records

```yaml
seeds:
  personal:
    fingerprint: SPSEED-XXXX-XXXX-XXXX-XXXX
    path: seeds/personal.seed
```

The seed label selects which encrypted seed file to open. The label, path, and fingerprint are not derivation inputs.

Before derivation, the selected seed file must decrypt to the declared fingerprint.

## Credential records

```yaml
credentials:
  - uid: cred_01HX8K8M9G6TD9CZQK7BW6MQD2
    alias: github-personal
    purpose: web-password
    versions:
      - number: 1
        status: pending
        seed: personal
        scheme: seedpass-v1
        public_salt: EBESExQVFhcYGRobHB0eHw
        profile_snapshot:
          kind: password
          length: 24
          min_uppercase: 1
          min_lowercase: 1
          min_digits: 1
          min_symbols: 1
          symbols: "-_.!@#$%^&*"
        created_at: "2026-05-10T00:00:00Z"
```

## Identity

- `uid` is immutable durable identity.
- `alias` is a mutable local handle.
- Durable relationships use UID, not alias.

## Public salt

Public salts are 128-bit random bytes encoded base64url without padding. Duplicate public salts are rejected globally within `recipes.yaml`.

## Lifecycle statuses

Allowed transitions:

| Current | Allowed next states |
| --- | --- |
| pending | active, failed |
| active | retired, revoked |
| retired | revoked |
| failed | terminal, or deleted by maintenance |
| revoked | terminal |

Invariants:

- At most one active version per credential.
- At most one pending version per credential.
- Zero active versions is valid only if there is one pending version.
- Pending version number is greater than every previous version.
- Confirming pending atomically makes it active and retires the old active.
- `rotate --abort` records pending as failed and does not affect active.

## Derivability

- `active`: default.
- `pending`: only with `--pending`.
- `retired`: only with `--version N --allow-retired`.
- `failed`: not derivable in MVP.
- `revoked`: not derivable in MVP.

## Timestamps

Lifecycle timestamps use RFC 3339 UTC strings. They are metadata only and never derivation inputs.
