# THREAT-MODEL

Status: `seedpass-v1-draft`.

## Assets

- Root seed.
- Master password.
- Public recipes.
- Directory metadata.
- Generated credentials, which are ephemeral and never stored.

## Attacker has recipes only

Learns metadata and public salts/UIDs, but cannot derive credentials.

Mitigations:

- No generated credentials in recipes.
- Metadata split between recipes and directory.

## Attacker has seed file only

Can attempt offline guessing against the seed envelope.

Mitigations:

- Argon2id.
- Strong passphrase guidance.
- Rewrap for parameter upgrades.

## Attacker has master password only

Cannot derive credentials without the seed file.

## Attacker has seed + master but not recipes

Can recover root seed, but lacks random credential UIDs and public salts. Recipes remain required for reliable derivation.

## Attacker has seed + master + recipes

Can derive credentials.

Mitigations:

- Rotation workflow.
- Seed compromise workflow post-MVP.
- Backup and doctor reporting.

## Non-secret event log

Event log must never contain generated credentials, root seed material, master passwords, derived keys, or decrypted seed bytes. Recipes are authoritative if event log disagrees.
