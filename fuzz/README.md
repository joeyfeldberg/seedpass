# Fuzzing plan

Seedpass fuzzing targets to wire into `cargo fuzz` before public release:

- strict YAML duplicate-key preflight (`seedpass-codec`).
- typed recipe/profile manifest loading (`seedpass-storage` + `seedpass-core`).
- canonical recipe encoder consistency against accepted derivation structs.
- password profile validation and derivation rejection paths.

Current MVP hardening uses unit/property tests and vector tests. Full long-running fuzz campaigns are intended for CI/release hardening.
