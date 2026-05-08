use seedpass_codec::canonical_recipe_v1;
use seedpass_core::{
    CredentialUid, DerivationRecipeV1, ProfileSnapshot, PublicSalt, Purpose, Scheme,
    RECIPE_FORMAT_V1,
};
use seedpass_crypto::{
    decrypt_seed, seed_fingerprint_display, seed_fingerprint_raw, RootSeed, SeedEnvelopeV1,
};
use seedpass_derive::{derive_credential_key, derive_password, recipe_hash};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct MainVector {
    canonical_recipe_json: String,
    canonical_recipe_sha256: String,
    credential_key_hex: String,
    master_password: String,
    password: String,
    root_seed_hex: String,
    seed_envelope: SeedEnvelopeV1,
    seed_fingerprint_display: String,
    seed_fingerprint_raw_hex: String,
}

#[derive(Debug, Deserialize)]
struct MetadataVector {
    expected_canonical_recipe_json: String,
    excluded_fields: Vec<String>,
}

fn main_vector() -> MainVector {
    let json = std::fs::read_to_string("../../tests/vectors/v1-draft-001.json")
        .or_else(|_| std::fs::read_to_string("tests/vectors/v1-draft-001.json"))
        .expect("main vector is readable");
    serde_json::from_str(&json).expect("main vector parses")
}

fn metadata_vector() -> MetadataVector {
    let json = std::fs::read_to_string("../../tests/vectors/metadata-invariance-v1-draft-001.json")
        .or_else(|_| std::fs::read_to_string("tests/vectors/metadata-invariance-v1-draft-001.json"))
        .expect("metadata vector is readable");
    serde_json::from_str(&json).expect("metadata vector parses")
}

fn recipe() -> DerivationRecipeV1 {
    DerivationRecipeV1 {
        format: RECIPE_FORMAT_V1.to_owned(),
        scheme: Scheme::from("seedpass-v1"),
        credential_uid: CredentialUid::from("cred_01HX8K8M9G6TD9CZQK7BW6MQD2"),
        purpose: Purpose::WebPassword,
        version: 1,
        public_salt: PublicSalt::from("EBESExQVFhcYGRobHB0eHw"),
        profile_snapshot: ProfileSnapshot::Password {
            length: 24,
            min_uppercase: 1,
            min_lowercase: 1,
            min_digits: 1,
            min_symbols: 1,
            symbols: "-_.!@#$%^&*".to_owned(),
        },
    }
}

#[test]
fn consumes_main_v1_draft_vector() {
    let vector = main_vector();
    let recipe = recipe();
    let canonical = canonical_recipe_v1(&recipe).expect("canonical recipe");
    assert_eq!(canonical, vector.canonical_recipe_json.as_bytes());
    assert_eq!(
        hex(&recipe_hash(&recipe).expect("recipe hash")),
        vector.canonical_recipe_sha256
    );

    let root_seed = RootSeed::new(decode_hex_32(&vector.root_seed_hex));
    assert_eq!(
        hex(&derive_credential_key(&root_seed, &recipe).expect("credential key")),
        vector.credential_key_hex
    );
    assert_eq!(
        derive_password(&root_seed, &recipe).expect("password"),
        vector.password
    );

    let decrypted = decrypt_seed(&vector.seed_envelope, vector.master_password.as_bytes())
        .expect("seed envelope decrypts");
    assert_eq!(decrypted.as_bytes(), root_seed.as_bytes());
    assert_eq!(
        hex(&seed_fingerprint_raw(&root_seed).expect("fingerprint raw")),
        vector.seed_fingerprint_raw_hex
    );
    assert_eq!(
        seed_fingerprint_display(&root_seed).expect("fingerprint display"),
        vector.seed_fingerprint_display
    );
}

#[test]
fn consumes_metadata_invariance_vector() {
    let vector = metadata_vector();
    let canonical = String::from_utf8(canonical_recipe_v1(&recipe()).expect("canonical recipe"))
        .expect("canonical utf8");
    assert_eq!(canonical, vector.expected_canonical_recipe_json);
    for excluded in vector.excluded_fields {
        assert!(
            !canonical.contains(&excluded),
            "canonical recipe unexpectedly contains excluded field marker: {excluded}"
        );
    }
}

#[test]
fn invalid_manifest_vectors_are_rejected_by_core_validator() {
    for path in [
        "tests/vectors/invalid/duplicate-public-salt.yaml",
        "tests/vectors/invalid/two-active-versions.yaml",
        "tests/vectors/invalid/unknown-scheme.yaml",
    ] {
        let yaml = std::fs::read_to_string(path)
            .or_else(|_| std::fs::read_to_string(format!("../../{path}")))
            .expect("invalid vector readable");
        let recipes: seedpass_core::RecipesFile = serde_yaml::from_str(&yaml).expect("yaml parses");
        assert!(
            !seedpass_core::Validate::is_valid(&recipes),
            "{path} should be invalid"
        );
    }
}

fn decode_hex_32(hex: &str) -> [u8; 32] {
    hex_to_vec(hex).try_into().expect("32 bytes")
}

fn hex_to_vec(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let s = core::str::from_utf8(chunk).expect("hex utf8");
            u8::from_str_radix(s, 16).expect("hex byte")
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
