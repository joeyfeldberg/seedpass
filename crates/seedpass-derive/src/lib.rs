//! Deterministic credential derivation.
//!
//! This crate turns a root seed plus canonical recipe into password/key output.
//! It must never persist generated credentials.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use seedpass_codec::canonical_recipe_v1;
use seedpass_core::{DerivationRecipeV1, Diagnostic, ProfileSnapshot, Severity};
use seedpass_crypto::{RootSeed, CREDENTIAL_KEY_INFO_V1, STREAM_DOMAIN_V1};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";

#[derive(Debug, Error)]
pub enum DeriveError {
    #[error("canonicalization failed: {0}")]
    Canonicalization(#[from] seedpass_codec::CodecError),
    #[error("HKDF expansion failed")]
    HkdfFailed,
    #[error("HMAC initialization failed")]
    HmacFailed,
    #[error("invalid password profile: {0}")]
    InvalidProfile(String),
}

pub fn recipe_hash(recipe: &DerivationRecipeV1) -> Result<[u8; 32], DeriveError> {
    let canonical = canonical_recipe_v1(recipe)?;
    Ok(Sha256::digest(canonical).into())
}

pub fn derive_credential_key(
    root_seed: &RootSeed,
    recipe: &DerivationRecipeV1,
) -> Result<[u8; 32], DeriveError> {
    let hash = recipe_hash(recipe)?;
    let hk = Hkdf::<Sha256>::new(Some(&hash), root_seed.as_bytes());
    let mut key = [0_u8; 32];
    hk.expand(CREDENTIAL_KEY_INFO_V1.as_bytes(), &mut key)
        .map_err(|_| DeriveError::HkdfFailed)?;
    Ok(key)
}

pub fn derive_password(
    root_seed: &RootSeed,
    recipe: &DerivationRecipeV1,
) -> Result<String, DeriveError> {
    let ProfileSnapshot::Password {
        length,
        min_uppercase,
        min_lowercase,
        min_digits,
        min_symbols,
        symbols,
    } = &recipe.profile_snapshot;

    reject_invalid_profile(&recipe.profile_snapshot)?;

    let mut credential_key = derive_credential_key(root_seed, recipe)?;
    let mut stream = ByteStream::new(&credential_key)?;

    let mut chars = Vec::with_capacity(usize::from(*length));
    draw_required(&mut chars, &mut stream, UPPERCASE, *min_uppercase)?;
    draw_required(&mut chars, &mut stream, LOWERCASE, *min_lowercase)?;
    draw_required(&mut chars, &mut stream, DIGITS, *min_digits)?;
    draw_required(&mut chars, &mut stream, symbols, *min_symbols)?;

    let union = format!("{LOWERCASE}{UPPERCASE}{DIGITS}{symbols}");
    while chars.len() < usize::from(*length) {
        chars.push(draw_char(&mut stream, &union)?);
    }

    for i in (1..chars.len()).rev() {
        let j = stream.draw_int(i + 1)?;
        chars.swap(i, j);
    }

    credential_key.zeroize();
    Ok(chars.into_iter().collect())
}

fn reject_invalid_profile(profile: &ProfileSnapshot) -> Result<(), DeriveError> {
    let hard_errors = profile
        .validate_profile()
        .into_iter()
        .filter(|diagnostic| diagnostic.severity == Severity::HardError)
        .collect::<Vec<Diagnostic>>();
    if hard_errors.is_empty() {
        Ok(())
    } else {
        Err(DeriveError::InvalidProfile(
            hard_errors
                .into_iter()
                .map(|diagnostic| diagnostic.message)
                .collect::<Vec<_>>()
                .join("; "),
        ))
    }
}

fn draw_required(
    chars: &mut Vec<char>,
    stream: &mut ByteStream,
    class: &str,
    count: u16,
) -> Result<(), DeriveError> {
    for _ in 0..count {
        chars.push(draw_char(stream, class)?);
    }
    Ok(())
}

fn draw_char(stream: &mut ByteStream, class: &str) -> Result<char, DeriveError> {
    let index = stream.draw_int(class.len())?;
    Ok(class
        .as_bytes()
        .get(index)
        .copied()
        .expect("draw_int returns in-bounds index") as char)
}

struct ByteStream {
    key: [u8; 32],
    block_index: u64,
    block: [u8; 32],
    offset: usize,
}

impl ByteStream {
    fn new(key: &[u8; 32]) -> Result<Self, DeriveError> {
        let mut stream = Self {
            key: *key,
            block_index: 0,
            block: [0_u8; 32],
            offset: 32,
        };
        stream.refill()?;
        Ok(stream)
    }

    fn draw_int(&mut self, n: usize) -> Result<usize, DeriveError> {
        debug_assert!(n > 0 && n <= 256);
        let limit = (256 / n) * n;
        loop {
            let byte = usize::from(self.next_byte()?);
            if byte < limit {
                return Ok(byte % n);
            }
        }
    }

    fn next_byte(&mut self) -> Result<u8, DeriveError> {
        if self.offset >= self.block.len() {
            self.refill()?;
        }
        let byte = self.block[self.offset];
        self.offset += 1;
        Ok(byte)
    }

    fn refill(&mut self) -> Result<(), DeriveError> {
        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|_| DeriveError::HmacFailed)?;
        mac.update(STREAM_DOMAIN_V1.as_bytes());
        mac.update(&self.block_index.to_be_bytes());
        self.block = mac.finalize().into_bytes().into();
        self.offset = 0;
        self.block_index += 1;
        Ok(())
    }
}

impl Drop for ByteStream {
    fn drop(&mut self) {
        self.key.zeroize();
        self.block.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use seedpass_core::{
        CredentialUid, ProfileSnapshot, PublicSalt, Purpose, Scheme, RECIPE_FORMAT_V1,
    };
    use seedpass_crypto::RootSeed;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Vector {
        canonical_recipe_sha256: String,
        credential_key_hex: String,
        password: String,
        root_seed_hex: String,
    }

    fn vector() -> Vector {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/vectors/v1-draft-001.json"
        );
        let json = std::fs::read_to_string(path).expect("vector is readable");
        serde_json::from_str(&json).expect("vector parses")
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

    fn root_seed() -> RootSeed {
        RootSeed::new(decode_hex_32(&vector().root_seed_hex))
    }

    #[test]
    fn recipe_hash_matches_vector() {
        assert_eq!(
            hex(&recipe_hash(&recipe()).expect("hash")),
            vector().canonical_recipe_sha256
        );
    }

    #[test]
    fn credential_key_matches_vector() {
        assert_eq!(
            hex(&derive_credential_key(&root_seed(), &recipe()).expect("key")),
            vector().credential_key_hex
        );
    }

    #[test]
    fn password_matches_vector() {
        assert_eq!(
            derive_password(&root_seed(), &recipe()).expect("password"),
            vector().password
        );
    }

    #[test]
    fn no_symbol_profile_is_supported() {
        let mut recipe = recipe();
        recipe.profile_snapshot = ProfileSnapshot::Password {
            length: 16,
            min_uppercase: 1,
            min_lowercase: 1,
            min_digits: 1,
            min_symbols: 0,
            symbols: String::new(),
        };
        let original = crate::tests::recipe();
        let password = derive_password(&root_seed(), &original).expect("original still works");
        assert_eq!(password.len(), 24);
        let password = derive_password(&root_seed(), &recipe).expect("no-symbol profile works");
        assert_eq!(password.len(), 16);
        assert!(password.chars().any(|ch| ch.is_ascii_uppercase()));
        assert!(password.chars().any(|ch| ch.is_ascii_lowercase()));
        assert!(password.chars().any(|ch| ch.is_ascii_digit()));
    }

    #[test]
    fn minimums_equal_length_is_supported() {
        let mut recipe = recipe();
        recipe.profile_snapshot = ProfileSnapshot::Password {
            length: 4,
            min_uppercase: 1,
            min_lowercase: 1,
            min_digits: 1,
            min_symbols: 1,
            symbols: "!".to_owned(),
        };
        assert!(derive_password(&root_seed(), &recipe).is_err());

        recipe.profile_snapshot = ProfileSnapshot::Password {
            length: 8,
            min_uppercase: 2,
            min_lowercase: 2,
            min_digits: 2,
            min_symbols: 2,
            symbols: "!".to_owned(),
        };
        let password = derive_password(&root_seed(), &recipe).expect("valid exact minimums");
        assert_eq!(password.len(), 8);
    }

    #[test]
    fn draw_int_rejects_modulo_bias_bytes() {
        let mut stream = ByteStream {
            key: [0_u8; 32],
            block_index: 0,
            block: [0_u8; 32],
            offset: 0,
        };
        stream.block[0] = 255;
        stream.block[1] = 5;
        assert_eq!(stream.draw_int(10).expect("draw"), 5);
    }

    #[test]
    fn impossible_profile_is_rejected() {
        let mut recipe = recipe();
        recipe.profile_snapshot = ProfileSnapshot::Password {
            length: 8,
            min_uppercase: 8,
            min_lowercase: 1,
            min_digits: 0,
            min_symbols: 0,
            symbols: String::new(),
        };
        assert!(derive_password(&root_seed(), &recipe).is_err());
    }

    #[test]
    fn duplicate_symbols_are_rejected() {
        let mut recipe = recipe();
        recipe.profile_snapshot = ProfileSnapshot::Password {
            length: 12,
            min_uppercase: 1,
            min_lowercase: 1,
            min_digits: 1,
            min_symbols: 1,
            symbols: "!!".to_owned(),
        };
        assert!(derive_password(&root_seed(), &recipe).is_err());
    }

    #[test]
    fn whitespace_symbols_are_rejected() {
        let mut recipe = recipe();
        recipe.profile_snapshot = ProfileSnapshot::Password {
            length: 12,
            min_uppercase: 1,
            min_lowercase: 1,
            min_digits: 1,
            min_symbols: 1,
            symbols: "! ".to_owned(),
        };
        assert!(derive_password(&root_seed(), &recipe).is_err());
    }

    proptest! {
        #[test]
        fn generated_password_has_requested_length(length in 8_u16..64) {
            let mut recipe = recipe();
            recipe.profile_snapshot = ProfileSnapshot::Password {
                length,
                min_uppercase: 1,
                min_lowercase: 1,
                min_digits: 1,
                min_symbols: 1,
                symbols: "!@#".to_owned(),
            };
            let password = derive_password(&root_seed(), &recipe).expect("valid profile derives");
            prop_assert_eq!(password.len(), usize::from(length));
            prop_assert!(password.chars().any(|ch| ch.is_ascii_uppercase()));
            prop_assert!(password.chars().any(|ch| ch.is_ascii_lowercase()));
            prop_assert!(password.chars().any(|ch| ch.is_ascii_digit()));
            prop_assert!(password.chars().any(|ch| "!@#".contains(ch)));
        }
    }

    #[test]
    fn repeated_runs_are_stable() {
        let first = derive_password(&root_seed(), &recipe()).expect("first");
        let second = derive_password(&root_seed(), &recipe()).expect("second");
        assert_eq!(first, second);
    }

    fn decode_hex_32(hex: &str) -> [u8; 32] {
        let bytes = hex_to_vec(hex);
        bytes.try_into().expect("32 bytes")
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
}
