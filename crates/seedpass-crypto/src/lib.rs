//! Seedpass cryptographic primitives.
//!
//! This crate owns seed envelopes, Argon2id/AES-GCM, fingerprints, HKDF, and
//! seed rewrap primitives. It should not know about CLI or storage.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use data_encoding::BASE32_NOPAD;
use hkdf::Hkdf;
use rand::random;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const SEED_ENVELOPE_FORMAT_V1: &str = "seedpass-seed-v1";
pub const SEED_FINGERPRINT_INFO_V1: &str = "seedpass-v1/seed-fingerprint";
pub const CREDENTIAL_KEY_INFO_V1: &str = "seedpass-v1/credential-key";
pub const STREAM_DOMAIN_V1: &str = "seedpass-v1/stream";
pub const ROOT_SEED_LEN: usize = 32;
pub const SEED_FINGERPRINT_LEN: usize = 16;
pub const ARGON2_KEY_LEN: usize = 32;
pub const ARGON2_VERSION: u32 = 19;
pub const AES_GCM_NONCE_LEN: usize = 12;
pub const ARGON2_MIN_MEMORY_KIB: u32 = 19 * 1024;
pub const ARGON2_MIN_ITERATIONS: u32 = 2;
pub const ARGON2_MIN_PARALLELISM: u32 = 1;
pub const ARGON2_RECOMMENDED_MEMORY_KIB: u32 = 262_144;
pub const ARGON2_RECOMMENDED_ITERATIONS: u32 = 3;
pub const ARGON2_RECOMMENDED_PARALLELISM: u32 = 4;
pub const ARGON2_MAX_MEMORY_KIB: u32 = 1024 * 1024;
pub const ARGON2_MAX_ITERATIONS: u32 = 10;
pub const ARGON2_MAX_PARALLELISM: u32 = 16;
pub const ARGON2_MAX_SALT_LEN: usize = 64;
pub const SEED_ENVELOPE_MAX_CIPHERTEXT_LEN: usize = 1024;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("unsupported seed envelope format: {0}")]
    UnsupportedFormat(String),
    #[error("unsupported KDF: {0}")]
    UnsupportedKdf(String),
    #[error("unsupported Argon2 version: {0}")]
    UnsupportedArgon2Version(u32),
    #[error("unsupported cipher: {0}")]
    UnsupportedCipher(String),
    #[error("invalid base64url field: {0}")]
    InvalidBase64(&'static str),
    #[error("invalid length for {field}: expected {expected}, got {actual}")]
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("invalid Argon2 parameters")]
    InvalidArgon2Params,
    #[error("seed encryption failed")]
    EncryptFailed,
    #[error("seed decryption failed")]
    DecryptFailed,
    #[error("HKDF expansion failed")]
    HkdfFailed,
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootSeed([u8; ROOT_SEED_LEN]);

impl RootSeed {
    pub fn new(bytes: [u8; ROOT_SEED_LEN]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Self {
        Self(random())
    }

    pub fn as_bytes(&self) -> &[u8; ROOT_SEED_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for RootSeed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RootSeed([REDACTED])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedEnvelopeV1 {
    pub format: String,
    pub kdf: KdfParams,
    pub cipher: CipherParams,
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub name: String,
    pub version: u32,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherParams {
    pub name: String,
    pub nonce: String,
}

impl SeedEnvelopeV1 {
    pub fn protected_header_aad(&self) -> Result<Vec<u8>, CryptoError> {
        protected_header_aad(&self.format, &self.kdf, &self.cipher)
    }
}

pub fn encrypt_seed_with_params(
    root_seed: &RootSeed,
    master_password: &[u8],
    kdf: KdfParams,
    cipher: CipherParams,
) -> Result<SeedEnvelopeV1, CryptoError> {
    validate_header(SEED_ENVELOPE_FORMAT_V1, &kdf, &cipher)?;
    let key = zeroize::Zeroizing::new(derive_argon2_key(master_password, &kdf)?);
    let nonce = decode_fixed::<AES_GCM_NONCE_LEN>(&cipher.nonce, "cipher.nonce")?;
    let aad = protected_header_aad(SEED_ENVELOPE_FORMAT_V1, &kdf, &cipher)?;
    let ciphertext = Aes256Gcm::new_from_slice(key.as_slice())
        .map_err(|_| CryptoError::EncryptFailed)?
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: root_seed.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::EncryptFailed)?;

    Ok(SeedEnvelopeV1 {
        format: SEED_ENVELOPE_FORMAT_V1.to_owned(),
        kdf,
        cipher,
        ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
    })
}

pub fn encrypt_seed(
    root_seed: &RootSeed,
    master_password: &[u8],
) -> Result<SeedEnvelopeV1, CryptoError> {
    let salt: [u8; 16] = random();
    let nonce: [u8; AES_GCM_NONCE_LEN] = random();
    encrypt_seed_with_params(
        root_seed,
        master_password,
        KdfParams {
            name: "argon2id".to_owned(),
            version: ARGON2_VERSION,
            memory_kib: 262_144,
            iterations: 3,
            parallelism: 4,
            salt: URL_SAFE_NO_PAD.encode(salt),
        },
        CipherParams {
            name: "aes-256-gcm".to_owned(),
            nonce: URL_SAFE_NO_PAD.encode(nonce),
        },
    )
}

pub fn decrypt_seed(
    envelope: &SeedEnvelopeV1,
    master_password: &[u8],
) -> Result<RootSeed, CryptoError> {
    validate_header(&envelope.format, &envelope.kdf, &envelope.cipher)?;
    let key = zeroize::Zeroizing::new(derive_argon2_key(master_password, &envelope.kdf)?);
    let nonce = decode_fixed::<AES_GCM_NONCE_LEN>(&envelope.cipher.nonce, "cipher.nonce")?;
    let aad = envelope.protected_header_aad()?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(envelope.ciphertext.as_bytes())
        .map_err(|_| CryptoError::InvalidBase64("ciphertext"))?;
    if ciphertext.len() > SEED_ENVELOPE_MAX_CIPHERTEXT_LEN {
        return Err(CryptoError::InvalidLength {
            field: "ciphertext",
            expected: SEED_ENVELOPE_MAX_CIPHERTEXT_LEN,
            actual: ciphertext.len(),
        });
    }
    let plaintext = zeroize::Zeroizing::new(
        Aes256Gcm::new_from_slice(key.as_slice())
            .map_err(|_| CryptoError::DecryptFailed)?
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::DecryptFailed)?,
    );

    if plaintext.len() != ROOT_SEED_LEN {
        return Err(CryptoError::InvalidLength {
            field: "root_seed",
            expected: ROOT_SEED_LEN,
            actual: plaintext.len(),
        });
    }
    let mut seed_bytes = [0_u8; ROOT_SEED_LEN];
    seed_bytes.copy_from_slice(&plaintext);
    let seed = RootSeed::new(seed_bytes);
    seed_bytes.zeroize();
    Ok(seed)
}

pub fn rewrap_seed_with_params(
    envelope: &SeedEnvelopeV1,
    old_master_password: &[u8],
    new_master_password: &[u8],
    new_kdf: KdfParams,
    new_cipher: CipherParams,
) -> Result<SeedEnvelopeV1, CryptoError> {
    let root_seed = decrypt_seed(envelope, old_master_password)?;
    encrypt_seed_with_params(&root_seed, new_master_password, new_kdf, new_cipher)
}

pub fn seed_fingerprint_raw(
    root_seed: &RootSeed,
) -> Result<[u8; SEED_FINGERPRINT_LEN], CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(&[]), root_seed.as_bytes());
    let mut out = [0_u8; SEED_FINGERPRINT_LEN];
    hk.expand(SEED_FINGERPRINT_INFO_V1.as_bytes(), &mut out)
        .map_err(|_| CryptoError::HkdfFailed)?;
    Ok(out)
}

pub fn seed_fingerprint_display(root_seed: &RootSeed) -> Result<String, CryptoError> {
    let raw = seed_fingerprint_raw(root_seed)?;
    let encoded = BASE32_NOPAD.encode(&raw);
    let grouped = encoded
        .as_bytes()
        .chunks(4)
        .map(|chunk| core::str::from_utf8(chunk).expect("base32 is ascii"))
        .collect::<Vec<_>>()
        .join("-");
    Ok(format!("SPSEED-{grouped}"))
}

pub fn verify_seed_fingerprint(
    envelope: &SeedEnvelopeV1,
    master_password: &[u8],
    expected_fingerprint: &str,
) -> Result<bool, CryptoError> {
    let root_seed = decrypt_seed(envelope, master_password)?;
    let actual = seed_fingerprint_display(&root_seed)?;
    Ok(actual
        .as_bytes()
        .ct_eq(expected_fingerprint.as_bytes())
        .into())
}

pub fn kdf_parameter_warnings(kdf: &KdfParams) -> Vec<String> {
    let mut warnings = Vec::new();
    if kdf.memory_kib < ARGON2_MIN_MEMORY_KIB
        || kdf.iterations < ARGON2_MIN_ITERATIONS
        || kdf.parallelism < ARGON2_MIN_PARALLELISM
    {
        warnings
            .push("seed KDF parameters are below current minimums; rewrap recommended".to_owned());
    } else if kdf.memory_kib < ARGON2_RECOMMENDED_MEMORY_KIB
        || kdf.iterations < ARGON2_RECOMMENDED_ITERATIONS
        || kdf.parallelism < ARGON2_RECOMMENDED_PARALLELISM
    {
        warnings.push(
            "seed KDF parameters are below current recommendations; consider rewrap".to_owned(),
        );
    }
    warnings
}

fn validate_header(
    format: &str,
    kdf: &KdfParams,
    cipher: &CipherParams,
) -> Result<(), CryptoError> {
    if format != SEED_ENVELOPE_FORMAT_V1 {
        return Err(CryptoError::UnsupportedFormat(format.to_owned()));
    }
    if kdf.name != "argon2id" {
        return Err(CryptoError::UnsupportedKdf(kdf.name.clone()));
    }
    if kdf.version != ARGON2_VERSION {
        return Err(CryptoError::UnsupportedArgon2Version(kdf.version));
    }
    if cipher.name != "aes-256-gcm" {
        return Err(CryptoError::UnsupportedCipher(cipher.name.clone()));
    }
    decode_fixed::<AES_GCM_NONCE_LEN>(&cipher.nonce, "cipher.nonce")?;
    let salt = URL_SAFE_NO_PAD
        .decode(kdf.salt.as_bytes())
        .map_err(|_| CryptoError::InvalidBase64("kdf.salt"))?;
    if salt.len() < 16 {
        return Err(CryptoError::InvalidLength {
            field: "kdf.salt",
            expected: 16,
            actual: salt.len(),
        });
    }
    if salt.len() > ARGON2_MAX_SALT_LEN {
        return Err(CryptoError::InvalidLength {
            field: "kdf.salt",
            expected: ARGON2_MAX_SALT_LEN,
            actual: salt.len(),
        });
    }
    if kdf.memory_kib > ARGON2_MAX_MEMORY_KIB
        || kdf.iterations > ARGON2_MAX_ITERATIONS
        || kdf.parallelism > ARGON2_MAX_PARALLELISM
    {
        return Err(CryptoError::InvalidArgon2Params);
    }
    Ok(())
}

fn derive_argon2_key(master_password: &[u8], kdf: &KdfParams) -> Result<[u8; 32], CryptoError> {
    let salt = URL_SAFE_NO_PAD
        .decode(kdf.salt.as_bytes())
        .map_err(|_| CryptoError::InvalidBase64("kdf.salt"))?;
    let params = Params::new(
        kdf.memory_kib,
        kdf.iterations,
        kdf.parallelism,
        Some(ARGON2_KEY_LEN),
    )
    .map_err(|_| CryptoError::InvalidArgon2Params)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; ARGON2_KEY_LEN];
    argon2
        .hash_password_into(master_password, &salt, &mut key)
        .map_err(|_| CryptoError::InvalidArgon2Params)?;
    Ok(key)
}

fn decode_fixed<const N: usize>(value: &str, field: &'static str) -> Result<[u8; N], CryptoError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| CryptoError::InvalidBase64(field))?;
    decoded
        .try_into()
        .map_err(|decoded: Vec<u8>| CryptoError::InvalidLength {
            field,
            expected: N,
            actual: decoded.len(),
        })
}

fn protected_header_aad(
    format: &str,
    kdf: &KdfParams,
    cipher: &CipherParams,
) -> Result<Vec<u8>, CryptoError> {
    validate_ascii(format, "format")?;
    validate_ascii(&kdf.name, "kdf.name")?;
    validate_ascii(&kdf.salt, "kdf.salt")?;
    validate_ascii(&cipher.name, "cipher.name")?;
    validate_ascii(&cipher.nonce, "cipher.nonce")?;

    let aad = format!(
        "{{\"cipher\":{{\"name\":\"{}\",\"nonce\":\"{}\"}},\"format\":\"{}\",\"kdf\":{{\"iterations\":{},\"memory_kib\":{},\"name\":\"{}\",\"parallelism\":{},\"salt\":\"{}\",\"version\":{}}}}}",
        cipher.name,
        cipher.nonce,
        format,
        kdf.iterations,
        kdf.memory_kib,
        kdf.name,
        kdf.parallelism,
        kdf.salt,
        kdf.version
    );
    Ok(aad.into_bytes())
}

fn validate_ascii(value: &str, field: &'static str) -> Result<(), CryptoError> {
    if value.is_ascii() {
        Ok(())
    } else {
        Err(CryptoError::InvalidBase64(field))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Vector {
        master_password: String,
        root_seed_hex: String,
        seed_envelope: SeedEnvelopeV1,
        seed_envelope_aad_json: String,
        seed_fingerprint_display: String,
        seed_fingerprint_raw_hex: String,
    }

    fn vector() -> Vector {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/vectors/v1-draft-001.json"
        );
        let json = std::fs::read_to_string(path).expect("vector is readable");
        serde_json::from_str(&json).expect("vector parses")
    }

    fn decode_hex_32(hex: &str) -> [u8; 32] {
        let mut out = [0_u8; 32];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let s = core::str::from_utf8(chunk).expect("hex utf8");
            out[i] = u8::from_str_radix(s, 16).expect("hex byte");
        }
        out
    }

    #[test]
    fn protected_header_aad_matches_vector() {
        let vector = vector();
        assert_eq!(
            String::from_utf8(vector.seed_envelope.protected_header_aad().expect("aad"))
                .expect("utf8"),
            vector.seed_envelope_aad_json
        );
    }

    #[test]
    fn decrypts_seed_envelope_vector() {
        let vector = vector();
        let seed = decrypt_seed(&vector.seed_envelope, vector.master_password.as_bytes())
            .expect("decrypts");
        assert_eq!(seed.as_bytes(), &decode_hex_32(&vector.root_seed_hex));
    }

    #[test]
    fn encrypts_seed_envelope_vector_with_deterministic_params() {
        let vector = vector();
        let seed = RootSeed::new(decode_hex_32(&vector.root_seed_hex));
        let envelope = encrypt_seed_with_params(
            &seed,
            vector.master_password.as_bytes(),
            vector.seed_envelope.kdf.clone(),
            vector.seed_envelope.cipher.clone(),
        )
        .expect("encrypts");
        assert_eq!(envelope, vector.seed_envelope);
    }

    #[test]
    fn seed_fingerprint_matches_vector() {
        let vector = vector();
        let seed = RootSeed::new(decode_hex_32(&vector.root_seed_hex));
        assert_eq!(
            seed_fingerprint_display(&seed).expect("fingerprint"),
            vector.seed_fingerprint_display
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(seed_fingerprint_raw(&seed).expect("raw")),
            URL_SAFE_NO_PAD.encode(hex_to_vec(&vector.seed_fingerprint_raw_hex).expect("raw hex"))
        );
    }

    #[test]
    fn wrong_password_fails() {
        let vector = vector();
        assert!(decrypt_seed(&vector.seed_envelope, b"wrong password").is_err());
    }

    #[test]
    fn tampered_header_fails() {
        let vector = vector();
        let mut envelope = vector.seed_envelope;
        envelope.kdf.iterations += 1;
        assert!(decrypt_seed(&envelope, vector.master_password.as_bytes()).is_err());
    }

    #[test]
    fn excessive_argon2_params_are_rejected_before_hashing() {
        let vector = vector();
        let mut envelope = vector.seed_envelope;
        envelope.kdf.memory_kib = ARGON2_MAX_MEMORY_KIB + 1;
        assert!(matches!(
            decrypt_seed(&envelope, vector.master_password.as_bytes()),
            Err(CryptoError::InvalidArgon2Params)
        ));
    }

    #[test]
    fn wrong_seed_fingerprint_is_detected() {
        let vector = vector();
        assert!(!verify_seed_fingerprint(
            &vector.seed_envelope,
            vector.master_password.as_bytes(),
            "SPSEED-AAAA-AAAA-AAAA-AAAA"
        )
        .expect("verify runs"));
    }

    #[test]
    fn rewrap_changes_envelope_but_not_fingerprint() {
        let vector = vector();
        let old_fingerprint = verify_seed_fingerprint(
            &vector.seed_envelope,
            vector.master_password.as_bytes(),
            &vector.seed_fingerprint_display,
        )
        .expect("verify old");
        assert!(old_fingerprint);

        let new_kdf = KdfParams {
            name: "argon2id".to_owned(),
            version: ARGON2_VERSION,
            memory_kib: 8192,
            iterations: 2,
            parallelism: 1,
            salt: URL_SAFE_NO_PAD.encode([99_u8; 16]),
        };
        let new_cipher = CipherParams {
            name: "aes-256-gcm".to_owned(),
            nonce: URL_SAFE_NO_PAD.encode([42_u8; AES_GCM_NONCE_LEN]),
        };
        let rewrapped = rewrap_seed_with_params(
            &vector.seed_envelope,
            vector.master_password.as_bytes(),
            b"new master password",
            new_kdf,
            new_cipher,
        )
        .expect("rewrap");
        assert_ne!(rewrapped, vector.seed_envelope);
        assert!(verify_seed_fingerprint(
            &rewrapped,
            b"new master password",
            &vector.seed_fingerprint_display
        )
        .expect("verify new"));
    }

    fn hex_to_vec(hex: &str) -> Option<Vec<u8>> {
        if !hex.len().is_multiple_of(2) {
            return None;
        }
        let mut out = Vec::with_capacity(hex.len() / 2);
        for chunk in hex.as_bytes().chunks(2) {
            let s = core::str::from_utf8(chunk).ok()?;
            out.push(u8::from_str_radix(s, 16).ok()?);
        }
        Some(out)
    }
}
