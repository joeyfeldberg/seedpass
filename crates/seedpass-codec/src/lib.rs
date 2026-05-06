//! Canonical and strict encoding for Seedpass.
//!
//! Canonicalization is a security boundary. Implementations must chase the
//! checked-in byte vectors, not incidental serde/YAML behavior.

use std::collections::BTreeSet;

use seedpass_core::{DerivationRecipeV1, ProfileSnapshot, Purpose};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CodecError {
    #[error("derivation-critical string contains non-ASCII data: {field}")]
    NonAscii { field: &'static str },
    #[error("unsupported derivation recipe purpose")]
    UnsupportedPurpose,
    #[error("duplicate YAML key `{key}` at line {line}")]
    DuplicateYamlKey { key: String, line: usize },
    #[error("unsupported YAML syntax at line {line}: {reason}")]
    UnsupportedYamlSyntax { line: usize, reason: &'static str },
}

/// Canonical JSON bytes for a `seedpass-v1` derivation recipe.
///
/// This is intentionally hand-written over the closed derivation struct. It does
/// not canonicalize arbitrary serde values.
pub fn canonical_recipe_v1(recipe: &DerivationRecipeV1) -> Result<Vec<u8>, CodecError> {
    validate_ascii("format", &recipe.format)?;
    validate_ascii("scheme", recipe.scheme.as_str())?;
    validate_ascii("credential_uid", recipe.credential_uid.as_str())?;
    validate_ascii("public_salt", recipe.public_salt.as_str())?;

    let mut out = String::new();
    out.push('{');
    push_string_field(&mut out, "credential_uid", recipe.credential_uid.as_str());
    out.push(',');
    push_string_field(&mut out, "format", &recipe.format);
    out.push(',');
    out.push_str("\"profile_snapshot\":");
    push_profile_snapshot(&mut out, &recipe.profile_snapshot)?;
    out.push(',');
    push_string_field(&mut out, "public_salt", recipe.public_salt.as_str());
    out.push(',');
    push_string_field(&mut out, "purpose", purpose_str(&recipe.purpose)?);
    out.push(',');
    push_string_field(&mut out, "scheme", recipe.scheme.as_str());
    out.push(',');
    push_u32_field(&mut out, "version", recipe.version);
    out.push('}');
    Ok(out.into_bytes())
}

/// Conservative duplicate-key preflight for Seedpass' YAML subset.
///
/// This is not a general-purpose YAML parser. It is a strict pre-parser for the
/// simple mapping/list style used by derivation-critical Seedpass files. The
/// storage layer should run this before typed deserialization.
pub fn reject_duplicate_yaml_keys(input: &str) -> Result<(), CodecError> {
    let mut stack: Vec<(usize, BTreeSet<String>)> = vec![(0, BTreeSet::new())];

    for (line_index, raw_line) in input.lines().enumerate() {
        let line_number = line_index + 1;
        let without_comment = raw_line
            .split_once('#')
            .map_or(raw_line, |(before, _)| before);
        if without_comment.trim().is_empty() {
            continue;
        }
        if raw_line.contains('\t') {
            return Err(CodecError::UnsupportedYamlSyntax {
                line: line_number,
                reason: "tabs are not allowed in Seedpass YAML",
            });
        }
        if without_comment.contains(['{', '}']) {
            return Err(CodecError::UnsupportedYamlSyntax {
                line: line_number,
                reason: "flow mappings are not allowed in Seedpass YAML",
            });
        }

        let indent = without_comment.chars().take_while(|ch| *ch == ' ').count();
        let trimmed = without_comment.trim_start();
        if trimmed.starts_with('&') || trimmed.starts_with('*') || trimmed.starts_with("<<:") {
            return Err(CodecError::UnsupportedYamlSyntax {
                line: line_number,
                reason: "anchors, aliases, and merge keys are not allowed in Seedpass YAML",
            });
        }
        let is_list_item = trimmed.starts_with("- ");
        let mapping_text = trimmed.strip_prefix("- ").unwrap_or(trimmed).trim_start();
        let Some(key) = yaml_mapping_key(mapping_text) else {
            continue;
        };

        while stack.len() > 1 && indent < stack.last().expect("stack has root").0 {
            stack.pop();
        }
        if is_list_item {
            while stack.len() > 1 && indent <= stack.last().expect("stack has root").0 {
                stack.pop();
            }
            stack.push((indent + 2, BTreeSet::new()));
        } else if indent > stack.last().expect("stack has root").0 {
            stack.push((indent, BTreeSet::new()));
        }

        let keys = &mut stack.last_mut().expect("stack has root").1;
        if !keys.insert(key.clone()) {
            return Err(CodecError::DuplicateYamlKey {
                key,
                line: line_number,
            });
        }
    }

    Ok(())
}

fn yaml_mapping_key(line: &str) -> Option<String> {
    let (candidate, _) = line.split_once(':')?;
    let key = candidate.trim();
    if key.is_empty() || key.contains(['{', '}', '[', ']']) {
        return None;
    }
    Some(key.trim_matches('"').trim_matches('\'').to_owned())
}

fn push_profile_snapshot(out: &mut String, profile: &ProfileSnapshot) -> Result<(), CodecError> {
    match profile {
        ProfileSnapshot::Password {
            length,
            min_uppercase,
            min_lowercase,
            min_digits,
            min_symbols,
            symbols,
        } => {
            validate_ascii("profile_snapshot.symbols", symbols)?;
            out.push('{');
            push_string_field(out, "kind", "password");
            out.push(',');
            push_u16_field(out, "length", *length);
            out.push(',');
            push_u16_field(out, "min_digits", *min_digits);
            out.push(',');
            push_u16_field(out, "min_lowercase", *min_lowercase);
            out.push(',');
            push_u16_field(out, "min_symbols", *min_symbols);
            out.push(',');
            push_u16_field(out, "min_uppercase", *min_uppercase);
            out.push(',');
            push_string_field(out, "symbols", symbols);
            out.push('}');
        }
    }
    Ok(())
}

fn purpose_str(purpose: &Purpose) -> Result<&'static str, CodecError> {
    match purpose {
        Purpose::WebPassword => Ok("web-password"),
    }
}

fn push_string_field(out: &mut String, key: &str, value: &str) {
    push_json_string(out, key);
    out.push(':');
    push_json_string(out, value);
}

fn push_u16_field(out: &mut String, key: &str, value: u16) {
    push_json_string(out, key);
    out.push(':');
    out.push_str(&value.to_string());
}

fn push_u32_field(out: &mut String, key: &str, value: u32) {
    push_json_string(out, key);
    out.push(':');
    out.push_str(&value.to_string());
}

fn push_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch < ' ' => {
                out.push_str("\\u");
                out.push_str(&format!("{:04x}", ch as u32));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

fn validate_ascii(field: &'static str, value: &str) -> Result<(), CodecError> {
    if value.is_ascii() {
        Ok(())
    } else {
        Err(CodecError::NonAscii { field })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seedpass_core::{
        Alias, CredentialRecord, CredentialUid, CredentialVersion, PublicSalt, Scheme, SeedLabel,
        VersionStatus, RECIPE_FORMAT_V1, SCHEME_V1,
    };
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Vector {
        canonical_recipe_json: String,
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
            scheme: Scheme::from(SCHEME_V1),
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
    fn canonical_recipe_matches_vector_byte_for_byte() {
        let actual = canonical_recipe_v1(&recipe()).expect("canonicalizes");
        assert_eq!(actual, vector().canonical_recipe_json.into_bytes());
    }

    #[test]
    fn json_string_escaping_is_minimal_and_valid() {
        let mut out = String::new();
        push_json_string(&mut out, "quote:\" slash:\\ newline:\n");
        assert_eq!(out, "\"quote:\\\" slash:\\\\ newline:\\n\"");
    }

    #[test]
    fn duplicate_yaml_keys_are_rejected_by_preflight() {
        let yaml = "format: seedpass-recipes-v1\nformat: seedpass-recipes-v1\n";
        assert_eq!(
            reject_duplicate_yaml_keys(yaml),
            Err(CodecError::DuplicateYamlKey {
                key: "format".to_owned(),
                line: 2
            })
        );
    }

    #[test]
    fn repeated_yaml_keys_in_different_list_items_are_allowed() {
        let yaml = "credentials:\n  - uid: cred_a\n    alias: a\n  - uid: cred_b\n    alias: b\n";
        assert_eq!(reject_duplicate_yaml_keys(yaml), Ok(()));
    }

    #[test]
    fn flow_mapping_yaml_is_rejected() {
        assert!(matches!(
            reject_duplicate_yaml_keys("format: {a: 1, a: 2}\n"),
            Err(CodecError::UnsupportedYamlSyntax { .. })
        ));
    }

    #[test]
    fn non_ascii_derivation_string_is_rejected() {
        let mut recipe = recipe();
        recipe.credential_uid = CredentialUid::from("cred_é");
        assert_eq!(
            canonical_recipe_v1(&recipe),
            Err(CodecError::NonAscii {
                field: "credential_uid"
            })
        );
    }

    #[test]
    fn mutable_metadata_is_not_in_canonical_recipe() {
        let record = CredentialRecord {
            uid: CredentialUid::from("cred_01HX8K8M9G6TD9CZQK7BW6MQD2"),
            alias: Alias::from("github-personal"),
            purpose: Purpose::WebPassword,
            versions: vec![CredentialVersion {
                number: 1,
                status: VersionStatus::Pending,
                seed: SeedLabel::from("personal"),
                scheme: Scheme::from(SCHEME_V1),
                public_salt: PublicSalt::from("EBESExQVFhcYGRobHB0eHw"),
                profile_snapshot: ProfileSnapshot::Password {
                    length: 24,
                    min_uppercase: 1,
                    min_lowercase: 1,
                    min_digits: 1,
                    min_symbols: 1,
                    symbols: "-_.!@#$%^&*".to_owned(),
                },
                created_at: Some("2026-05-10T00:00:00Z".to_owned()),
                confirmed_at: None,
                failed_at: None,
                retired_at: None,
                revoked_at: None,
            }],
        };
        let canonical = String::from_utf8(
            canonical_recipe_v1(&DerivationRecipeV1::from_record_version(
                &record,
                &record.versions[0],
            ))
            .expect("canonicalizes"),
        )
        .expect("utf8");

        for excluded in [
            "github-personal",
            "personal",
            "2026-05-10T00:00:00Z",
            "service",
            "username",
            "tags",
            "seed_fingerprint",
            "seed path",
        ] {
            assert!(!canonical.contains(excluded), "found excluded: {excluded}");
        }
    }
}
