//! RFC 6238 TOTP (HMAC-SHA1, 6 digits, 30-second steps).
//!
//! Operator secrets live in `operator.totp`. Per-client secrets sit next to
//! the matching `authorized_certs/*.crt` as `*.totp`.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use data_encoding::BASE32_NOPAD;
use ring::hmac;

use crate::config::{self, ConfigError};

/// Authenticator-app digits.
pub const TOTP_DIGITS: u32 = 6;
/// Step size in seconds.
pub const TOTP_PERIOD_SECS: u64 = 30;
const SECRET_BYTES: usize = 20;
const OPERATOR_FILE: &str = "operator.totp";

/// Generates a new 160-bit secret and its unpadded Base32 form.
#[must_use]
pub fn generate_secret() -> (String, Vec<u8>) {
    let mut raw = vec![0u8; SECRET_BYTES];
    let _ = getrandom::getrandom(&mut raw);
    (encode_secret(&raw), raw)
}

/// Encodes a raw secret as unpadded Base32.
#[must_use]
pub fn encode_secret(raw: &[u8]) -> String {
    BASE32_NOPAD.encode(raw)
}

/// Decodes an unpadded or padded Base32 secret.
///
/// # Errors
///
/// Returns `ConfigError::InvalidValue` when the secret is not Base32.
pub fn decode_secret(encoded: &str) -> Result<Vec<u8>, ConfigError> {
    let compact: String = encoded
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    BASE32_NOPAD
        .decode(compact.as_bytes())
        .or_else(|_| data_encoding::BASE32.decode(encoded.trim().as_bytes()))
        .map_err(|_| ConfigError::InvalidValue {
            key: "totp_secret".to_string(),
            value: encoded.to_string(),
        })
}

/// `otpauth://` URI for authenticator apps.
#[must_use]
pub fn otpauth_uri(account: &str, secret_b32: &str) -> String {
    let account = account.replace(['/', ':'], "_");
    format!(
        "otpauth://totp/RoSE:{account}?secret={secret_b32}&issuer=RoSE&period={TOTP_PERIOD_SECS}&digits={TOTP_DIGITS}"
    )
}

/// Computes the TOTP code at `unix_time`.
#[must_use]
pub fn totp_at(secret: &[u8], unix_time: u64) -> String {
    let counter = unix_time / TOTP_PERIOD_SECS;
    format!(
        "{:0width$}",
        hotp(secret, counter),
        width = TOTP_DIGITS as usize
    )
}

/// Accepts `code` in the current step or either adjacent step.
#[must_use]
pub fn totp_verify(secret: &[u8], code: &str, unix_time: u64) -> bool {
    let compact: String = code.chars().filter(char::is_ascii_digit).collect();
    if compact.len() != TOTP_DIGITS as usize {
        return false;
    }
    let counter = unix_time / TOTP_PERIOD_SECS;
    for skew in [0_i64, -1, 1] {
        let step = counter.saturating_add_signed(skew);
        if totp_at_counter(secret, step) == compact {
            return true;
        }
    }
    false
}

/// Verifies against the current clock.
#[must_use]
pub fn totp_verify_now(secret: &[u8], code: &str) -> bool {
    totp_verify(secret, code, unix_now())
}

/// Writes the operator TOTP secret, replacing any existing file.
///
/// # Errors
///
/// Returns `ConfigError::Io` on filesystem errors.
pub fn init_operator_totp(config_dir: &Path) -> Result<(String, String), ConfigError> {
    let (encoded, _) = generate_secret();
    std::fs::create_dir_all(config_dir)?;
    std::fs::write(config_dir.join(OPERATOR_FILE), format!("{encoded}\n"))?;
    let uri = otpauth_uri("operator", &encoded);
    Ok((encoded, uri))
}

/// Loads the operator TOTP secret if `operator.totp` exists.
///
/// # Errors
///
/// Returns `ConfigError::InvalidValue` when the file is not Base32.
pub fn load_operator_totp(config_dir: &Path) -> Result<Option<Vec<u8>>, ConfigError> {
    load_totp_file(&config_dir.join(OPERATOR_FILE))
}

/// True when an operator TOTP secret is configured.
#[must_use]
pub fn operator_totp_configured(config_dir: &Path) -> bool {
    config_dir.join(OPERATOR_FILE).is_file()
}

/// Checks an operator TOTP code when a secret is configured.
///
/// # Errors
///
/// Returns `ConfigError::InvalidValue` when a code is required and missing or wrong.
pub fn verify_operator_totp(config_dir: &Path, code: Option<&str>) -> Result<(), ConfigError> {
    let Some(secret) = load_operator_totp(config_dir)? else {
        return Ok(());
    };
    let Some(code) = code.filter(|c| !c.is_empty()) else {
        return Err(ConfigError::InvalidValue {
            key: "totp".to_string(),
            value: String::new(),
        });
    };
    if totp_verify_now(&secret, code) {
        Ok(())
    } else {
        Err(ConfigError::InvalidValue {
            key: "totp".to_string(),
            value: code.to_string(),
        })
    }
}

/// Writes a per-client TOTP secret next to `cert_path` (a `.crt`).
///
/// # Errors
///
/// Returns `ConfigError::Io` on filesystem errors.
pub fn enroll_client_totp(cert_path: &Path) -> Result<(String, String), ConfigError> {
    let (encoded, _) = generate_secret();
    let dest = totp_path_for_cert(cert_path);
    std::fs::write(&dest, format!("{encoded}\n"))?;
    let account = cert_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("client");
    let uri = otpauth_uri(account, &encoded);
    Ok((encoded, uri))
}

/// Loads the TOTP secret for an authorized client certificate DER.
///
/// # Errors
///
/// Returns `ConfigError::InvalidValue` when a sidecar exists but is not Base32.
pub fn secret_for_authorized_cert(
    authorized_certs_dir: &Path,
    cert_der: &[u8],
) -> Result<Option<Vec<u8>>, ConfigError> {
    let Some(cert_path) = config::authorized_cert_path(authorized_certs_dir, cert_der) else {
        return Ok(None);
    };
    load_totp_file(&totp_path_for_cert(&cert_path))
}

fn totp_path_for_cert(cert_path: &Path) -> PathBuf {
    cert_path.with_extension("totp")
}

fn load_totp_file(path: &Path) -> Result<Option<Vec<u8>>, ConfigError> {
    if !path.is_file() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(path)?;
    let line = contents.lines().next().unwrap_or("").trim();
    if line.is_empty() {
        return Ok(None);
    }
    Ok(Some(decode_secret(line)?))
}

fn totp_at_counter(secret: &[u8], counter: u64) -> String {
    format!(
        "{:0width$}",
        hotp(secret, counter),
        width = TOTP_DIGITS as usize
    )
}

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, secret);
    let tag = hmac::sign(&key, &counter.to_be_bytes());
    let hash = tag.as_ref();
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(hash[offset]) & 0x7f) << 24
        | u32::from(hash[offset + 1]) << 16
        | u32::from(hash[offset + 2]) << 8
        | u32::from(hash[offset + 3]);
    bin % 10u32.pow(TOTP_DIGITS)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_sha1_six_digit_vector() {
        let secret = b"12345678901234567890";
        assert_eq!(totp_at(secret, 59), "287082");
        assert!(totp_verify(secret, "287082", 59));
        assert!(totp_verify(secret, "287082", 59 + 30));
        assert!(!totp_verify(secret, "000000", 59));
        assert!(!totp_verify(secret, "12", 59));
    }

    #[test]
    fn secret_roundtrip_and_otpauth() {
        let (encoded, raw) = generate_secret();
        assert_eq!(decode_secret(&encoded).unwrap(), raw);
        let uri = otpauth_uri("alice", &encoded);
        assert!(uri.contains("otpauth://totp/RoSE:alice"));
        assert!(uri.contains(&encoded));
    }

    #[test]
    fn operator_and_client_files() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!operator_totp_configured(dir.path()));
        verify_operator_totp(dir.path(), None).unwrap();
        let (secret, uri) = init_operator_totp(dir.path()).unwrap();
        assert!(operator_totp_configured(dir.path()));
        assert!(uri.contains("operator"));
        let raw = decode_secret(&secret).unwrap();
        let code = totp_at(&raw, unix_now());
        verify_operator_totp(dir.path(), Some(&code)).unwrap();
        assert!(verify_operator_totp(dir.path(), Some("000000")).is_err());
        assert!(verify_operator_totp(dir.path(), None).is_err());

        let cert = dir.path().join("authorized_certs").join("12.crt");
        std::fs::create_dir_all(cert.parent().unwrap()).unwrap();
        std::fs::write(&cert, b"der").unwrap();
        let (_, client_uri) = enroll_client_totp(&cert).unwrap();
        assert!(client_uri.contains("12"));
        assert!(dir.path().join("authorized_certs/12.totp").is_file());
        assert!(
            secret_for_authorized_cert(cert.parent().unwrap(), b"der")
                .unwrap()
                .is_some()
        );
        assert!(
            secret_for_authorized_cert(cert.parent().unwrap(), b"other")
                .unwrap()
                .is_none()
        );
    }
}
