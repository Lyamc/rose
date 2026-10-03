//! `OpenID` Connect device authorization for pairing a client certificate.
//!
//! The server is the OIDC client. It shows a URL and user code on the
//! connecting terminal, polls the token endpoint, and on success authorizes
//! the presented certificate.

use serde::Deserialize;

use crate::config::RoseConfig;

/// OIDC client settings from `config.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoSettings {
    /// Issuer URL (`https://idp.example.com/realms/rose`).
    pub issuer: String,
    /// Confidential or public client id.
    pub client_id: String,
    /// Optional client secret.
    pub client_secret: Option<String>,
}

impl RoseConfig {
    /// OIDC settings when both issuer and client id are set.
    #[must_use]
    pub fn sso_settings(&self) -> Option<SsoSettings> {
        let issuer = self.sso_issuer.as_ref()?.trim();
        let client_id = self.sso_client_id.as_ref()?.trim();
        if issuer.is_empty() || client_id.is_empty() {
            return None;
        }
        Some(SsoSettings {
            issuer: issuer.trim_end_matches('/').to_string(),
            client_id: client_id.to_string(),
            client_secret: self
                .sso_client_secret
                .as_ref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        })
    }
}

/// Device-authorization grant in progress.
#[derive(Debug, Clone)]
pub struct DeviceAuth {
    /// Device code polled at the token endpoint.
    pub device_code: String,
    /// Short code the user types in the browser.
    pub user_code: String,
    /// URL shown to the user.
    pub verification_uri: String,
    /// Minimum poll interval, seconds.
    pub interval: u64,
    /// Lifetime of the device code, seconds.
    pub expires_in: u64,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct Discovery {
    device_authorization_endpoint: Option<String>,
    token_endpoint: String,
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct DeviceAuthResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    interval: Option<u64>,
    #[serde(default)]
    expires_in: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IdClaims {
    sub: String,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    aud: Aud,
}

#[derive(Debug, Deserialize, Default)]
#[serde(untagged)]
enum Aud {
    String(String),
    List(Vec<String>),
    #[default]
    Missing,
}

impl Aud {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::String(value) => value == expected,
            Self::List(values) => values.iter().any(|v| v == expected),
            Self::Missing => false,
        }
    }
}

/// Starts the OIDC device-authorization grant.
///
/// COVERAGE: Talks to a real identity provider; JWT validation is unit-tested.
///
/// # Errors
///
/// Returns `SsoError` when discovery or the device-authorization request fails.
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn start_device_login(settings: &SsoSettings) -> Result<DeviceAuth, SsoError> {
    let client = http_client()?;
    let discovery: Discovery = client
        .get(format!(
            "{}/.well-known/openid-configuration",
            settings.issuer
        ))
        .send()
        .await
        .map_err(|e| SsoError::Http(e.to_string()))?
        .error_for_status()
        .map_err(|e| SsoError::Http(e.to_string()))?
        .json()
        .await
        .map_err(|e| SsoError::Http(e.to_string()))?;
    let endpoint = discovery
        .device_authorization_endpoint
        .ok_or(SsoError::NoDeviceFlow)?;
    let mut form = vec![
        ("client_id", settings.client_id.as_str()),
        ("scope", "openid"),
    ];
    if let Some(secret) = settings.client_secret.as_deref() {
        form.push(("client_secret", secret));
    }
    let resp: DeviceAuthResponse = client
        .post(endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| SsoError::Http(e.to_string()))?
        .error_for_status()
        .map_err(|e| SsoError::Http(e.to_string()))?
        .json()
        .await
        .map_err(|e| SsoError::Http(e.to_string()))?;
    Ok(DeviceAuth {
        device_code: resp.device_code,
        user_code: resp.user_code,
        verification_uri: resp.verification_uri,
        interval: resp.interval.unwrap_or(5).max(1),
        expires_in: resp.expires_in.unwrap_or(600).max(30),
        token_endpoint: discovery.token_endpoint,
        jwks_uri: discovery.jwks_uri,
    })
}

/// Polls once for an `id_token`. `Ok(None)` means the user has not finished.
///
/// COVERAGE: Talks to a real identity provider; JWT validation is unit-tested.
///
/// # Errors
///
/// Returns `SsoError` when the token request or JWT validation fails.
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn try_poll_id_token(
    settings: &SsoSettings,
    auth: &DeviceAuth,
) -> Result<Option<String>, SsoError> {
    let client = http_client()?;
    let mut form = vec![
        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ("device_code", auth.device_code.as_str()),
        ("client_id", settings.client_id.as_str()),
    ];
    if let Some(secret) = settings.client_secret.as_deref() {
        form.push(("client_secret", secret));
    }
    let resp: TokenResponse = client
        .post(&auth.token_endpoint)
        .form(&form)
        .send()
        .await
        .map_err(|e| SsoError::Http(e.to_string()))?
        .json()
        .await
        .map_err(|e| SsoError::Http(e.to_string()))?;
    if let Some(token) = resp.id_token {
        let jwks = client
            .get(&auth.jwks_uri)
            .send()
            .await
            .map_err(|e| SsoError::Http(e.to_string()))?
            .error_for_status()
            .map_err(|e| SsoError::Http(e.to_string()))?
            .json()
            .await
            .map_err(|e| SsoError::Http(e.to_string()))?;
        let sub = validate_id_token(&token, &jwks, &settings.issuer, &settings.client_id)?;
        return Ok(Some(sub));
    }
    match resp.error.as_deref() {
        None | Some("authorization_pending" | "slow_down") => Ok(None),
        Some(other) => Err(SsoError::Token(other.to_string())),
    }
}

/// Validates an ID token against a JWKS document.
///
/// # Errors
///
/// Returns `SsoError::Token` when the JWT is invalid.
pub fn validate_id_token(
    token: &str,
    jwks: &jsonwebtoken::jwk::JwkSet,
    issuer: &str,
    audience: &str,
) -> Result<String, SsoError> {
    let header = jsonwebtoken::decode_header(token).map_err(|e| SsoError::Token(e.to_string()))?;
    let jwk = header
        .kid
        .as_deref()
        .and_then(|kid| jwks.find(kid))
        .or_else(|| jwks.keys.first())
        .ok_or_else(|| SsoError::Token("no matching JWK".into()))?;
    let key =
        jsonwebtoken::DecodingKey::from_jwk(jwk).map_err(|e| SsoError::Token(e.to_string()))?;
    validate_id_token_with_key(token, &key, header.alg, issuer, audience)
}

/// Validates an ID token with an already-resolved key.
///
/// # Errors
///
/// Returns `SsoError::Token` when the JWT is invalid.
pub fn validate_id_token_with_key(
    token: &str,
    key: &jsonwebtoken::DecodingKey,
    alg: jsonwebtoken::Algorithm,
    issuer: &str,
    audience: &str,
) -> Result<String, SsoError> {
    let mut validation = jsonwebtoken::Validation::new(alg);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["sub", "exp", "iss"]);
    let data = jsonwebtoken::decode::<IdClaims>(token, key, &validation)
        .map_err(|e| SsoError::Token(e.to_string()))?;
    if !data.claims.aud.contains(audience) {
        return Err(SsoError::Token("audience mismatch".into()));
    }
    if data.claims.iss.as_deref() != Some(issuer) {
        return Err(SsoError::Token("issuer mismatch".into()));
    }
    Ok(data.claims.sub)
}

/// SSO failures.
#[derive(Debug, thiserror::Error)]
pub enum SsoError {
    /// HTTP or JSON error talking to the identity provider.
    #[error("SSO HTTP error: {0}")]
    Http(String),
    /// The issuer does not advertise device authorization.
    #[error("identity provider does not support the OIDC device flow")]
    NoDeviceFlow,
    /// Token endpoint or JWT validation failed.
    #[error("SSO token error: {0}")]
    Token(String),
}

#[cfg_attr(coverage_nightly, coverage(off))]
fn http_client() -> Result<reqwest::Client, SsoError> {
    reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .map_err(|e| SsoError::Http(e.to_string()))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde::Serialize;

    #[derive(Serialize)]
    struct EncodeClaims<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        exp: u64,
        iat: u64,
    }

    #[test]
    fn sso_settings_need_issuer_and_client_id() {
        let mut cfg = RoseConfig::default();
        assert!(cfg.sso_settings().is_none());
        cfg.sso_issuer = Some("https://idp.example".into());
        assert!(cfg.sso_settings().is_none());
        cfg.sso_client_id = Some("rose".into());
        let sso = cfg.sso_settings().unwrap();
        assert_eq!(sso.issuer, "https://idp.example");
        assert_eq!(sso.client_id, "rose");
    }

    #[test]
    fn validates_signed_id_token() {
        let secret = b"unit-test-hs256-secret-key!!!!";
        let now = jsonwebtoken::get_current_timestamp();
        let token = encode(
            &Header::new(Algorithm::HS256),
            &EncodeClaims {
                sub: "user-1",
                iss: "https://idp.example",
                aud: "rose",
                exp: now + 60,
                iat: now,
            },
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        let key = jsonwebtoken::DecodingKey::from_secret(secret);
        let sub = validate_id_token_with_key(
            &token,
            &key,
            Algorithm::HS256,
            "https://idp.example",
            "rose",
        )
        .unwrap();
        assert_eq!(sub, "user-1");
        assert!(
            validate_id_token_with_key(&token, &key, Algorithm::HS256, "https://other", "rose")
                .is_err()
        );
    }
}
