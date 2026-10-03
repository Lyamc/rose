//! Connection retry policy and failure classification.
//!
//! Initial connects retry on unreachable/timeout errors. A server that is
//! listening and rejecting the handshake (missing or unauthorized client
//! certificate, TLS alert, QUIC `CONNECTION_REFUSED`) is reported and not
//! retried unless `always_retry` is set.

use std::time::Duration;

use crate::config::RoseConfig;
use crate::transport::TransportError;

/// Default maximum number of initial connection attempts.
pub const DEFAULT_RETRY_LIMIT: i64 = 10;

/// Cap for the decay schedule, in seconds.
const MAX_DELAY_SECS: u64 = 3600;

/// Leading terms of the default delay schedule, in seconds.
///
/// After this prefix the delay is 60s, then doubles until [`MAX_DELAY_SECS`].
const DECAY_PREFIX_SECS: &[u64] = &[1, 2, 3, 5, 5, 5, 10, 10, 10, 30];

/// How a failed connection attempt should be treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectFailureKind {
    /// Nothing useful answered: timeout, reset, bind failure, packet loss.
    Transient,
    /// The peer was listening and refused this client.
    Rejected,
}

/// Delay between retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryInterval {
    /// `1, 2, 3, 5, 5, 5, 10, 10, 10, 30, 60, 120, ...` seconds, capped at 1 hour.
    Decay,
    /// Constant delay.
    Fixed(Duration),
}

/// Client retry configuration, merged from `config.toml` and CLI flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryPolicy {
    /// Retry even when the server is listening and rejecting the client.
    pub always_retry: bool,
    /// Maximum initial-connection attempts. Negative means unlimited.
    pub retry_limit: i64,
    /// Delay schedule.
    pub interval: RetryInterval,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            always_retry: false,
            retry_limit: DEFAULT_RETRY_LIMIT,
            interval: RetryInterval::Decay,
        }
    }
}

/// CLI overrides for [`RetryPolicy`], passed as one value so call sites stay small.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RetryFlags {
    /// `--always-retry`.
    pub always_retry: bool,
    /// `--retry-limit`, if set.
    pub retry_limit: Option<i64>,
    /// `--retry-interval` in seconds, if set.
    pub retry_interval: Option<u64>,
}

impl RetryFlags {
    /// Merges these flags with `config.toml`.
    #[must_use]
    pub fn resolve(self, config: &RoseConfig) -> RetryPolicy {
        RetryPolicy::resolve(
            config,
            self.always_retry,
            self.retry_limit,
            self.retry_interval,
        )
    }
}

impl RetryPolicy {
    /// Builds a policy from config, with CLI flags taking precedence.
    ///
    /// `always_retry` is OR-ed with the config value. `retry_limit` and
    /// `retry_interval_secs` override the config when `Some`.
    #[must_use]
    pub fn resolve(
        config: &RoseConfig,
        always_retry: bool,
        retry_limit: Option<i64>,
        retry_interval_secs: Option<u64>,
    ) -> Self {
        let interval = match retry_interval_secs.or(config.retry_interval_secs) {
            Some(secs) => RetryInterval::Fixed(Duration::from_secs(secs)),
            None => RetryInterval::Decay,
        };
        Self {
            always_retry: always_retry || config.always_retry,
            retry_limit: retry_limit.unwrap_or(config.retry_limit),
            interval,
        }
    }

    /// Delay to wait after `failed_attempts` unsuccessful tries (1-based).
    #[must_use]
    pub fn delay_after(self, failed_attempts: u32) -> Duration {
        match self.interval {
            RetryInterval::Fixed(duration) => duration,
            RetryInterval::Decay => {
                let index = failed_attempts.saturating_sub(1);
                Duration::from_secs(decay_secs(index))
            }
        }
    }

    /// Whether `attempts` (1-based, including the latest failure) used up the limit.
    ///
    /// Mid-session reconnects pass `unlimited = true` so roaming is not capped
    /// by the initial-connect limit.
    #[must_use]
    pub const fn exhausted(self, attempts: u32, unlimited: bool) -> bool {
        if unlimited || self.retry_limit < 0 {
            return false;
        }
        let limit = if self.retry_limit == 0 {
            1
        } else {
            self.retry_limit as u32
        };
        attempts >= limit
    }

    /// Whether this failure should be retried under the policy.
    #[must_use]
    pub const fn should_retry(self, kind: ConnectFailureKind) -> bool {
        match kind {
            ConnectFailureKind::Transient => true,
            ConnectFailureKind::Rejected => self.always_retry,
        }
    }
}

/// Seconds to wait after the attempt at `index` (0-based) under the decay schedule.
#[must_use]
pub fn decay_secs(index: u32) -> u64 {
    let idx = index as usize;
    if idx < DECAY_PREFIX_SECS.len() {
        return DECAY_PREFIX_SECS[idx];
    }
    let extra = u32::try_from(idx - DECAY_PREFIX_SECS.len()).unwrap_or(u32::MAX);
    let shift = extra.min(6);
    (60u64.saturating_mul(1u64 << shift)).min(MAX_DELAY_SECS)
}

/// Classifies a transport-layer connect failure.
#[must_use]
pub fn classify_transport(error: &TransportError) -> ConnectFailureKind {
    match error {
        TransportError::Connect(error) => classify_connect_error(error),
        TransportError::Connection(error) => classify_connection_error(error),
        TransportError::Bind(_) | TransportError::Config(_) => ConnectFailureKind::Transient,
    }
}

/// Classifies an `anyhow` error by walking the source chain.
#[must_use]
pub fn classify_anyhow(error: &anyhow::Error) -> ConnectFailureKind {
    for cause in error.chain() {
        if let Some(transport) = cause.downcast_ref::<TransportError>() {
            return classify_transport(transport);
        }
        if let Some(connection) = cause.downcast_ref::<quinn::ConnectionError>() {
            return classify_connection_error(connection);
        }
        if let Some(connect) = cause.downcast_ref::<quinn::ConnectError>() {
            return classify_connect_error(connect);
        }
    }
    classify_message(&error.to_string())
}

const fn classify_connect_error(error: &quinn::ConnectError) -> ConnectFailureKind {
    match error {
        quinn::ConnectError::EndpointStopping
        | quinn::ConnectError::CidsExhausted
        | quinn::ConnectError::NoDefaultClientConfig => ConnectFailureKind::Transient,
        quinn::ConnectError::InvalidServerName(_)
        | quinn::ConnectError::InvalidRemoteAddress(_)
        | quinn::ConnectError::UnsupportedVersion => ConnectFailureKind::Rejected,
    }
}

fn classify_connection_error(error: &quinn::ConnectionError) -> ConnectFailureKind {
    match error {
        quinn::ConnectionError::TimedOut | quinn::ConnectionError::Reset => {
            ConnectFailureKind::Transient
        }
        quinn::ConnectionError::VersionMismatch | quinn::ConnectionError::LocallyClosed => {
            ConnectFailureKind::Rejected
        }
        quinn::ConnectionError::CidsExhausted => ConnectFailureKind::Transient,
        quinn::ConnectionError::TransportError(transport) => {
            classify_code_raw(u64::from(transport.code), transport.reason.as_bytes())
        }
        quinn::ConnectionError::ConnectionClosed(close) => {
            classify_code_raw(u64::from(close.error_code), &close.reason)
        }
        quinn::ConnectionError::ApplicationClosed(_) => ConnectFailureKind::Rejected,
    }
}

fn classify_code_raw(code: u64, reason: &[u8]) -> ConnectFailureKind {
    if code == u64::from(quinn::TransportErrorCode::CONNECTION_REFUSED)
        || code == u64::from(quinn::TransportErrorCode::APPLICATION_ERROR)
        || (0x100..0x200).contains(&code)
    {
        return ConnectFailureKind::Rejected;
    }
    classify_message(&String::from_utf8_lossy(reason))
}

fn classify_message(message: &str) -> ConnectFailureKind {
    let lower = message.to_ascii_lowercase();
    if lower.contains("cryptographic handshake")
        || lower.contains("invalid peer certificate")
        || lower.contains("unknownissuer")
        || lower.contains("certificate required")
        || lower.contains("unknown ca")
        || lower.contains("handshake failed")
        || lower.contains("connection refused")
    {
        ConnectFailureKind::Rejected
    } else {
        ConnectFailureKind::Transient
    }
}

/// User-facing explanation for a rejected connection.
#[must_use]
pub fn explain_rejection(error: &dyn std::fmt::Display, pairing_code: Option<&str>) -> String {
    let text = error.to_string();
    let lower = text.to_ascii_lowercase();
    if lower.contains("unknownissuer")
        || lower.contains("unknown ca")
        || lower.contains("invalid peer certificate")
        || lower.contains("certificate required")
    {
        let pairing = pairing_code.map_or(String::new(), |code| {
            format!(" Pairing code: {code}. On the server run: rose ctl approve {code}.")
        });
        format!(
            "server rejected the client certificate ({text}).{pairing} \
             You can also copy this machine's client certificate (usually \
             ~/.config/rose/client.crt.der) into the server's authorized_certs/ \
             directory as a .crt file."
        )
    } else {
        format!("server rejected the connection ({text})")
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn decay_schedule_matches_specified_prefix_then_doubles() {
        let expected = [
            1, 2, 3, 5, 5, 5, 10, 10, 10, 30, 60, 120, 240, 480, 960, 1920, 3600, 3600,
        ];
        for (index, secs) in expected.into_iter().enumerate() {
            assert_eq!(decay_secs(index as u32), secs, "index {index}");
        }
    }

    #[test]
    fn default_policy_uses_decay_and_ten_attempts() {
        let policy = RetryPolicy::default();
        assert!(!policy.always_retry);
        assert_eq!(policy.retry_limit, 10);
        assert_eq!(policy.interval, RetryInterval::Decay);
        assert_eq!(policy.delay_after(1), Duration::from_secs(1));
        assert_eq!(policy.delay_after(2), Duration::from_secs(2));
        assert_eq!(policy.delay_after(11), Duration::from_secs(60));
        assert!(!policy.exhausted(9, false));
        assert!(policy.exhausted(10, false));
        assert!(!policy.exhausted(10, true));
        assert!(!policy.exhausted(99, true));
    }

    #[test]
    fn negative_retry_limit_is_unlimited() {
        let policy = RetryPolicy {
            retry_limit: -1,
            ..RetryPolicy::default()
        };
        assert!(!policy.exhausted(1_000, false));
    }

    #[test]
    fn zero_retry_limit_is_a_single_attempt() {
        let policy = RetryPolicy {
            retry_limit: 0,
            ..RetryPolicy::default()
        };
        assert!(policy.exhausted(1, false));
    }

    #[test]
    fn rejected_errors_retry_only_when_always_retry() {
        let mut policy = RetryPolicy::default();
        assert!(policy.should_retry(ConnectFailureKind::Transient));
        assert!(!policy.should_retry(ConnectFailureKind::Rejected));
        policy.always_retry = true;
        assert!(policy.should_retry(ConnectFailureKind::Rejected));
    }

    #[test]
    fn resolve_prefers_cli_over_config() {
        let cfg = RoseConfig {
            always_retry: false,
            retry_limit: 4,
            retry_interval_secs: Some(7),
            ..RoseConfig::default()
        };
        let policy = RetryPolicy::resolve(&cfg, true, Some(-1), None);
        assert!(policy.always_retry);
        assert_eq!(policy.retry_limit, -1);
        assert_eq!(
            policy.interval,
            RetryInterval::Fixed(Duration::from_secs(7))
        );

        let policy = RetryPolicy::resolve(&cfg, false, None, Some(2));
        assert!(!policy.always_retry);
        assert_eq!(policy.retry_limit, 4);
        assert_eq!(
            policy.interval,
            RetryInterval::Fixed(Duration::from_secs(2))
        );
    }

    #[test]
    fn classify_timeout_as_transient() {
        assert_eq!(
            classify_transport(&TransportError::Connection(
                quinn::ConnectionError::TimedOut
            )),
            ConnectFailureKind::Transient
        );
        assert_eq!(
            classify_transport(&TransportError::Connection(quinn::ConnectionError::Reset)),
            ConnectFailureKind::Transient
        );
    }

    #[test]
    fn classify_handshake_messages_as_rejected() {
        let err = anyhow::anyhow!(
            "connection error: the cryptographic handshake failed: error 48: invalid peer certificate: UnknownIssuer"
        );
        assert_eq!(classify_anyhow(&err), ConnectFailureKind::Rejected);
        let explanation = explain_rejection(&err, Some("12345678"));
        assert!(explanation.contains("authorized_certs"), "{explanation}");
        assert!(explanation.contains("client certificate"), "{explanation}");
        assert!(explanation.contains("12345678"), "{explanation}");
        assert!(explanation.contains("rose ctl approve"), "{explanation}");
    }

    #[test]
    fn classify_generic_io_as_transient() {
        let err = anyhow::anyhow!("failed to bind endpoint: address in use");
        assert_eq!(classify_anyhow(&err), ConnectFailureKind::Transient);
    }

    #[tokio::test]
    async fn empty_authorized_certs_is_a_rejected_handshake() {
        let dir = tempfile::tempdir().unwrap();
        let server_cert =
            crate::config::generate_self_signed_cert(&["localhost".to_string()]).unwrap();
        let client_cert =
            crate::config::generate_self_signed_cert(&["localhost".to_string()]).unwrap();
        let server = crate::transport::QuicServer::bind_mutual_tls(
            "127.0.0.1:0".parse().unwrap(),
            server_cert,
            dir.path(),
            dir.path(),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let server_cert_der = server.server_cert_der().clone();
        let accept = tokio::spawn(async move {
            let _ = server.accept().await;
        });

        let client = crate::transport::QuicClient::new().unwrap();
        let kind = match client
            .connect_with_cert(addr, "localhost", &server_cert_der, &client_cert)
            .await
        {
            Err(err) => classify_transport(&err),
            Ok(conn) => classify_transport(&TransportError::Connection(conn.closed().await)),
        };
        assert_eq!(kind, ConnectFailureKind::Rejected);
        let _ = accept.await;
    }
}
