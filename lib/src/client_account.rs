//! Windows account bound to an authorized client certificate.
//!
//! `rose ctl approve` and `rose ctl authorize` record the account that ran
//! the command. A system service opens shells as that account. The file sits
//! next to the certificate as `name.user`.

use std::path::{Path, PathBuf};

/// Account that owns shells for one client certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientAccount {
    /// User name, without a domain.
    pub user: String,
    /// Windows SID. Empty when the account was recorded on Unix.
    pub sid: String,
}

impl ClientAccount {
    /// Whether this SID is `LocalSystem`.
    #[must_use]
    pub fn is_local_system(&self) -> bool {
        self.sid.eq_ignore_ascii_case("S-1-5-18")
    }

    /// Name shown in logs.
    #[must_use]
    pub fn label(&self) -> String {
        if self.sid.is_empty() {
            self.user.clone()
        } else {
            format!("{} ({})", self.user, self.sid)
        }
    }
}

/// Path of the account file for a certificate path ending in `.crt`.
#[must_use]
pub fn sidecar(cert_path: &Path) -> PathBuf {
    let name = cert_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("client.crt");
    let stem = name.strip_suffix(".crt").unwrap_or(name);
    cert_path.with_file_name(format!("{stem}.user"))
}

/// Writes the account next to `cert_path`.
///
/// # Errors
///
/// Returns an error when the file cannot be written.
pub fn write_account(cert_path: &Path, account: &ClientAccount) -> std::io::Result<()> {
    let user = account.user.replace(['\n', '\r'], " ");
    let sid = account.sid.replace(['\n', '\r'], " ");
    std::fs::write(sidecar(cert_path), format!("user={user}\nsid={sid}\n"))
}

/// Reads the account recorded for a certificate file.
#[must_use]
pub fn read_account(cert_path: &Path) -> Option<ClientAccount> {
    let text = std::fs::read_to_string(sidecar(cert_path)).ok()?;
    parse_account(&text)
}

/// Reads the account for an authorized certificate's exact DER bytes.
#[must_use]
pub fn read_for_cert(authorized_certs_dir: &Path, cert_der: &[u8]) -> Option<ClientAccount> {
    let path = crate::config::authorized_cert_path(authorized_certs_dir, cert_der)?;
    read_account(&path)
}

/// Account to store when this process approves a client.
///
/// On Windows this is the process token. A `LocalSystem` process records the
/// interactive console user instead, because the service itself is not a
/// login account.
#[must_use]
pub fn capture_approver() -> ClientAccount {
    #[cfg(windows)]
    {
        if crate::win_shell::is_local_system().unwrap_or(false)
            && let Ok((user, sid)) = crate::win_shell::console_user()
            && !sid.eq_ignore_ascii_case("S-1-5-18")
        {
            return ClientAccount { user, sid };
        }
        if let Ok((user, sid)) = crate::win_shell::current_user() {
            return ClientAccount { user, sid };
        }
    }
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string());
    ClientAccount {
        user,
        sid: String::new(),
    }
}

/// Records [`capture_approver`] beside a certificate that was just accepted.
pub fn bind_cert(cert_path: &Path) -> ClientAccount {
    let account = capture_approver();
    if let Err(error) = write_account(cert_path, &account) {
        tracing::warn!(%error, path = %cert_path.display(), "could not record the account for this client");
    }
    account
}

/// Short identity for a login event.
#[must_use]
pub fn describe(authorized_certs_dir: &Path, cert_der: Option<&[u8]>) -> String {
    let Some(cert_der) = cert_der else {
        return "unknown client".to_string();
    };
    if let Some(account) = read_for_cert(authorized_certs_dir, cert_der) {
        return account.label();
    }
    let fingerprint = crate::config::cert_fingerprint(cert_der);
    let shown = fingerprint.chars().take(23).collect::<String>();
    format!("cert {shown}")
}

fn parse_account(text: &str) -> Option<ClientAccount> {
    let mut user = None;
    let mut sid = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("user=") {
            user = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("sid=") {
            sid = Some(value.trim().to_string());
        }
    }
    let user = user.filter(|user| !user.is_empty())?;
    Some(ClientAccount {
        user,
        sid: sid.unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::{
        ClientAccount, bind_cert, describe, parse_account, read_account, sidecar, write_account,
    };

    #[test]
    fn account_file_round_trips_beside_the_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("lyam.crt");
        std::fs::write(&cert, b"der").unwrap();
        let account = ClientAccount {
            user: "lyam".to_string(),
            sid: "S-1-5-21-1".to_string(),
        };
        write_account(&cert, &account).unwrap();
        assert_eq!(sidecar(&cert), dir.path().join("lyam.user"));
        assert_eq!(read_account(&cert), Some(account.clone()));
        assert_eq!(account.label(), "lyam (S-1-5-21-1)");
        assert!(
            ClientAccount {
                user: "SYSTEM".to_string(),
                sid: "s-1-5-18".to_string(),
            }
            .is_local_system()
        );
        assert!(parse_account("sid=S-1\n").is_none());
    }

    #[test]
    fn describe_uses_the_bound_account_or_a_fingerprint() {
        let dir = tempfile::tempdir().unwrap();
        let authorized = dir.path().join("authorized_certs");
        std::fs::create_dir_all(&authorized).unwrap();
        let cert = authorized.join("lyam.crt");
        std::fs::write(&cert, b"cert-bytes").unwrap();
        write_account(
            &cert,
            &ClientAccount {
                user: "lyam".to_string(),
                sid: String::new(),
            },
        )
        .unwrap();
        assert_eq!(describe(&authorized, Some(b"cert-bytes")), "lyam");
        assert_eq!(describe(&authorized, None), "unknown client");
        let unbound = describe(&authorized, Some(b"other"));
        assert!(unbound.starts_with("cert "), "{unbound}");
    }

    #[test]
    fn bind_cert_records_the_process_user() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("pair.crt");
        std::fs::write(&cert, b"der").unwrap();
        let account = bind_cert(&cert);
        assert!(!account.user.is_empty());
        assert_eq!(read_account(&cert).unwrap().user, account.user);
    }
}
