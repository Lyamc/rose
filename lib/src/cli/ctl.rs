//! Persistent live configuration for a running `rose server`.
//!
//! `rose ctl set` writes `config.toml`. The server rereads that file on each
//! handshake and while watching live sessions, so changes apply without a
//! restart.

use std::path::{Path, PathBuf};

use clap::Subcommand;

use crate::config::{self, RoseConfig, RosePaths};

/// Subcommands for `rose ctl`.
#[derive(Subcommand, Clone, Debug)]
pub(super) enum CtlAction {
    /// Print the full `config.toml`.
    Show,
    /// Print one config value.
    Get {
        /// Config key (for example `require_client_certs`).
        key: String,
    },
    /// Set one config value and write `config.toml`.
    Set {
        /// Config key (for example `require_client_certs`).
        key: String,
        /// New value (`true`/`false`, a number, a comma-separated list, or `none`).
        value: String,
    },
    /// Copy a client certificate into `authorized_certs/`.
    Authorize {
        /// Path to a DER client certificate (`client.crt.der` from `rose keygen`).
        cert: PathBuf,
        /// Filename under `authorized_certs/` (defaults from the source name).
        #[arg(long)]
        name: Option<String>,
    },
    /// Delete a `.crt` from `authorized_certs/`.
    Revoke {
        /// Certificate file name (`lyam` or `lyam.crt`).
        name: String,
    },
    /// List pairing codes from clients waiting to be approved.
    Pending,
    /// Authorize a client by the pairing code shown on `rose connect`.
    #[command(visible_alias = "pair")]
    Approve {
        /// Numeric pairing code, as printed on the client.
        code: String,
        /// Operator TOTP code, required when `operator.totp` exists.
        #[arg(long)]
        totp: Option<String>,
    },
    /// Discard a pending pairing request.
    Deny {
        /// Numeric pairing code.
        code: String,
    },
    /// Operator TOTP secret for `rose ctl approve`.
    Totp {
        #[command(subcommand)]
        action: TotpAction,
    },
}

/// `rose ctl totp` actions.
#[derive(Subcommand, Clone, Debug)]
pub(super) enum TotpAction {
    /// Write a new `operator.totp` and print the otpauth URI.
    Init,
}

/// Runs a `rose ctl` action against `config_dir` (or the default paths).
///
/// # Errors
///
/// Returns an error if the config cannot be loaded or written, or if a
/// certificate path is invalid.
pub(super) fn run_ctl(
    config_dir: Option<PathBuf>,
    action: Option<CtlAction>,
) -> anyhow::Result<()> {
    let paths = RosePaths::resolve_optional(config_dir);
    match action.unwrap_or(CtlAction::Show) {
        CtlAction::Show => {
            print!("{}", show_config(&paths.config_dir)?);
        }
        CtlAction::Get { key } => {
            println!("{}", get_config(&paths.config_dir, &key)?);
        }
        CtlAction::Set { key, value } => {
            set_config(&paths.config_dir, &key, &value)?;
            println!("{}={}", key, get_config(&paths.config_dir, &key)?);
        }
        CtlAction::Authorize { cert, name } => {
            let dest = authorize_client_cert(&paths, &cert, name.as_deref())?;
            println!("authorized {}", dest.display());
        }
        CtlAction::Revoke { name } => {
            let dest = revoke_client_cert(&paths, &name)?;
            println!("revoked {}", dest.display());
        }
        CtlAction::Pending => {
            print!("{}", format_pending(&paths.config_dir));
        }
        CtlAction::Approve { code, totp } => {
            let dest = config::approve_pending_client_cert(
                &paths.config_dir,
                &paths.authorized_certs_dir,
                &code,
                totp.as_deref(),
            )?;
            println!("authorized {}", dest.display());
        }
        CtlAction::Deny { code } => {
            let dest = config::deny_pending_client_cert(&paths.config_dir, &code)?;
            println!("denied {}", dest.display());
        }
        CtlAction::Totp {
            action: TotpAction::Init,
        } => {
            let (_secret, uri) = crate::totp::init_operator_totp(&paths.config_dir)?;
            println!("{uri}");
        }
    }
    Ok(())
}

fn format_pending(config_dir: &Path) -> String {
    let pending = config::list_pending_client_certs(config_dir);
    if pending.is_empty() {
        return "no pending pairing requests\n".to_string();
    }
    let hint = if crate::totp::operator_totp_configured(config_dir) {
        "pending pairing codes (rose ctl approve <code> --totp <digits>):\n"
    } else {
        "pending pairing codes (rose ctl approve <code>):\n"
    };
    let mut out = String::from(hint);
    for item in pending {
        out.push_str(&format!("  {}  ({}s ago)\n", item.code, item.age_secs));
    }
    out
}

fn show_config(config_dir: &Path) -> anyhow::Result<String> {
    let cfg = RoseConfig::load(config_dir)?;
    Ok(toml::to_string_pretty(&cfg)?)
}

fn get_config(config_dir: &Path, key: &str) -> anyhow::Result<String> {
    Ok(RoseConfig::load(config_dir)?.get_key(key)?)
}

fn set_config(config_dir: &Path, key: &str, value: &str) -> anyhow::Result<()> {
    let mut cfg = RoseConfig::load(config_dir)?;
    cfg.set_key(key, value)?;
    cfg.save(config_dir)?;
    Ok(())
}

fn authorize_client_cert(
    paths: &RosePaths,
    cert: &Path,
    name: Option<&str>,
) -> anyhow::Result<PathBuf> {
    let file_name = match name {
        Some(name) => authorized_cert_filename(name)?,
        None => authorized_cert_filename_from_path(cert)?,
    };
    std::fs::create_dir_all(&paths.authorized_certs_dir)?;
    let dest = paths.authorized_certs_dir.join(file_name);
    let bytes = std::fs::read(cert)?;
    std::fs::write(&dest, bytes)?;
    Ok(dest)
}

fn revoke_client_cert(paths: &RosePaths, name: &str) -> anyhow::Result<PathBuf> {
    let dest = paths
        .authorized_certs_dir
        .join(authorized_cert_filename(name)?);
    if !dest.exists() {
        anyhow::bail!("no authorized certificate named {}", dest.display());
    }
    std::fs::remove_file(&dest)?;
    Ok(dest)
}

fn authorized_cert_filename_from_path(path: &Path) -> anyhow::Result<String> {
    let base = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("certificate path must have a UTF-8 file name"))?;
    let name = if let Some(stem) = base.strip_suffix(".crt.der") {
        format!("{stem}.crt")
    } else if base.ends_with(".crt") {
        base.to_string()
    } else if let Some(stem) = base.strip_suffix(".der") {
        format!("{stem}.crt")
    } else {
        format!("{base}.crt")
    };
    authorized_cert_filename(&name)
}

fn authorized_cert_filename(name: &str) -> anyhow::Result<String> {
    let name = name.trim();
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || Path::new(name).components().count() != 1
    {
        anyhow::bail!("certificate name must be a plain file name");
    }
    if name.ends_with(".crt") {
        Ok(name.to_string())
    } else {
        Ok(format!("{name}.crt"))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn ctl_set_is_visible_to_load_and_get() {
        let dir = tempfile::tempdir().unwrap();
        set_config(dir.path(), "require_client_certs", "false").unwrap();
        set_config(dir.path(), "max_sessions", "4").unwrap();
        assert_eq!(
            get_config(dir.path(), "require_client_certs").unwrap(),
            "false"
        );
        assert_eq!(get_config(dir.path(), "max_sessions").unwrap(), "4");
        let shown = show_config(dir.path()).unwrap();
        assert!(shown.contains("require_client_certs = false"), "{shown}");
        assert!(shown.contains("max_sessions = 4"), "{shown}");
    }

    #[test]
    fn authorize_and_revoke_write_crt_files() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RosePaths::with_base(dir.path().to_path_buf());
        let src = dir.path().join("lyam.crt.der");
        std::fs::write(&src, b"cert-bytes").unwrap();
        let dest = authorize_client_cert(&paths, &src, None).unwrap();
        assert_eq!(dest.file_name().unwrap(), "lyam.crt");
        assert_eq!(std::fs::read(&dest).unwrap(), b"cert-bytes");
        assert!(crate::config::is_authorized_client_cert(
            &paths.authorized_certs_dir,
            b"cert-bytes"
        ));
        revoke_client_cert(&paths, "lyam").unwrap();
        assert!(!dest.exists());
    }

    #[test]
    fn certificate_names_reject_path_components() {
        assert!(authorized_cert_filename("../x.crt").is_err());
        assert!(authorized_cert_filename("a/b.crt").is_err());
        assert_eq!(authorized_cert_filename("alice").unwrap(), "alice.crt");
    }

    #[test]
    fn ctl_approve_and_deny_pending_codes() {
        let dir = tempfile::tempdir().unwrap();
        let paths = RosePaths::with_base(dir.path().to_path_buf());
        let cert = crate::config::generate_self_signed_cert(&["pair".to_string()]).unwrap();
        let code = config::record_pending_client_cert(dir.path(), cert.cert_der.as_ref());
        let listed = format_pending(dir.path());
        assert!(listed.contains(&code), "{listed}");
        run_ctl(
            Some(dir.path().to_path_buf()),
            Some(CtlAction::Approve { code, totp: None }),
        )
        .unwrap();
        assert!(config::is_authorized_client_cert(
            &paths.authorized_certs_dir,
            cert.cert_der.as_ref()
        ));
        assert!(format_pending(dir.path()).contains("no pending"));

        let other = crate::config::generate_self_signed_cert(&["other".to_string()]).unwrap();
        let other_code = config::record_pending_client_cert(dir.path(), other.cert_der.as_ref());
        run_ctl(
            Some(dir.path().to_path_buf()),
            Some(CtlAction::Deny { code: other_code }),
        )
        .unwrap();
        assert!(format_pending(dir.path()).contains("no pending"));
    }

    #[test]
    fn ctl_totp_init_writes_operator_secret() {
        let dir = tempfile::tempdir().unwrap();
        run_ctl(
            Some(dir.path().to_path_buf()),
            Some(CtlAction::Totp {
                action: TotpAction::Init,
            }),
        )
        .unwrap();
        assert!(crate::totp::operator_totp_configured(dir.path()));
        let listed = format_pending(dir.path());
        assert!(listed.contains("no pending"), "{listed}");

        let cert = crate::config::generate_self_signed_cert(&["pair".to_string()]).unwrap();
        let code = config::record_pending_client_cert(dir.path(), cert.cert_der.as_ref());
        let listed = format_pending(dir.path());
        assert!(listed.contains("--totp"), "{listed}");
        assert!(
            run_ctl(
                Some(dir.path().to_path_buf()),
                Some(CtlAction::Approve {
                    code: code.clone(),
                    totp: None
                }),
            )
            .is_err()
        );
        let secret = crate::totp::load_operator_totp(dir.path())
            .unwrap()
            .unwrap();
        let totp = crate::totp::totp_at(&secret, {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });
        run_ctl(
            Some(dir.path().to_path_buf()),
            Some(CtlAction::Approve {
                code,
                totp: Some(totp),
            }),
        )
        .unwrap();
    }
}
