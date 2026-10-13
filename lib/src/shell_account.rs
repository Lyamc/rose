//! Which Windows account a new shell runs as.
//!
//! A user install runs the server as that user, so the shell is the server
//! process. A system install runs the server as `LocalSystem` so it can start
//! before anyone logs on and can open an elevated shell. A normal shell runs
//! as the Windows user recorded when that client was approved. `LocalSystem`
//! is used only when `windows_root_access` allows it.

use portable_pty::CommandBuilder;

use crate::pty::{PtyError, PtySession};

/// Environment variable the client uses to request an elevated shell.
///
/// It is removed before the shell starts.
pub const ELEVATE_ENV: &str = "ROSE_ELEVATE";

/// Environment variable the client uses to request a `LocalSystem` shell.
///
/// It is removed before the shell starts. The server honors it only when
/// `windows_root_access` is true.
pub const SYSTEM_ENV: &str = "ROSE_SYSTEM";

/// Logon-task name used by `rose service install --user`.
pub const LOGON_TASK: &str = "RoSE";

/// How this server process was installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceKind {
    /// The process token is the account that should own shells.
    User,
    /// The process is the machine service. Shells are the approved user.
    System,
}

/// Whether this connection asked for an elevated or system shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellRequest {
    /// The Windows user bound to the client certificate, without elevation.
    Default,
    /// The elevated token of that user.
    Elevated,
    /// `LocalSystem`. Requires `windows_root_access`.
    System,
    /// Both `--elevate` and `--system` were set.
    Conflict,
}

/// Account used to spawn one shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellIdentity {
    /// Spawn with the current process token.
    Process,
    /// The Windows user recorded when the client was approved.
    BoundUser,
    /// Linked elevated token of that user.
    ElevatedUser,
}

/// The requested shell cannot be started.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ShellAccountError {
    /// `--elevate` was used, but this process is not the system service.
    #[error(
        "elevation is only available from the system service (`rose service install`). A user install runs as you and cannot elevate without a consent prompt"
    )]
    ElevationRequiresSystemService,
    /// The Windows user bound to this client is not logged on.
    #[error("Windows user {0} is not logged on")]
    UserNotLoggedOn(String),
    /// The client certificate has no Windows account recorded.
    #[error(
        "this client is not bound to a Windows user. Run `rose ctl approve` as the account that should own the shell"
    )]
    UnboundClient,
    /// `LocalSystem` was requested while `windows_root_access` is false, or from a user install.
    #[error(
        "a LocalSystem shell requires the system service and windows_root_access = true (`rose connect --system`)"
    )]
    RootDisabled,
    /// The client asked for both an elevated shell and a system shell.
    #[error("use either --elevate or --system")]
    ConflictingShellRequest,
    /// The logged-on account has no split elevated token.
    #[error("this logon has no elevated token")]
    NoElevatedToken,
    /// The interactive profile did not include a directory for the shell.
    #[error("the user profile has no USERPROFILE")]
    MissingProfile,
    /// A Windows API call failed.
    #[error("{0}")]
    Windows(String),
    /// Opening the PTY failed after the account was chosen.
    #[error("{0}")]
    Pty(String),
}

/// Decides the shell account.
///
/// A system service does not keep its own token unless `root_access` is set
/// and the client asked for `LocalSystem`, or the approved account is
/// `LocalSystem`. `bound` is the account stored when the certificate was approved.
///
/// # Errors
///
/// Returns [`ShellAccountError`] when elevation, a system shell, or a missing
/// account makes the request impossible.
pub fn shell_identity(
    kind: ServiceKind,
    request: ShellRequest,
    root_access: bool,
    bound: Option<&crate::client_account::ClientAccount>,
) -> Result<ShellIdentity, ShellAccountError> {
    let bound_system = bound.is_some_and(crate::client_account::ClientAccount::is_local_system);
    match (kind, request, root_access, bound.is_some(), bound_system) {
        (_, ShellRequest::Conflict, _, _, _) => Err(ShellAccountError::ConflictingShellRequest),
        (ServiceKind::User, ShellRequest::Default, _, _, _) => Ok(ShellIdentity::Process),
        (ServiceKind::User, ShellRequest::Elevated, _, _, _) => {
            Err(ShellAccountError::ElevationRequiresSystemService)
        }
        (ServiceKind::User, ShellRequest::System, _, _, _) => Err(ShellAccountError::RootDisabled),
        (ServiceKind::System, ShellRequest::System, false, _, _) => {
            Err(ShellAccountError::RootDisabled)
        }
        (ServiceKind::System, ShellRequest::System, true, _, _) => Ok(ShellIdentity::Process),
        (ServiceKind::System, _, false, _, true) => Err(ShellAccountError::RootDisabled),
        (ServiceKind::System, _, true, _, true) => Ok(ShellIdentity::Process),
        (ServiceKind::System, ShellRequest::Default, _, false, _) => {
            Err(ShellAccountError::UnboundClient)
        }
        (ServiceKind::System, ShellRequest::Elevated, _, false, _) => {
            Err(ShellAccountError::UnboundClient)
        }
        (ServiceKind::System, ShellRequest::Default, _, true, false) => {
            Ok(ShellIdentity::BoundUser)
        }
        (ServiceKind::System, ShellRequest::Elevated, _, true, false) => {
            Ok(ShellIdentity::ElevatedUser)
        }
    }
}

/// Removes [`ELEVATE_ENV`] from the forwarded environment.
#[must_use]
pub fn split_shell_request(env: &[(String, String)]) -> (ShellRequest, Vec<(String, String)>) {
    let mut elevate = false;
    let mut system = false;
    let mut kept = Vec::with_capacity(env.len());
    for (key, value) in env {
        if key == ELEVATE_ENV {
            if value == "1" {
                elevate = true;
            }
            continue;
        }
        if key == SYSTEM_ENV {
            if value == "1" {
                system = true;
            }
            continue;
        }
        kept.push((key.clone(), value.clone()));
    }
    let request = match (elevate, system) {
        (true, true) => ShellRequest::Conflict,
        (true, false) => ShellRequest::Elevated,
        (false, true) => ShellRequest::System,
        (false, false) => ShellRequest::Default,
    };
    (request, kept)
}

/// Reads one variable from a Windows environment block.
///
/// The block is UTF-16 entries of `KEY=value`, each ending in NUL, with an
/// extra NUL after the last entry. Names are compared case-insensitively.
#[must_use]
pub fn env_block_value(block: &[u16], key: &str) -> Option<String> {
    env_block_entries(block).into_iter().find_map(|entry| {
        let eq = entry.iter().position(|unit| *unit == u16::from(b'='))?;
        ascii_key_eq(&entry[..eq], key).then(|| String::from_utf16_lossy(&entry[eq + 1..]))
    })
}

/// Inserts or replaces one variable in a Windows environment block.
pub fn env_block_set(block: &mut Vec<u16>, key: &str, value: &str) {
    let mut entries = env_block_entries(block);
    entries.retain(|entry| {
        let Some(eq) = entry.iter().position(|unit| *unit == u16::from(b'=')) else {
            return true;
        };
        !ascii_key_eq(&entry[..eq], key)
    });
    let mut entry = key.encode_utf16().collect::<Vec<_>>();
    entry.push(u16::from(b'='));
    entry.extend(value.encode_utf16());
    entries.push(entry);
    *block = flatten_env_block(&entries);
}

/// Identifies this process. On Unix the server is always a user install.
///
/// # Errors
///
/// Returns [`ShellAccountError::Windows`] when the process token cannot be read.
// The Windows branch reads the process token, so the function cannot be const.
#[cfg_attr(not(windows), allow(clippy::missing_const_for_fn))]
pub fn current_service_kind() -> Result<ServiceKind, ShellAccountError> {
    #[cfg(windows)]
    {
        if crate::win_shell::is_local_system()? {
            Ok(ServiceKind::System)
        } else {
            Ok(ServiceKind::User)
        }
    }
    #[cfg(not(windows))]
    {
        Ok(ServiceKind::User)
    }
}

/// Opens a shell for `identity`.
///
/// # Errors
///
/// Returns [`ShellAccountError`] when the account or the PTY cannot be created.
pub fn open_shell(
    rows: u16,
    cols: u16,
    identity: ShellIdentity,
    env: &[(String, String)],
    account: Option<&crate::client_account::ClientAccount>,
) -> Result<PtySession, ShellAccountError> {
    match identity {
        ShellIdentity::Process => {
            let mut command = CommandBuilder::new_default_prog();
            for (key, value) in env {
                command.env(key, value);
            }
            PtySession::open_terminal(rows, cols, command).map_err(pty_error)
        }
        ShellIdentity::BoundUser | ShellIdentity::ElevatedUser => {
            let Some(account) = account else {
                return Err(ShellAccountError::UnboundClient);
            };
            #[cfg(windows)]
            {
                crate::win_shell::open_user_terminal(
                    rows,
                    cols,
                    identity == ShellIdentity::ElevatedUser,
                    env,
                    &account.sid,
                    &account.user,
                )
            }
            #[cfg(not(windows))]
            {
                let _ = (rows, cols, env);
                Err(ShellAccountError::Windows(format!(
                    "a shell for {} is only available on Windows",
                    account.label()
                )))
            }
        }
    }
}

fn pty_error(error: PtyError) -> ShellAccountError {
    ShellAccountError::Pty(error.to_string())
}

fn env_block_entries(block: &[u16]) -> Vec<Vec<u16>> {
    let mut entries = Vec::new();
    let mut entry = Vec::new();
    for unit in block {
        if *unit == 0 {
            if entry.is_empty() {
                break;
            }
            entries.push(std::mem::take(&mut entry));
        } else {
            entry.push(*unit);
        }
    }
    entries
}

fn flatten_env_block(entries: &[Vec<u16>]) -> Vec<u16> {
    let mut block = Vec::new();
    for entry in entries {
        block.extend(entry);
        block.push(0);
    }
    block.push(0);
    block
}

fn ascii_upper_unit(unit: u16) -> u16 {
    if unit <= 0x7F {
        u16::from((unit as u8).to_ascii_uppercase())
    } else {
        unit
    }
}

fn ascii_key_eq(units: &[u16], key: &str) -> bool {
    let key: Vec<u16> = key.encode_utf16().collect();
    if units.len() != key.len() {
        return false;
    }
    units
        .iter()
        .zip(key)
        .all(|(unit, key_unit)| ascii_upper_unit(*unit) == ascii_upper_unit(key_unit))
}

/// Builds the `schtasks` arguments for a logon task that runs as the current user.
#[must_use]
pub fn schtasks_create_args(executable: &std::path::Path, server_args: &[String]) -> Vec<String> {
    let mut command = String::new();
    command.push('"');
    command.push_str(&executable.display().to_string().replace('"', "\\\""));
    command.push('"');
    for arg in server_args {
        command.push(' ');
        command.push('"');
        command.push_str(&arg.replace('"', "\\\""));
        command.push('"');
    }
    vec![
        "/Create".to_string(),
        "/F".to_string(),
        "/TN".to_string(),
        LOGON_TASK.to_string(),
        "/IT".to_string(),
        "/SC".to_string(),
        "ONLOGON".to_string(),
        "/RL".to_string(),
        "LIMITED".to_string(),
        "/TR".to_string(),
        command,
    ]
}

/// `schtasks` arguments that stop the user logon task.
#[must_use]
pub fn schtasks_end_args() -> Vec<String> {
    vec![
        "/End".to_string(),
        "/TN".to_string(),
        LOGON_TASK.to_string(),
    ]
}

/// `schtasks` arguments that delete the user logon task.
#[must_use]
pub fn schtasks_delete_args() -> Vec<String> {
    vec![
        "/Delete".to_string(),
        "/F".to_string(),
        "/TN".to_string(),
        LOGON_TASK.to_string(),
    ]
}

/// `schtasks` arguments that start the user logon task now.
#[must_use]
pub fn schtasks_run_args() -> Vec<String> {
    vec![
        "/Run".to_string(),
        "/TN".to_string(),
        LOGON_TASK.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::{
        ServiceKind, ShellIdentity, ShellRequest, env_block_set, env_block_value,
        schtasks_create_args, shell_identity, split_shell_request,
    };
    use crate::client_account::ClientAccount;

    fn bound(sid: &str) -> ClientAccount {
        ClientAccount {
            user: "lyam".to_string(),
            sid: sid.to_string(),
        }
    }

    #[test]
    fn system_service_uses_the_approved_user() {
        let user = bound("S-1-5-21-1");
        let system = bound("S-1-5-18");
        assert_eq!(
            shell_identity(
                ServiceKind::System,
                ShellRequest::Default,
                false,
                Some(&user)
            )
            .unwrap(),
            ShellIdentity::BoundUser
        );
        assert_eq!(
            shell_identity(
                ServiceKind::System,
                ShellRequest::Elevated,
                false,
                Some(&user)
            )
            .unwrap(),
            ShellIdentity::ElevatedUser
        );
        assert!(matches!(
            shell_identity(ServiceKind::System, ShellRequest::Default, false, None),
            Err(super::ShellAccountError::UnboundClient)
        ));
        assert!(matches!(
            shell_identity(
                ServiceKind::System,
                ShellRequest::Default,
                false,
                Some(&system)
            ),
            Err(super::ShellAccountError::RootDisabled)
        ));
        assert_eq!(
            shell_identity(ServiceKind::System, ShellRequest::System, true, None).unwrap(),
            ShellIdentity::Process
        );
        assert!(shell_identity(ServiceKind::System, ShellRequest::System, false, None).is_err());
    }

    #[test]
    fn user_install_cannot_elevate_or_become_system() {
        assert_eq!(
            shell_identity(ServiceKind::User, ShellRequest::Default, false, None).unwrap(),
            ShellIdentity::Process
        );
        assert!(shell_identity(ServiceKind::User, ShellRequest::Elevated, false, None).is_err());
        assert!(shell_identity(ServiceKind::User, ShellRequest::System, true, None).is_err());
        assert!(shell_identity(ServiceKind::User, ShellRequest::Conflict, false, None).is_err());
    }

    #[test]
    fn elevate_marker_is_not_forwarded_to_the_shell() {
        let (request, kept) = split_shell_request(&[
            ("TERM".to_string(), "xterm-256color".to_string()),
            ("ROSE_ELEVATE".to_string(), "1".to_string()),
            ("LANG".to_string(), "en_US.UTF-8".to_string()),
        ]);
        assert_eq!(request, ShellRequest::Elevated);
        assert_eq!(
            kept,
            vec![
                ("TERM".to_string(), "xterm-256color".to_string()),
                ("LANG".to_string(), "en_US.UTF-8".to_string()),
            ]
        );
    }

    #[test]
    fn other_elevate_values_do_not_request_elevation() {
        let (request, kept) =
            split_shell_request(&[("ROSE_ELEVATE".to_string(), "true".to_string())]);
        assert_eq!(request, ShellRequest::Default);
        assert!(kept.is_empty());
        let (request, _) = split_shell_request(&[("ROSE_SYSTEM".to_string(), "1".to_string())]);
        assert_eq!(request, ShellRequest::System);
        let (request, _) = split_shell_request(&[
            ("ROSE_ELEVATE".to_string(), "1".to_string()),
            ("ROSE_SYSTEM".to_string(), "1".to_string()),
        ]);
        assert_eq!(request, ShellRequest::Conflict);
    }

    #[test]
    fn env_block_replaces_term_and_keeps_profile() {
        let mut block = Vec::new();
        env_block_set(&mut block, "USERPROFILE", r"C:\Users\lyam");
        env_block_set(&mut block, "TERM", "dumb");
        env_block_set(&mut block, "term", "xterm-256color");
        assert_eq!(
            env_block_value(&block, "UserProfile").as_deref(),
            Some(r"C:\Users\lyam")
        );
        assert_eq!(
            env_block_value(&block, "TERM").as_deref(),
            Some("xterm-256color")
        );
    }

    #[test]
    fn logon_task_quotes_paths_and_stays_limited() {
        let args = schtasks_create_args(
            std::path::Path::new(r"C:\Users\Lyam\AppData\Local\RoSE\rose.exe"),
            &[
                "server".to_string(),
                "--listen".to_string(),
                "0.0.0.0:4433".to_string(),
                "--config-dir".to_string(),
                r"C:\Users\Lyam\AppData\Roaming\RoSE".to_string(),
            ],
        );
        assert!(args.contains(&"/RL".to_string()));
        assert!(args.contains(&"LIMITED".to_string()));
        assert!(args.contains(&"ONLOGON".to_string()));
        assert!(args.contains(&"/IT".to_string()));
        assert_eq!(
            super::schtasks_delete_args(),
            ["/Delete", "/F", "/TN", "RoSE"].map(str::to_string)
        );
        assert_eq!(
            super::schtasks_run_args(),
            ["/Run", "/TN", "RoSE"].map(str::to_string)
        );
        assert_eq!(
            super::schtasks_end_args(),
            ["/End", "/TN", "RoSE"].map(str::to_string)
        );
        let command = args.last().unwrap();
        assert!(command.starts_with(r#""C:\Users\Lyam\AppData\Local\RoSE\rose.exe""#));
        assert!(command.contains(r#""C:\Users\Lyam\AppData\Roaming\RoSE""#));
    }
}
