//! Login and pairing messages.
//!
//! Every attempt is written to the tracing log. On Windows the same text is
//! an Application information event when `windows_event_log` is true.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

/// One line describing a login attempt.
#[must_use]
pub fn login_message(
    result: &str,
    peer: SocketAddr,
    local: Option<IpAddr>,
    who: &str,
    detail: &str,
) -> String {
    let via = match local {
        Some(ip) => ip.to_string(),
        None => "unknown interface".to_string(),
    };
    format!("RoSE login {result} from {peer} via {via} as {who}: {detail}")
}

/// One line describing a pairing approval.
#[must_use]
pub fn pairing_message(user: &str, sid: &str, code: &str, cert: &Path) -> String {
    let sid = if sid.is_empty() { "no sid" } else { sid };
    format!(
        "RoSE approved pairing code {code} for Windows user {user} ({sid}). Certificate {}.",
        cert.display()
    )
}

/// Writes `message` to tracing and, on Windows, to the Application event log.
pub fn emit(enabled: bool, message: &str) {
    tracing::info!(windows_event_log = enabled, "{message}");
    #[cfg(windows)]
    if enabled {
        win_event::report_info(message);
    }
}

#[cfg(windows)]
mod win_event {
    use std::ptr;

    use windows_sys::Win32::System::EventLog::{
        DeregisterEventSource, EVENTLOG_INFORMATION_TYPE, RegisterEventSourceW, ReportEventW,
    };

    /// COVERAGE: The event log exists only on Windows.
    #[cfg_attr(coverage_nightly, coverage(off))]
    // RegisterEventSourceW and ReportEventW have no safe wrapper in this crate.
    #[allow(unsafe_code)]
    pub(super) fn report_info(message: &str) {
        let source = wide("RoSE");
        let text = wide(message);
        unsafe {
            let handle = RegisterEventSourceW(ptr::null(), source.as_ptr());
            if handle.is_null() {
                return;
            }
            let strings = [text.as_ptr()];
            ReportEventW(
                handle,
                EVENTLOG_INFORMATION_TYPE,
                0,
                1,
                ptr::null_mut(),
                1,
                0,
                strings.as_ptr(),
                ptr::null(),
            );
            DeregisterEventSource(handle);
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::path::Path;

    use super::{login_message, pairing_message};

    #[test]
    fn login_and_pairing_messages_include_who_and_where() {
        let peer: SocketAddr = "203.0.113.5:4433".parse().unwrap();
        let login = login_message(
            "failed",
            peer,
            Some("192.0.2.10".parse().unwrap()),
            "lyam (S-1-5-21-1)",
            "invalid TOTP code",
        );
        assert!(login.contains("failed"), "{login}");
        assert!(login.contains("203.0.113.5:4433"), "{login}");
        assert!(login.contains("192.0.2.10"), "{login}");
        assert!(login.contains("lyam (S-1-5-21-1)"), "{login}");
        assert!(login.contains("invalid TOTP code"), "{login}");
        let unknown = login_message("ok", peer, None, "unknown client", "session opened");
        assert!(unknown.contains("unknown interface"), "{unknown}");
        let pairing = pairing_message(
            "lyam",
            "",
            "1234",
            Path::new(r"C:\ProgramData\RoSE\authorized_certs\1234.crt"),
        );
        assert!(pairing.contains("1234"), "{pairing}");
        assert!(pairing.contains("lyam"), "{pairing}");
        assert!(pairing.contains("no sid"), "{pairing}");
        assert!(pairing.contains("1234.crt"), "{pairing}");
    }
}
