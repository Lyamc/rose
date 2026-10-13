//! Bans for repeated authentication failures, and handling for port scans.
//!
//! Failures from one IP address follow `auth_ban_schedule`. The default
//! schedule is 15 minutes, 30 minutes, 60 minutes, then a permanent ban.
//! A permanent ban stays until `rose ctl unban`. Antibot policy is separate:
//! `delay` slows repeat connections that have not authenticated, and `block`
//! bans an address that only scans the port.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::RoseConfig;

const BAN_FILE: &str = "auth_bans.json";

/// How long an address stays banned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanLength {
    /// Ban ends after this duration.
    Timed(Duration),
    /// Ban stays until it is cleared.
    Permanent,
}

/// What to do with an address that connects without authenticating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Antibot {
    /// No extra delay or probe ban.
    Off,
    /// Slow the handshake. A successful login clears the delay.
    Delay,
    /// Ban the address after repeated connections that never log in.
    Block,
}

/// Ban and antibot settings copied from `config.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardSettings {
    /// Failures inside the window before the next ban.
    pub ban_after: u32,
    /// How long a failure keeps counting.
    pub window: Duration,
    /// Ban lengths. Empty disables fail2ban.
    pub schedule: Vec<BanLength>,
    /// Port-scan behavior.
    pub antibot: Antibot,
    /// First delay applied to a repeat unauthenticated address.
    pub delay: Duration,
    /// Upper bound on that delay.
    pub delay_cap: Duration,
    /// Unauthenticated connections before `block` bans the address.
    pub probe_limit: u32,
}

impl GuardSettings {
    /// Reads the guard fields from server config.
    #[must_use]
    pub fn from_config(config: &RoseConfig) -> Self {
        let schedule = parse_schedule(&config.auth_ban_schedule).unwrap_or_else(|()| {
            tracing::warn!(
                schedule = %config.auth_ban_schedule,
                "auth_ban_schedule is invalid; authentication bans are disabled"
            );
            Vec::new()
        });
        let antibot = parse_antibot(&config.antibot).unwrap_or_else(|()| {
            tracing::warn!(
                antibot = %config.antibot,
                "antibot is invalid; port-scan handling is off"
            );
            Antibot::Off
        });
        Self {
            ban_after: config.auth_ban_after.max(1),
            window: Duration::from_secs(config.auth_ban_window_secs.max(1)),
            schedule,
            antibot,
            delay: Duration::from_millis(config.antibot_delay_ms),
            delay_cap: Duration::from_millis(
                config.antibot_delay_cap_ms.max(config.antibot_delay_ms),
            ),
            probe_limit: config.antibot_probe_limit.max(1),
        }
    }

    const fn bans_enabled(&self) -> bool {
        !self.schedule.is_empty()
    }
}

/// Result of checking one address before or after a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    /// Continue the handshake.
    Allow,
    /// Wait, then continue. The delay ends after a successful login.
    Delay(Duration),
    /// Refuse this address.
    Banned(BanLength),
}

/// Parses `15m,30m,60m,-1`. `none` and `off` disable bans.
///
/// # Errors
///
/// Returns an error when a token is not a duration or `-1`.
pub fn parse_schedule(text: &str) -> Result<Vec<BanLength>, ()> {
    let text = text.trim();
    if text.is_empty() || text.eq_ignore_ascii_case("none") || text.eq_ignore_ascii_case("off") {
        return Ok(Vec::new());
    }
    text.split(',')
        .map(|token| parse_ban_token(token.trim()))
        .collect()
}

/// Parses `off`, `delay`, or `block`.
///
/// # Errors
///
/// Returns an error for any other word.
pub fn parse_antibot(text: &str) -> Result<Antibot, ()> {
    match text.trim().to_ascii_lowercase().as_str() {
        "off" | "none" | "false" => Ok(Antibot::Off),
        "delay" | "latency" | "tarpit" => Ok(Antibot::Delay),
        "block" | "ban" => Ok(Antibot::Block),
        _ => Err(()),
    }
}

/// Canonical text for a schedule, suitable for `config.toml`.
#[must_use]
pub fn format_schedule(schedule: &[BanLength]) -> String {
    if schedule.is_empty() {
        return "none".to_string();
    }
    schedule
        .iter()
        .map(|length| match length {
            BanLength::Permanent => "-1".to_string(),
            BanLength::Timed(duration) => format_duration(*duration),
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// True when a session error is a rejected login rather than a timeout.
#[must_use]
pub fn is_credential_failure(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("invalid totp")
        || message.contains("not authorized")
        || message.contains("certificate required")
        || message.contains("unknownissuer")
}

/// Decides whether a new connection from `ip` may proceed.
pub fn begin_connection(
    dir: &Path,
    settings: &GuardSettings,
    ip: IpAddr,
    now: SystemTime,
) -> Access {
    let guard = Guard::load(dir);
    guard.begin(settings, ip, now)
}

/// Records a handshake that never became an authenticated session.
pub fn rejected_handshake(
    dir: &Path,
    settings: &GuardSettings,
    ip: IpAddr,
    now: SystemTime,
) -> Access {
    let mut guard = Guard::load(dir);
    let access = guard.rejected(settings, ip, now);
    guard.save(dir);
    access
}

/// Records a wrong certificate or TOTP code.
pub fn auth_failure(dir: &Path, settings: &GuardSettings, ip: IpAddr, now: SystemTime) -> Access {
    let mut guard = Guard::load(dir);
    let access = guard.fail_auth(settings, ip, now);
    guard.save(dir);
    access
}

/// Clears the failure and port-scan counters after a successful login.
///
/// The ban ladder is kept, so the next ban is longer.
pub fn auth_success(dir: &Path, ip: IpAddr, now: SystemTime) {
    let mut guard = Guard::load(dir);
    guard.succeed(ip, now);
    guard.save(dir);
}

/// Removes one address. Returns whether it was present.
pub fn clear_ban(dir: &Path, ip: IpAddr) -> bool {
    let mut guard = Guard::load(dir);
    let removed = guard.entries.remove(&ip.to_string()).is_some();
    if removed {
        guard.save(dir);
    }
    removed
}

/// Removes every ban and failure counter.
pub fn clear_bans(dir: &Path) {
    let mut guard = Guard::load(dir);
    guard.entries.clear();
    guard.save(dir);
}

/// Text for `rose ctl bans`.
#[must_use]
pub fn list_bans(dir: &Path, now: SystemTime) -> String {
    let guard = Guard::load(dir);
    if guard.entries.is_empty() {
        return "no authentication bans\n".to_string();
    }
    let mut out = String::from("authentication bans:\n");
    for (ip, record) in &guard.entries {
        out.push_str("  ");
        out.push_str(ip);
        out.push_str("  ");
        if record.permanent {
            out.push_str("permanent");
        } else if let Some(until) = record.banned_until_unix.and_then(unix_time) {
            if until > now {
                out.push_str("banned for ");
                out.push_str(&format_duration(
                    until.duration_since(now).unwrap_or_default(),
                ));
            } else {
                out.push_str(&format!("{} failures", record.failures));
            }
        } else {
            out.push_str(&format!("{} failures", record.failures));
        }
        out.push('\n');
    }
    out
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Guard {
    entries: BTreeMap<String, Record>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct Record {
    #[serde(default)]
    failures: u32,
    #[serde(default)]
    last_failure_unix: Option<u64>,
    #[serde(default)]
    ban_step: usize,
    #[serde(default)]
    banned_until_unix: Option<u64>,
    #[serde(default)]
    permanent: bool,
    #[serde(default)]
    probes: u32,
    #[serde(default)]
    last_probe_unix: Option<u64>,
}

impl Guard {
    fn load(dir: &Path) -> Self {
        let path = dir.join(BAN_FILE);
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Self::default();
        };
        serde_json::from_str(&text).unwrap_or_else(|_| {
            tracing::warn!(path = %path.display(), "ignoring an unreadable auth ban file");
            Self::default()
        })
    }

    fn save(&self, dir: &Path) {
        let path = dir.join(BAN_FILE);
        if self.entries.is_empty() {
            let _ = std::fs::remove_file(&path);
            return;
        }
        let Ok(text) = serde_json::to_string_pretty(&self) else {
            return;
        };
        if let Err(error) = std::fs::create_dir_all(dir) {
            tracing::warn!(%error, "could not create the directory for authentication bans");
            return;
        }
        if let Err(error) = std::fs::write(&path, text) {
            tracing::warn!(%error, path = %path.display(), "could not store authentication bans");
        }
    }

    fn begin(&self, settings: &GuardSettings, ip: IpAddr, now: SystemTime) -> Access {
        if let Some(ban) = self.ban_status(&ip.to_string(), now) {
            return Access::Banned(ban);
        }
        if settings.antibot == Antibot::Delay {
            let probes = fresh_probes(self.entries.get(&ip.to_string()), now, settings.window);
            let delay = scaled_delay(probes, settings.delay, settings.delay_cap);
            if !delay.is_zero() {
                return Access::Delay(delay);
            }
        }
        Access::Allow
    }

    fn rejected(&mut self, settings: &GuardSettings, ip: IpAddr, now: SystemTime) -> Access {
        let key = ip.to_string();
        if let Some(ban) = self.ban_status(&key, now) {
            return Access::Banned(ban);
        }
        self.bump(&key, now, settings.window, true, true);
        self.finish(settings, &key, now)
    }

    fn fail_auth(&mut self, settings: &GuardSettings, ip: IpAddr, now: SystemTime) -> Access {
        let key = ip.to_string();
        if let Some(ban) = self.ban_status(&key, now) {
            return Access::Banned(ban);
        }
        self.bump(&key, now, settings.window, true, false);
        if let Some(record) = self.entries.get_mut(&key) {
            record.probes = 0;
            record.last_probe_unix = None;
        }
        self.finish(settings, &key, now)
    }

    fn succeed(&mut self, ip: IpAddr, now: SystemTime) {
        let key = ip.to_string();
        if self.ban_status(&key, now).is_some() {
            return;
        }
        if let Some(record) = self.entries.get_mut(&key) {
            record.failures = 0;
            record.last_failure_unix = None;
            record.probes = 0;
            record.last_probe_unix = None;
            record.banned_until_unix = None;
            if record.ban_step == 0 {
                self.entries.remove(&key);
            }
        }
    }

    fn finish(&mut self, settings: &GuardSettings, key: &str, now: SystemTime) -> Access {
        let Some(record) = self.entries.get(key) else {
            return Access::Allow;
        };
        let auth_hit = settings.bans_enabled() && record.failures >= settings.ban_after;
        let probe_hit = settings.antibot == Antibot::Block && record.probes >= settings.probe_limit;
        if auth_hit || probe_hit {
            let length = self.apply_ban(settings, key, now);
            return Access::Banned(length);
        }
        Access::Allow
    }

    fn apply_ban(&mut self, settings: &GuardSettings, key: &str, now: SystemTime) -> BanLength {
        let step = self.entries.get(key).map_or(0, |record| record.ban_step);
        let length = ban_at(settings, step);
        let record = self.entries.entry(key.to_string()).or_insert(Record {
            failures: 0,
            last_failure_unix: None,
            ban_step: 0,
            banned_until_unix: None,
            permanent: false,
            probes: 0,
            last_probe_unix: None,
        });
        match &length {
            BanLength::Permanent => {
                record.permanent = true;
                record.banned_until_unix = None;
            }
            BanLength::Timed(duration) => {
                record.permanent = false;
                record.banned_until_unix = Some(unix_secs(now + *duration));
            }
        }
        if settings.schedule.len() > 1 {
            record.ban_step = step.saturating_add(1).min(settings.schedule.len() - 1);
        }
        record.failures = 0;
        record.probes = 0;
        record.last_failure_unix = None;
        record.last_probe_unix = None;
        length
    }

    fn bump(&mut self, key: &str, now: SystemTime, window: Duration, failure: bool, probe: bool) {
        let record = self.entries.entry(key.to_string()).or_insert(Record {
            failures: 0,
            last_failure_unix: None,
            ban_step: 0,
            banned_until_unix: None,
            permanent: false,
            probes: 0,
            last_probe_unix: None,
        });
        if failure {
            if stale(record.last_failure_unix, now, window) {
                record.failures = 0;
            }
            record.failures = record.failures.saturating_add(1);
            record.last_failure_unix = Some(unix_secs(now));
        }
        if probe {
            if stale(record.last_probe_unix, now, window) {
                record.probes = 0;
            }
            record.probes = record.probes.saturating_add(1);
            record.last_probe_unix = Some(unix_secs(now));
        }
    }

    fn ban_status(&self, key: &str, now: SystemTime) -> Option<BanLength> {
        let record = self.entries.get(key)?;
        if record.permanent {
            return Some(BanLength::Permanent);
        }
        let until = unix_time(record.banned_until_unix?)?;
        if until > now {
            Some(BanLength::Timed(
                until.duration_since(now).unwrap_or_default(),
            ))
        } else {
            None
        }
    }
}

fn ban_at(settings: &GuardSettings, step: usize) -> BanLength {
    if settings.schedule.is_empty() {
        return BanLength::Timed(settings.window);
    }
    settings.schedule.get(step).cloned().unwrap_or_else(|| {
        settings
            .schedule
            .last()
            .cloned()
            .unwrap_or(BanLength::Permanent)
    })
}

fn scaled_delay(probes: u32, base: Duration, cap: Duration) -> Duration {
    if probes == 0 || base.is_zero() {
        return Duration::ZERO;
    }
    let shift = (probes - 1).min(10);
    let factor = 1u32 << shift;
    base.checked_mul(factor).unwrap_or(cap).min(cap)
}

fn fresh_probes(record: Option<&Record>, now: SystemTime, window: Duration) -> u32 {
    let Some(record) = record else {
        return 0;
    };
    if stale(record.last_probe_unix, now, window) {
        0
    } else {
        record.probes
    }
}

fn stale(previous: Option<u64>, now: SystemTime, window: Duration) -> bool {
    let Some(previous) = previous.and_then(unix_time) else {
        return false;
    };
    now.duration_since(previous).unwrap_or_default() > window
}

fn parse_ban_token(token: &str) -> Result<BanLength, ()> {
    if token == "-1" || token.eq_ignore_ascii_case("permanent") {
        return Ok(BanLength::Permanent);
    }
    let unit_at = token
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(token.len());
    let (number, unit) = token.split_at(unit_at);
    let value: u64 = number.parse().map_err(|_| ())?;
    let seconds = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "s" | "sec" | "secs" | "second" | "seconds" => value,
        "m" | "min" | "mins" | "minute" | "minutes" => value.saturating_mul(60),
        "h" | "hr" | "hrs" | "hour" | "hours" => value.saturating_mul(60 * 60),
        "d" | "day" | "days" => value.saturating_mul(24 * 60 * 60),
        _ => return Err(()),
    };
    if seconds == 0 {
        return Err(());
    }
    Ok(BanLength::Timed(Duration::from_secs(seconds)))
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    if seconds >= 86_400 && seconds.is_multiple_of(86_400) {
        format!("{}d", seconds / 86_400)
    } else if seconds >= 3_600 && seconds.is_multiple_of(3_600) {
        format!("{}h", seconds / 3_600)
    } else if seconds >= 60 && seconds.is_multiple_of(60) {
        format!("{}m", seconds / 60)
    } else {
        format!("{seconds}s")
    }
}

fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn unix_time(seconds: u64) -> Option<SystemTime> {
    UNIX_EPOCH.checked_add(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use super::{
        Access, Antibot, BanLength, GuardSettings, auth_failure, auth_success, begin_connection,
        clear_ban, clear_bans, is_credential_failure, list_bans, parse_antibot, parse_schedule,
        rejected_handshake,
    };

    fn settings(antibot: Antibot, after: u32, probes: u32) -> GuardSettings {
        GuardSettings {
            ban_after: after,
            window: Duration::from_secs(15 * 60),
            schedule: parse_schedule("15m,30m,60m,-1").unwrap(),
            antibot,
            delay: Duration::from_secs(2),
            delay_cap: Duration::from_secs(8),
            probe_limit: probes,
        }
    }

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_700_000_000 + seconds)
    }

    fn ip() -> IpAddr {
        "203.0.113.5".parse().unwrap()
    }

    #[test]
    fn default_schedule_doubles_until_permanent() {
        let schedule = parse_schedule("15m, 30m, 60m, -1").unwrap();
        assert_eq!(
            schedule,
            vec![
                BanLength::Timed(Duration::from_secs(15 * 60)),
                BanLength::Timed(Duration::from_secs(30 * 60)),
                BanLength::Timed(Duration::from_secs(60 * 60)),
                BanLength::Permanent,
            ]
        );
        assert!(parse_schedule("none").unwrap().is_empty());
        assert!(parse_schedule("15 fortnights").is_err());
        assert_eq!(parse_antibot("latency").unwrap(), Antibot::Delay);
        assert_eq!(parse_antibot("ban").unwrap(), Antibot::Block);
        assert!(parse_antibot("maybe").is_err());
    }

    #[test]
    fn failures_climb_the_ban_ladder_and_ignore_attempts_during_a_ban() {
        let dir = tempfile::tempdir().unwrap();
        let settings = settings(Antibot::Off, 2, 5);
        let address = ip();
        assert_eq!(
            auth_failure(dir.path(), &settings, address, at(0)),
            Access::Allow
        );
        assert_eq!(
            auth_failure(dir.path(), &settings, address, at(10)),
            Access::Banned(BanLength::Timed(Duration::from_secs(15 * 60)))
        );
        assert_eq!(
            auth_failure(dir.path(), &settings, address, at(20)),
            Access::Banned(BanLength::Timed(Duration::from_secs(15 * 60 - 10)))
        );
        assert_eq!(
            begin_connection(dir.path(), &settings, address, at(10 + 15 * 60)),
            Access::Allow
        );
        auth_success(dir.path(), address, at(10 + 15 * 60));
        assert_eq!(
            auth_failure(dir.path(), &settings, address, at(911)),
            Access::Allow
        );
        assert_eq!(
            auth_failure(dir.path(), &settings, address, at(912)),
            Access::Banned(BanLength::Timed(Duration::from_secs(30 * 60)))
        );
        let later = 912 + 30 * 60;
        assert_eq!(
            auth_failure(dir.path(), &settings, address, at(later)),
            Access::Allow
        );
        assert_eq!(
            auth_failure(dir.path(), &settings, address, at(later + 1)),
            Access::Banned(BanLength::Timed(Duration::from_secs(60 * 60)))
        );
        let after_hour = later + 1 + 60 * 60;
        assert_eq!(
            auth_failure(dir.path(), &settings, address, at(after_hour)),
            Access::Allow
        );
        assert_eq!(
            auth_failure(dir.path(), &settings, address, at(after_hour + 1)),
            Access::Banned(BanLength::Permanent)
        );
        assert_eq!(
            begin_connection(dir.path(), &settings, address, at(after_hour + 10_000)),
            Access::Banned(BanLength::Permanent)
        );
        let listed = list_bans(dir.path(), at(after_hour + 10_000));
        assert!(listed.contains("203.0.113.5"), "{listed}");
        assert!(listed.contains("permanent"), "{listed}");
        assert!(clear_ban(dir.path(), address));
        assert!(!clear_ban(dir.path(), address));
        assert_eq!(
            begin_connection(dir.path(), &settings, address, at(after_hour + 10_000)),
            Access::Allow
        );
    }

    #[test]
    fn failures_outside_the_window_do_not_add_up() {
        let dir = tempfile::tempdir().unwrap();
        let settings = settings(Antibot::Off, 2, 5);
        let address = ip();
        assert_eq!(
            auth_failure(dir.path(), &settings, address, at(0)),
            Access::Allow
        );
        assert_eq!(
            auth_failure(dir.path(), &settings, address, at(15 * 60 + 1)),
            Access::Allow
        );
    }

    #[test]
    fn delay_grows_until_a_login_clears_it() {
        let dir = tempfile::tempdir().unwrap();
        let settings = settings(Antibot::Delay, 100, 100);
        let address = ip();
        assert_eq!(
            begin_connection(dir.path(), &settings, address, at(0)),
            Access::Allow
        );
        assert_eq!(
            rejected_handshake(dir.path(), &settings, address, at(1)),
            Access::Allow
        );
        assert_eq!(
            begin_connection(dir.path(), &settings, address, at(2)),
            Access::Delay(Duration::from_secs(2))
        );
        rejected_handshake(dir.path(), &settings, address, at(3));
        assert_eq!(
            begin_connection(dir.path(), &settings, address, at(4)),
            Access::Delay(Duration::from_secs(4))
        );
        rejected_handshake(dir.path(), &settings, address, at(5));
        assert_eq!(
            begin_connection(dir.path(), &settings, address, at(6)),
            Access::Delay(Duration::from_secs(8))
        );
        auth_success(dir.path(), address, at(7));
        assert_eq!(
            begin_connection(dir.path(), &settings, address, at(8)),
            Access::Allow
        );
    }

    #[test]
    fn block_bans_repeated_port_checks_that_never_log_in() {
        let dir = tempfile::tempdir().unwrap();
        let settings = settings(Antibot::Block, 100, 2);
        let address = ip();
        assert_eq!(
            rejected_handshake(dir.path(), &settings, address, at(0)),
            Access::Allow
        );
        assert_eq!(
            rejected_handshake(dir.path(), &settings, address, at(1)),
            Access::Banned(BanLength::Timed(Duration::from_secs(15 * 60)))
        );
        clear_bans(dir.path());
        assert!(list_bans(dir.path(), at(2)).contains("no authentication bans"));
    }

    #[test]
    fn credential_errors_are_not_timeouts() {
        assert!(is_credential_failure("invalid TOTP code"));
        assert!(is_credential_failure(
            "client certificate is not authorized"
        ));
        assert!(is_credential_failure("client certificate required"));
        assert!(!is_credential_failure("authorization timed out"));
        assert!(!is_credential_failure("Windows user lyam is not logged on"));
    }
}
