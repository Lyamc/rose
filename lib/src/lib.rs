#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! `RoSE` — Remote Shell Environment.
//!
//! A modern replacement for Mosh built on QUIC and wezterm's terminal emulator.

mod auth_guard;
pub mod cli;
mod client_account;
pub mod config;
mod input;
pub mod protocol;
pub mod pty;
#[cfg(unix)]
mod pty_io;
pub mod scrollback;
mod security_log;
pub mod session;
mod shell_account;
pub mod sso;
pub mod ssp;
pub mod stun;
pub mod terminal;
pub mod totp;
pub mod transport;

#[cfg(windows)]
#[allow(unsafe_code)] // Win32 token and process APIs have no safe wrapper.
mod win_shell;

#[cfg(test)]
pub(crate) mod testutil;
