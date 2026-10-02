//! CLI entry point for the `rose` binary.
//!
//! This module contains all command-line parsing, server/client loop logic,
//! and SSH bootstrap mode. The actual binary is a thin wrapper that calls
//! [`run`].

mod client;
mod input;
mod keygen;
mod server;
mod service;
mod ssh_bootstrap;
mod util;

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// `RoSE` — Remote Shell Environment.
#[derive(Parser)]
#[command(name = "rose", version, about)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands.
#[derive(Subcommand)]
enum Commands {
    /// Connect to a remote host.
    Connect {
        /// The host to connect to (hostname or IP).
        host: String,

        /// Port to connect to.
        #[arg(long, default_value = "4433")]
        port: u16,

        /// Path to the server's certificate (DER format).
        #[arg(long)]
        cert: Option<PathBuf>,

        /// Reattach to a detached session using its 32-digit hexadecimal ID.
        #[arg(long, value_parser = parse_session_id, conflicts_with = "ssh")]
        session: Option<[u8; 16]>,

        /// Use SSH bootstrap mode instead of native mode.
        #[arg(long)]
        ssh: bool,

        /// Path to the `rose` binary on the remote server (for `--ssh` mode).
        #[arg(long, default_value = "rose")]
        server_binary: String,

        /// Skip direct UDP and force STUN hole-punching (for testing).
        #[arg(long)]
        force_stun: bool,

        /// SSH port to connect to (for `--ssh` mode). Defaults to SSH's own default (22).
        #[arg(long)]
        ssh_port: Option<u16>,

        /// Extra options to pass to the SSH command (for `--ssh` mode).
        /// Can be specified multiple times, e.g. `--ssh-option StrictHostKeyChecking=no`.
        #[arg(long)]
        ssh_option: Vec<String>,

        /// Path to a client certificate for mutual TLS (DER format).
        /// Used for reattaching to a bootstrapped session after detach.
        #[arg(long)]
        client_cert: Option<PathBuf>,
    },
    /// Run the `RoSE` server daemon.
    Server {
        /// Address to listen on.
        #[arg(long, default_value = "0.0.0.0:4433")]
        listen: SocketAddr,

        /// Bootstrap mode: read client cert from stdin, bind random port,
        /// print `ROSE_BOOTSTRAP` line to stdout.
        #[arg(long)]
        bootstrap: bool,

        /// Hostnames to include in the server certificate's Subject Alternative Names.
        /// Defaults to "localhost". Add your server's hostname or IP for proper
        /// TLS hostname verification in native mode.
        #[arg(long)]
        hostname: Vec<String>,
    },
    /// Generate X.509 client certificates for authentication.
    Keygen,
    /// Install or remove the Windows service and its firewall rule.
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

/// Windows service lifecycle commands.
#[derive(Subcommand)]
enum ServiceAction {
    /// Copy `rose`, register the auto-start service, and allow its UDP port.
    Install {
        /// Address the service listens on.
        #[arg(long, default_value = "0.0.0.0:4433")]
        listen: SocketAddr,

        /// Hostnames to include in the server certificate's Subject Alternative Names.
        #[arg(long)]
        hostname: Vec<String>,
    },
    /// Stop the service, remove the firewall rule, and delete the installed binary.
    Uninstall,
    /// Service Control Manager entry point.
    #[command(hide = true)]
    Run {
        /// Address the service listens on.
        #[arg(long, default_value = "0.0.0.0:4433")]
        listen: SocketAddr,

        /// Hostnames to include in the server certificate's Subject Alternative Names.
        #[arg(long)]
        hostname: Vec<String>,

        /// Directory for the service certificate, config, and log.
        #[arg(long)]
        config_dir: PathBuf,
    },
}

fn parse_session_id(value: &str) -> Result<[u8; 16], String> {
    if value.len() != 32 || !value.is_ascii() {
        return Err("session ID must contain 32 hexadecimal digits".into());
    }
    util::hex_decode(value)
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "session ID must contain 32 hexadecimal digits".into())
}

/// Starts the Windows service dispatcher on this thread.
///
/// The binary calls this from `main` before starting tokio. Windows requires
/// the service control dispatcher on the process main thread.
///
/// # Errors
///
/// Returns an error when the arguments are not `service run`, or when the
/// Service Control Manager rejects the process.
///
/// COVERAGE: CLI entry point; the dispatcher requires the Service Control Manager.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn run_service() -> anyhow::Result<()> {
    init_tracing(service::service_log_path(
        &std::env::args().collect::<Vec<_>>(),
    ));
    let cli = Cli::parse();
    match cli.command {
        Commands::Service {
            action:
                ServiceAction::Run {
                    listen,
                    hostname,
                    config_dir,
                },
        } => service::run(listen, hostname, config_dir),
        _ => anyhow::bail!("rose service run was invoked with unexpected arguments"),
    }
}

/// Parses CLI arguments and runs the appropriate subcommand.
///
/// This is the main entry point for the `rose` binary. Call this from
/// a `#[tokio::main]` function. `service run` is the exception: call
/// [`run_service`] from `main` so the dispatcher stays on the main thread.
///
/// # Errors
///
/// Returns an error if the subcommand fails.
///
/// COVERAGE: CLI entry point; logic tested via integration/e2e tests.
#[cfg_attr(coverage_nightly, coverage(off))]
pub async fn run() -> anyhow::Result<()> {
    init_tracing(service::service_log_path(
        &std::env::args().collect::<Vec<_>>(),
    ));

    let cli = Cli::parse();

    match cli.command {
        Commands::Connect {
            host,
            port,
            cert,
            session,
            ssh,
            server_binary,
            force_stun,
            ssh_port,
            ssh_option,
            client_cert,
        } => {
            if ssh {
                ssh_bootstrap::run_ssh_bootstrap(
                    &host,
                    &server_binary,
                    force_stun,
                    ssh_port,
                    &ssh_option,
                )
                .await
            } else {
                client::run_client(&host, port, cert, client_cert, session).await
            }
        }
        Commands::Server {
            listen,
            bootstrap,
            hostname,
        } => server::run_server(listen, bootstrap, hostname).await,
        Commands::Keygen => keygen::run_keygen(),
        Commands::Service { action } => match action {
            ServiceAction::Install { listen, hostname } => service::install(listen, hostname),
            ServiceAction::Uninstall => service::uninstall(),
            ServiceAction::Run {
                listen,
                hostname,
                config_dir,
            } => service::run(listen, hostname, config_dir),
        },
    }
}

fn init_tracing(log_file: Option<PathBuf>) {
    let default_filter = if log_file.is_some() { "info" } else { "error" };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_filter));
    if let Some(path) = log_file
        && let Some(parent) = path.parent()
        && std::fs::create_dir_all(parent).is_ok()
        && let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(std::sync::Mutex::new(file))
            .init();
        return;
    }
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn parse_native_session() {
        let cli = Cli::try_parse_from([
            "rose",
            "connect",
            "host",
            "--session",
            "00112233445566778899aAbBcCdDeEfF",
        ])
        .unwrap();
        let Commands::Connect { session, .. } = cli.command else {
            panic!("expected connect");
        };
        assert_eq!(
            session,
            Some([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ])
        );
    }

    #[test]
    fn reject_invalid_session_arguments() {
        for invalid in [
            "short",
            "gg112233445566778899aabbccddeeff",
            "éééééééééééééééé",
        ] {
            assert!(
                Cli::try_parse_from(["rose", "connect", "host", "--session", invalid]).is_err()
            );
        }
        assert!(
            Cli::try_parse_from([
                "rose",
                "connect",
                "host",
                "--ssh",
                "--session",
                "00112233445566778899aabbccddeeff",
            ])
            .is_err()
        );
    }

    #[test]
    fn parse_service_install_and_uninstall() {
        let install = Cli::try_parse_from([
            "rose",
            "service",
            "install",
            "--listen",
            "192.0.2.10:4433",
            "--hostname",
            "rose.example",
        ])
        .unwrap();
        let Commands::Service { action } = install.command else {
            panic!("expected service");
        };
        let ServiceAction::Install { listen, hostname } = action else {
            panic!("expected install");
        };
        assert_eq!(listen, "192.0.2.10:4433".parse().unwrap());
        assert_eq!(hostname, vec!["rose.example".to_string()]);

        let uninstall = Cli::try_parse_from(["rose", "service", "uninstall"]).unwrap();
        assert!(matches!(
            uninstall.command,
            Commands::Service {
                action: ServiceAction::Uninstall
            }
        ));
    }
}
