//! Install and remove the `RoSE` server as a Windows service.
//!
//! `rose service install` copies this binary, registers an auto-start service,
//! and adds an inbound UDP firewall rule for the listen port. `rose service
//! uninstall` stops the service, deletes that rule, and removes the copied
//! binary. Configuration under the service data directory is left in place.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

/// Service Control Manager name.
pub(super) const SERVICE_NAME: &str = "RoSE";

/// Name shown in the Services snap-in.
pub(super) const SERVICE_DISPLAY_NAME: &str = "RoSE Server";

/// Description stored on the service.
pub(super) const SERVICE_DESCRIPTION: &str =
    "Remote Shell Environment server. Accepts QUIC on UDP and runs sessions as LocalSystem.";

/// Stable Windows Firewall rule name.
pub(super) const FIREWALL_RULE_NAME: &str = "RoSE";

/// Firewall rule name shown in Windows Defender Firewall.
pub(super) const FIREWALL_RULE_DISPLAY: &str = "RoSE Server";

/// Directory created under Program Files and `ProgramData`.
const DATA_DIR_NAME: &str = "RoSE";

/// File name of the installed server binary.
const EXECUTABLE_NAME: &str = "rose.exe";

/// Win32 `ERROR_ACCESS_DENIED`.
#[cfg(windows)]
const ERROR_ACCESS_DENIED: i32 = 5;

/// Win32 `ERROR_SERVICE_DOES_NOT_EXIST`.
#[cfg(windows)]
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;

/// Win32 `ERROR_SERVICE_NOT_ACTIVE`.
#[cfg(windows)]
const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;

/// Win32 `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`.
#[cfg(windows)]
const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;

/// Where the service binary and its data are stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ServiceLayout {
    /// Directory that contains [`EXECUTABLE_NAME`].
    pub install_dir: PathBuf,
    /// Full path of the installed `rose.exe`.
    pub executable: PathBuf,
    /// Certificate and config directory (`ROSE` data root).
    pub config_dir: PathBuf,
}

/// Install parameters derived from the listen address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InstallPlan {
    /// Filesystem locations.
    pub layout: ServiceLayout,
    /// Arguments passed by the Service Control Manager. The executable path is separate.
    pub launch_arguments: Vec<String>,
    /// PowerShell that replaces the inbound UDP firewall rule.
    pub firewall_script: String,
    /// Text printed after a successful install.
    pub summary: String,
}

/// The listen port was 0, so there is no firewall port to open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ListenPortError;

impl std::fmt::Display for ListenPortError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the service listen port must not be 0")
    }
}

impl std::error::Error for ListenPortError {}

/// Resolves the Windows install and data directories.
#[must_use]
pub(super) fn service_layout(program_files: &Path, program_data: &Path) -> ServiceLayout {
    let install_dir = program_files.join(DATA_DIR_NAME);
    ServiceLayout {
        executable: install_dir.join(EXECUTABLE_NAME),
        install_dir,
        config_dir: program_data.join(DATA_DIR_NAME),
    }
}

/// Builds the service command line, firewall script, and user-facing summary.
///
/// # Errors
///
/// Returns [`ListenPortError`] when `listen` uses port 0.
pub(super) fn prepare_install(
    program_files: &Path,
    program_data: &Path,
    listen: SocketAddr,
    hostnames: &[String],
) -> Result<InstallPlan, ListenPortError> {
    let port = listen.port();
    if port == 0 {
        return Err(ListenPortError);
    }
    let layout = service_layout(program_files, program_data);
    let launch_arguments = launch_arguments(listen, &layout.config_dir, hostnames);
    let local_ip = specified_ip(listen.ip());
    let firewall_script = firewall_replace_script(port, &layout.executable, local_ip.as_deref());
    let summary = install_summary(&layout, listen);
    Ok(InstallPlan {
        layout,
        launch_arguments,
        firewall_script,
        summary,
    })
}

/// Arguments for `sc.exe failure` so a crashed service restarts up to three times.
#[must_use]
pub(super) fn service_failure_args(service_name: &str) -> Vec<String> {
    [
        "failure",
        service_name,
        "reset=",
        "86400",
        "actions=",
        "restart/5000/restart/5000/restart/5000",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// Log file for `rose service run`, when `--config-dir` is present.
///
/// `args` is the full argument list, including the program name.
#[must_use]
pub(super) fn service_log_path(args: &[String]) -> Option<PathBuf> {
    let mut parts = args.iter().map(String::as_str);
    let _program = parts.next()?;
    if parts.next() != Some("service") || parts.next() != Some("run") {
        return None;
    }
    let rest: Vec<&str> = parts.collect();
    config_dir_arg(&rest).map(|dir| dir.join("service.log"))
}

/// PowerShell that removes the `RoSE` firewall rule if it exists.
#[must_use]
pub(super) fn firewall_remove_script() -> String {
    format!(
        "$ErrorActionPreference = 'Stop'; Get-NetFirewallRule -Name '{FIREWALL_RULE_NAME}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule"
    )
}

/// Text printed after uninstall. Configuration is intentionally kept.
#[must_use]
pub(super) fn uninstall_summary(layout: &ServiceLayout) -> String {
    format!(
        "Removed the {SERVICE_DISPLAY_NAME} service, its firewall rule, and {}.\nLeft configuration in place at {}.",
        layout.install_dir.display(),
        layout.config_dir.display(),
    )
}

/// Installs the Windows service and its firewall rule.
///
/// # Errors
///
/// Returns an error on non-Windows platforms, when the listen port is 0, or
/// when creating the service or firewall rule fails.
pub(super) fn install(listen: SocketAddr, hostnames: Vec<String>) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        windows::install(listen, &hostnames)
    }
    #[cfg(not(windows))]
    {
        let _ = (listen, hostnames);
        anyhow::bail!("installing the RoSE service is only supported on Windows");
    }
}

/// Stops the service, removes its firewall rule, and deletes the installed binary.
///
/// # Errors
///
/// Returns an error on non-Windows platforms or when removal fails.
pub(super) fn uninstall() -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        windows::uninstall()
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("uninstalling the RoSE service is only supported on Windows");
    }
}

/// Entry point used by the Service Control Manager.
///
/// # Errors
///
/// Returns an error on non-Windows platforms or when the dispatcher rejects the process.
pub(super) fn run(
    listen: SocketAddr,
    hostname: Vec<String>,
    config_dir: PathBuf,
) -> anyhow::Result<()> {
    #[cfg(windows)]
    {
        windows::run(listen, hostname, config_dir)
    }
    #[cfg(not(windows))]
    {
        let _ = (listen, hostname, config_dir);
        anyhow::bail!("the RoSE Windows service can only run on Windows");
    }
}

fn launch_arguments(listen: SocketAddr, config_dir: &Path, hostnames: &[String]) -> Vec<String> {
    let mut args = vec![
        "service".to_string(),
        "run".to_string(),
        "--listen".to_string(),
        listen.to_string(),
        "--config-dir".to_string(),
        config_dir.display().to_string(),
    ];
    for hostname in hostnames {
        args.push("--hostname".to_string());
        args.push(hostname.clone());
    }
    args
}

fn specified_ip(ip: IpAddr) -> Option<String> {
    (!ip.is_unspecified()).then(|| ip.to_string())
}

fn firewall_replace_script(port: u16, program: &Path, local_ip: Option<&str>) -> String {
    let program = powershell_literal(&program.display().to_string());
    let local_address = local_ip
        .map(|ip| format!(" -LocalAddress {}", powershell_literal(ip)))
        .unwrap_or_default();
    format!(
        "$ErrorActionPreference = 'Stop'; Get-NetFirewallRule -Name '{FIREWALL_RULE_NAME}' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; New-NetFirewallRule -Name '{FIREWALL_RULE_NAME}' -DisplayName '{FIREWALL_RULE_DISPLAY}' -Direction Inbound -Action Allow -Protocol UDP -LocalPort {port} -Program {program}{local_address} -Profile Any -Enabled True | Out-Null"
    )
}

fn install_summary(layout: &ServiceLayout, listen: SocketAddr) -> String {
    format!(
        "Installed the {SERVICE_DISPLAY_NAME} service.\n\
         Binary: {}\n\
         Listen: {listen} (UDP)\n\
         Firewall rule: {FIREWALL_RULE_DISPLAY} ({FIREWALL_RULE_NAME})\n\
         Config: {}\n\
         The service account is LocalSystem, and the service starts automatically.\n\
         Place client certificates in {}.",
        layout.executable.display(),
        layout.config_dir.display(),
        layout.config_dir.join("authorized_certs").display(),
    )
}

fn config_dir_arg(args: &[&str]) -> Option<PathBuf> {
    for (index, arg) in args.iter().enumerate() {
        if let Some(value) = arg.strip_prefix("--config-dir=") {
            return Some(PathBuf::from(value));
        }
        if *arg == "--config-dir" {
            return args.get(index + 1).map(PathBuf::from);
        }
    }
    None
}

fn powershell_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// COVERAGE: These functions register a real Windows service and firewall rule.
/// The command plan is unit tested; executing it would change this machine.
#[cfg(windows)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod windows {
    use std::ffi::OsString;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::{Arc, OnceLock};
    use std::time::{Duration, Instant};

    use windows_service::service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
        ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    use super::{
        ERROR_ACCESS_DENIED, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, ERROR_SERVICE_DOES_NOT_EXIST,
        ERROR_SERVICE_NOT_ACTIVE, EXECUTABLE_NAME, SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME,
        SERVICE_NAME, ServiceLayout, firewall_remove_script, prepare_install, service_failure_args,
        service_layout, uninstall_summary,
    };
    use crate::cli::server::run_server_at;
    use crate::config::RosePaths;

    struct ServiceRunConfig {
        listen: SocketAddr,
        hostname: Vec<String>,
        config_dir: PathBuf,
    }

    static SERVICE_RUN: OnceLock<ServiceRunConfig> = OnceLock::new();

    pub(super) fn install(listen: SocketAddr, hostnames: &[String]) -> anyhow::Result<()> {
        let program_files = env_dir("ProgramFiles", r"C:\Program Files");
        let program_data = env_dir("ProgramData", r"C:\ProgramData");
        let plan = prepare_install(&program_files, &program_data, listen, hostnames)?;
        // Stop a previous service before replacing its executable. Windows locks a running image.
        remove_service()?;
        let source = std::env::current_exe()?;
        copy_binary(&source, &plan.layout.executable)?;
        std::fs::create_dir_all(plan.layout.config_dir.join("authorized_certs"))
            .map_err(|error| io_error(error, "create the RoSE config directory"))?;

        create_service(&plan.layout.executable, &plan.launch_arguments)?;
        run_powershell(&plan.firewall_script, "add the RoSE firewall rule")?;
        configure_restart()?;
        start_service()?;
        eprintln!("{}", plan.summary);
        Ok(())
    }

    pub(super) fn uninstall() -> anyhow::Result<()> {
        let program_files = env_dir("ProgramFiles", r"C:\Program Files");
        let program_data = env_dir("ProgramData", r"C:\ProgramData");
        let layout = service_layout(&program_files, &program_data);
        remove_service()?;
        run_powershell(&firewall_remove_script(), "remove the RoSE firewall rule")?;
        remove_installed_files(&layout)?;
        eprintln!("{}", uninstall_summary(&layout));
        Ok(())
    }

    pub(super) fn run(
        listen: SocketAddr,
        hostname: Vec<String>,
        config_dir: PathBuf,
    ) -> anyhow::Result<()> {
        SERVICE_RUN
            .set(ServiceRunConfig {
                listen,
                hostname,
                config_dir,
            })
            .map_err(|_| anyhow::anyhow!("the RoSE service dispatcher was started twice"))?;
        service_ffi::start_dispatcher().map_err(dispatcher_error)
    }

    fn env_dir(name: &str, fallback: &str) -> PathBuf {
        std::env::var_os(name).map_or_else(|| PathBuf::from(fallback), PathBuf::from)
    }

    fn copy_binary(source: &std::path::Path, destination: &std::path::Path) -> anyhow::Result<()> {
        if let (Ok(source), Ok(destination)) = (
            std::fs::canonicalize(source),
            std::fs::canonicalize(destination),
        ) && source == destination
        {
            return Ok(());
        }
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| io_error(error, "create the RoSE install directory"))?;
        }
        let mut last_error = None;
        for _ in 0..25 {
            match std::fs::copy(source, destination) {
                Ok(_) => return Ok(()),
                Err(error) if is_in_use(&error) => {
                    last_error = Some(error);
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(error) => {
                    return Err(io_error(error, "copy rose.exe into the install directory"));
                }
            }
        }
        Err(io_error(
            last_error.unwrap_or_else(|| std::io::Error::other("rose.exe stayed locked")),
            "copy rose.exe into the install directory",
        ))
    }

    fn create_service(
        executable: &std::path::Path,
        launch_arguments: &[String],
    ) -> anyhow::Result<()> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .map_err(service_error)?;
        let service_info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(SERVICE_DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: executable.to_path_buf(),
            launch_arguments: launch_arguments.iter().map(OsString::from).collect(),
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };
        let access =
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS;
        let service = manager
            .create_service(&service_info, access)
            .map_err(service_error)?;
        service
            .set_description(SERVICE_DESCRIPTION)
            .map_err(service_error)?;
        Ok(())
    }

    fn configure_restart() -> anyhow::Result<()> {
        run_command(
            "sc",
            &service_failure_args(SERVICE_NAME),
            "configure the RoSE service to restart after a failure",
        )
    }

    fn start_service() -> anyhow::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(service_error)?;
        let service = manager
            .open_service(SERVICE_NAME, ServiceAccess::START)
            .map_err(service_error)?;
        service.start::<&str>(&[]).map_err(service_error)?;
        Ok(())
    }

    fn remove_service() -> anyhow::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .map_err(service_error)?;
        let access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
        let service = match manager.open_service(SERVICE_NAME, access) {
            Ok(service) => service,
            Err(error) if winapi_code(&error) == Some(ERROR_SERVICE_DOES_NOT_EXIST) => {
                return Ok(());
            }
            Err(error) => return Err(service_error(error)),
        };

        service.delete().map_err(service_error)?;
        let state = service.query_status().map_err(service_error)?.current_state;
        if !matches!(state, ServiceState::Stopped | ServiceState::StopPending) {
            match service.stop() {
                Ok(_) => {}
                Err(error) if winapi_code(&error) == Some(ERROR_SERVICE_NOT_ACTIVE) => {}
                Err(error) => return Err(service_error(error)),
            }
        }
        drop(service);

        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            match manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
                Err(error) if winapi_code(&error) == Some(ERROR_SERVICE_DOES_NOT_EXIST) => {
                    return Ok(());
                }
                Ok(_) | Err(_) => std::thread::sleep(Duration::from_millis(200)),
            }
        }
        anyhow::bail!(
            "the RoSE service is marked for deletion and is still registered; retry uninstall after it stops"
        )
    }

    fn remove_installed_files(layout: &ServiceLayout) -> anyhow::Result<()> {
        if layout.executable.exists()
            && let Err(error) = std::fs::remove_file(&layout.executable)
        {
            if is_in_use(&error) {
                schedule_delete(layout)?;
                return Ok(());
            }
            return Err(io_error(error, "delete the installed rose.exe"));
        }
        match std::fs::remove_dir(&layout.install_dir) {
            Ok(()) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(io_error(error, "remove the RoSE install directory")),
        }
    }

    fn schedule_delete(layout: &ServiceLayout) -> anyhow::Result<()> {
        let executable = layout.install_dir.join(EXECUTABLE_NAME);
        let script = format!(
            "ping 127.0.0.1 -n 3 > nul & del /f /q {} & rmdir {}",
            cmd_quote(&executable.display().to_string()),
            cmd_quote(&layout.install_dir.display().to_string()),
        );
        hidden_command("cmd")
            .args(["/C", &script])
            .spawn()
            .map(|_| ())
            .map_err(|error| io_error(error, "schedule deletion of the installed rose.exe"))
    }

    fn run_powershell(script: &str, action: &str) -> anyhow::Result<()> {
        run_command(
            "powershell.exe",
            &[
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-Command".to_string(),
                script.to_string(),
            ],
            action,
        )
    }

    fn run_command(program: &str, args: &[String], action: &str) -> anyhow::Result<()> {
        let output = hidden_command(program)
            .args(args)
            .output()
            .map_err(|error| io_error(error, action))?;
        if output.status.success() {
            return Ok(());
        }
        let details = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        anyhow::bail!("failed to {action}: {details}");
    }

    fn hidden_command(program: &str) -> Command {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut command = Command::new(program);
        command.creation_flags(CREATE_NO_WINDOW);
        command
    }

    fn is_in_use(error: &std::io::Error) -> bool {
        // Access denied or sharing violation: the file is this running process.
        matches!(error.raw_os_error(), Some(ERROR_ACCESS_DENIED | 32))
    }

    fn io_error(error: std::io::Error, action: &str) -> anyhow::Error {
        if error.raw_os_error() == Some(ERROR_ACCESS_DENIED) {
            anyhow::anyhow!(
                "access denied while trying to {action}; re-run from an elevated Administrator prompt"
            )
        } else {
            anyhow::anyhow!("failed to {action}: {error}")
        }
    }

    fn service_error(error: windows_service::Error) -> anyhow::Error {
        if winapi_code(&error) == Some(ERROR_ACCESS_DENIED) {
            return anyhow::anyhow!(
                "access denied while updating the RoSE Windows service; re-run from an elevated Administrator prompt"
            );
        }
        match std::error::Error::source(&error) {
            Some(source) => anyhow::anyhow!("{error}: {source}"),
            None => anyhow::anyhow!("{error}"),
        }
    }

    fn dispatcher_error(error: windows_service::Error) -> anyhow::Error {
        if winapi_code(&error) == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            return anyhow::anyhow!(
                "`rose service run` is started by the Windows Service Control Manager. Use `rose service install` to register the service."
            );
        }
        service_error(error)
    }

    fn winapi_code(error: &windows_service::Error) -> Option<i32> {
        match error {
            windows_service::Error::Winapi(io) => io.raw_os_error(),
            _ => None,
        }
    }

    pub(in super::super) fn service_main(_arguments: Vec<OsString>) {
        if let Err(error) = execute_service() {
            tracing::error!(%error, "RoSE service failed");
        }
    }

    fn execute_service() -> anyhow::Result<()> {
        let config = SERVICE_RUN.get().ok_or_else(|| {
            anyhow::anyhow!("RoSE service started without its install configuration")
        })?;
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
        let status_handle =
            service_control_handler::register(SERVICE_NAME, move |event| match event {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    let _ = shutdown_tx.send(true);
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            })
            .map_err(service_error)?;

        status_handle
            .set_service_status(status(
                ServiceState::StartPending,
                ServiceControlAccept::empty(),
                ServiceExitCode::Win32(0),
            ))
            .map_err(service_error)?;

        let status_handle = Arc::new(status_handle);
        let ready_handle = Arc::clone(&status_handle);
        let on_listening = Box::new(move || {
            let _ = ready_handle.set_service_status(status(
                ServiceState::Running,
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                ServiceExitCode::Win32(0),
            ));
        });

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        let server_result = runtime.block_on(run_server_at(
            config.listen,
            false,
            config.hostname.clone(),
            RosePaths::with_base(config.config_dir.clone()),
            Some(on_listening),
            async move {
                let _ = shutdown_rx.wait_for(|stop| *stop).await;
            },
        ));
        drop(runtime);

        let exit_code = if server_result.is_ok() {
            ServiceExitCode::Win32(0)
        } else {
            ServiceExitCode::ServiceSpecific(1)
        };
        status_handle
            .set_service_status(status(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                exit_code,
            ))
            .map_err(service_error)?;
        server_result
    }

    const fn status(
        current_state: ServiceState,
        controls_accepted: ServiceControlAccept,
        exit_code: ServiceExitCode,
    ) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state,
            controls_accepted,
            exit_code,
            checkpoint: 0,
            wait_hint: Duration::from_secs(15),
            process_id: None,
        }
    }

    fn cmd_quote(value: &str) -> String {
        format!("\"{value}\"")
    }

    /// `define_windows_service!` expands to an unsafe FFI trampoline.
    #[allow(unsafe_code)]
    mod service_ffi {
        use std::ffi::OsString;

        use windows_service::define_windows_service;

        define_windows_service!(ffi_service_main, service_main_trampoline);

        fn service_main_trampoline(arguments: Vec<OsString>) {
            super::service_main(arguments);
        }

        pub(super) fn start_dispatcher() -> windows_service::Result<()> {
            windows_service::service_dispatcher::start(super::SERVICE_NAME, ffi_service_main)
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn plan(listen: &str, hostnames: &[&str]) -> InstallPlan {
        prepare_install(
            Path::new(r"C:\Program Files"),
            Path::new(r"C:\ProgramData"),
            listen.parse().unwrap(),
            &hostnames
                .iter()
                .map(|hostname| (*hostname).to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }

    #[test]
    fn install_plan_opens_udp_for_the_default_port() {
        let plan = plan("0.0.0.0:4433", &["rose.example"]);
        assert_eq!(
            plan.layout.executable,
            PathBuf::from(r"C:\Program Files\RoSE\rose.exe")
        );
        assert_eq!(
            plan.layout.config_dir,
            PathBuf::from(r"C:\ProgramData\RoSE")
        );
        assert_eq!(
            plan.launch_arguments,
            vec![
                "service",
                "run",
                "--listen",
                "0.0.0.0:4433",
                "--config-dir",
                r"C:\ProgramData\RoSE",
                "--hostname",
                "rose.example",
            ]
        );
        assert!(plan.firewall_script.contains("-Protocol UDP"));
        assert!(plan.firewall_script.contains("-LocalPort 4433"));
        assert!(plan.firewall_script.contains("-Direction Inbound"));
        assert!(plan.firewall_script.contains("-Action Allow"));
        assert!(
            plan.firewall_script
                .contains(r"-Program 'C:\Program Files\RoSE\rose.exe'")
        );
        assert!(!plan.firewall_script.contains("-LocalAddress"));
        assert!(plan.summary.contains("UDP"));
        assert!(plan.summary.contains("LocalSystem"));
        assert!(plan.summary.contains("authorized_certs"));
    }

    #[test]
    fn install_plan_pins_a_specific_listen_address() {
        let plan = plan("[2001:db8::1]:9443", &[]);
        assert!(plan.firewall_script.contains("-LocalPort 9443"));
        assert!(plan.firewall_script.contains("-LocalAddress '2001:db8::1'"));
        assert_eq!(
            plan.launch_arguments,
            vec![
                "service",
                "run",
                "--listen",
                "[2001:db8::1]:9443",
                "--config-dir",
                r"C:\ProgramData\RoSE",
            ]
        );
    }

    #[test]
    fn install_plan_quotes_paths_for_powershell() {
        let script = firewall_replace_script(4433, Path::new(r"C:\RoSE's\rose.exe"), None);
        assert!(script.contains(r"-Program 'C:\RoSE''s\rose.exe'"));
    }

    #[test]
    fn install_plan_rejects_an_ephemeral_bind() {
        let error = prepare_install(
            Path::new(r"C:\Program Files"),
            Path::new(r"C:\ProgramData"),
            "127.0.0.1:0".parse().unwrap(),
            &[],
        )
        .unwrap_err();
        assert_eq!(error, ListenPortError);
    }

    #[test]
    fn uninstall_removes_the_named_firewall_rule() {
        let layout = service_layout(Path::new(r"C:\Program Files"), Path::new(r"C:\ProgramData"));
        let script = firewall_remove_script();
        assert!(script.contains("-Name 'RoSE'"));
        assert!(script.contains("Remove-NetFirewallRule"));
        assert!(!script.contains("New-NetFirewallRule"));
        let summary = uninstall_summary(&layout);
        assert!(summary.contains(r"C:\Program Files\RoSE"));
        assert!(summary.contains(r"C:\ProgramData\RoSE"));
    }

    #[test]
    fn failure_recovery_restarts_the_service() {
        assert_eq!(
            service_failure_args(SERVICE_NAME),
            [
                "failure",
                "RoSE",
                "reset=",
                "86400",
                "actions=",
                "restart/5000/restart/5000/restart/5000",
            ]
        );
    }

    #[test]
    fn service_run_log_follows_config_dir() {
        let args = [
            "rose",
            "service",
            "run",
            "--listen",
            "0.0.0.0:4433",
            "--config-dir",
            r"C:\ProgramData\RoSE",
        ]
        .map(str::to_string);
        assert_eq!(
            service_log_path(&args),
            Some(PathBuf::from(r"C:\ProgramData\RoSE\service.log"))
        );

        let equals = ["rose", "service", "run", r"--config-dir=D:\rose"].map(str::to_string);
        assert_eq!(
            service_log_path(&equals),
            Some(PathBuf::from(r"D:\rose\service.log"))
        );
        assert_eq!(
            service_log_path(&["rose".to_string(), "server".to_string()]),
            None
        );
    }
}
