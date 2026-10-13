//! Starts a shell as the interactive Windows user from a `LocalSystem` service.
//!
//! `WTSQueryUserToken` returns the logon token. `CreateProcessAsUser` with that
//! token does not show a consent dialog. The elevated token is the logon's
//! linked token, which only a process with `SeTcbPrivilege` (the system
//! service) can read.

// Win32 token and process creation have no safe wrapper.
#![allow(unsafe_code)]

use std::ffi::c_void;
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::ptr;
use std::sync::Mutex;

use portable_pty::{Child, ChildKiller, ExitStatus, MasterPty, PtySize};
use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, CreateWellKnownSid, DuplicateTokenEx, EqualSid, GetTokenInformation,
    LookupAccountSidW, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, SID_NAME_USE,
    SecurityImpersonation, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_SESSIONID,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_LINKED_TOKEN, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TOKEN_USER, TokenElevationType, TokenElevationTypeDefault, TokenElevationTypeFull,
    TokenElevationTypeLimited, TokenLinkedToken, TokenPrimary, TokenUser, WinLocalSystemSid,
};
use windows_sys::Win32::System::Console::{
    COORD, ClosePseudoConsole, CreatePseudoConsole, HPCON, PSEUDOCONSOLE_INHERIT_CURSOR,
    ResizePseudoConsole,
};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::RemoteDesktop::{
    WTS_SESSION_INFOW, WTSEnumerateSessionsW, WTSFreeMemory, WTSGetActiveConsoleSessionId,
    WTSQueryUserToken,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetExitCodeProcess, GetProcessId, InitializeProcThreadAttributeList, OpenProcessToken,
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

use crate::pty::{PtySession, SpawnedPty};
use crate::shell_account::{ShellAccountError, env_block_set, env_block_value};

const NO_CONSOLE_SESSION: u32 = 0xFFFF_FFFF;
const STILL_ACTIVE: u32 = 259;

struct OwnedHandle(HANDLE);

// The handle is owned by this process. The Win32 calls used here may run on
// more than one thread.
unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

/// Reports whether this process is `LocalSystem`.
///
/// # Errors
///
/// Returns [`ShellAccountError::Windows`] when the process token cannot be read.
pub(crate) fn is_local_system() -> Result<bool, ShellAccountError> {
    let token = open_process_token(TOKEN_QUERY)?;
    let mut needed = 0u32;
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(last_error("read the process token user"));
    }
    let mut buffer = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(last_error("read the process token user"));
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid = [0u8; 68];
    let mut sid_len = u32::try_from(sid.len()).unwrap_or(u32::MAX);
    let created = unsafe {
        CreateWellKnownSid(
            WinLocalSystemSid,
            ptr::null_mut(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
        )
    };
    if created == 0 {
        return Err(last_error("build the LocalSystem SID"));
    }
    Ok(unsafe { EqualSid(user.User.Sid, sid.as_mut_ptr().cast()) } != 0)
}

/// Account of this process: user name and SID.
///
/// # Errors
///
/// Returns [`ShellAccountError::Windows`] when the process token cannot be read.
pub(crate) fn current_user() -> Result<(String, String), ShellAccountError> {
    let token = open_process_token(TOKEN_QUERY)?;
    account_from_token(token.0)
}

/// Account of the interactive console session.
///
/// # Errors
///
/// Returns [`ShellAccountError::UserNotLoggedOn`] when nobody is logged on,
/// or [`ShellAccountError::Windows`] when the token cannot be read.
pub(crate) fn console_user() -> Result<(String, String), ShellAccountError> {
    let session = unsafe { WTSGetActiveConsoleSessionId() };
    if session == NO_CONSOLE_SESSION || session == 0 {
        return Err(ShellAccountError::UserNotLoggedOn("console".to_string()));
    }
    let token = session_token(session)?;
    account_from_token(token.0)
}

/// Opens a ConPTY shell as the Windows user `sid`.
///
/// # Errors
///
/// Returns [`ShellAccountError`] when that user is not logged on, elevation is
/// unavailable, or the process cannot be created.
pub(crate) fn open_user_terminal(
    rows: u16,
    cols: u16,
    elevated: bool,
    env: &[(String, String)],
    sid: &str,
    user_label: &str,
) -> Result<PtySession, ShellAccountError> {
    enable_privileges()?;
    let token = token_for_sid(sid, elevated, user_label)?;
    let mut block = user_environment(token.0)?;
    for (key, value) in env {
        env_block_set(&mut block, key, value);
    }
    let profile =
        env_block_value(&block, "USERPROFILE").ok_or(ShellAccountError::MissingProfile)?;
    let exe = env_block_value(&block, "ComSpec")
        .unwrap_or_else(|| r"C:\Windows\System32\cmd.exe".to_string());
    tracing::info!(
        user = env_block_value(&block, "USERNAME").unwrap_or_default(),
        elevated,
        profile = profile.as_str(),
        "session account"
    );

    let rows = rows.max(1);
    let cols = cols.max(1);
    let mut console = pseudo_console(rows, cols)?;
    let child = spawn_as_user(token.0, console.con, &exe, &profile, &block)?;
    let con = console.con;
    console.con = 0;
    let readable = console
        .readable
        .take()
        .ok_or_else(|| ShellAccountError::Windows("console output pipe is missing".to_string()))?;
    let writable = console
        .writable
        .take()
        .ok_or_else(|| ShellAccountError::Windows("console input pipe is missing".to_string()))?;
    let master = Box::new(UserMaster {
        con,
        readable,
        writable: Mutex::new(Some(writable)),
        size: Mutex::new(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        }),
    });
    let writer = master
        .take_writer()
        .map_err(|error| ShellAccountError::Windows(error.to_string()))?;
    let reader = master
        .try_clone_reader()
        .map_err(|error| ShellAccountError::Windows(error.to_string()))?;
    PtySession::from_spawned(
        rows,
        cols,
        true,
        SpawnedPty {
            master,
            child: Box::new(child),
            reader,
            writer,
        },
    )
    .map_err(|error| ShellAccountError::Pty(error.to_string()))
}

struct ConsoleEnds {
    con: HPCON,
    readable: Option<File>,
    writable: Option<File>,
}

impl Drop for ConsoleEnds {
    fn drop(&mut self) {
        if self.con != 0 {
            unsafe { ClosePseudoConsole(self.con) }
            self.con = 0;
        }
    }
}

fn pseudo_console(rows: u16, cols: u16) -> Result<ConsoleEnds, ShellAccountError> {
    let (stdin_read, stdin_write) = pipe()?;
    let (stdout_read, stdout_write) = pipe()?;
    let mut con: HPCON = 0;
    let created = unsafe {
        CreatePseudoConsole(
            COORD {
                X: i16::try_from(cols).unwrap_or(i16::MAX),
                Y: i16::try_from(rows).unwrap_or(i16::MAX),
            },
            stdin_read,
            stdout_write,
            PSEUDOCONSOLE_INHERIT_CURSOR,
            &mut con,
        )
    };
    unsafe {
        CloseHandle(stdin_read);
        CloseHandle(stdout_write);
    }
    if created != 0 {
        unsafe {
            CloseHandle(stdin_write);
            CloseHandle(stdout_read);
        }
        return Err(ShellAccountError::Windows(format!(
            "create the console: HRESULT {created}"
        )));
    }
    let readable = unsafe { File::from_raw_handle(stdout_read) };
    let writable = unsafe { File::from_raw_handle(stdin_write) };
    Ok(ConsoleEnds {
        con,
        readable: Some(readable),
        writable: Some(writable),
    })
}

fn pipe() -> Result<(HANDLE, HANDLE), ShellAccountError> {
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    let ok = unsafe { CreatePipe(&mut read, &mut write, ptr::null(), 64 * 1024) };
    if ok == 0 {
        return Err(last_error("create a console pipe"));
    }
    Ok((read, write))
}

fn spawn_as_user(
    token: HANDLE,
    con: HPCON,
    exe: &str,
    profile: &str,
    environment: &[u16],
) -> Result<UserChild, ShellAccountError> {
    let mut attributes = AttributeList::new()?;
    attributes.set_console(con)?;
    let mut exe_wide = wide(exe);
    let mut command = wide(&format!("\"{exe}\""));
    let mut directory = wide(profile);
    let mut desktop = wide("winsta0\\default");
    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb =
        u32::try_from(std::mem::size_of::<STARTUPINFOEXW>()).unwrap_or(u32::MAX);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = INVALID_HANDLE_VALUE;
    startup.StartupInfo.hStdOutput = INVALID_HANDLE_VALUE;
    startup.StartupInfo.hStdError = INVALID_HANDLE_VALUE;
    startup.StartupInfo.lpDesktop = desktop.as_mut_ptr();
    startup.lpAttributeList = attributes.as_mut_ptr();
    let mut process_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let created = unsafe {
        CreateProcessAsUserW(
            token,
            exe_wide.as_mut_ptr(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_PROCESS_GROUP,
            environment.as_ptr().cast(),
            directory.as_ptr(),
            ptr::from_ref(&startup).cast(),
            &mut process_info,
        )
    };
    if created == 0 {
        return Err(last_error("start the shell as the approved user"));
    }
    unsafe {
        CloseHandle(process_info.hThread);
    }
    Ok(UserChild {
        process: OwnedHandle(process_info.hProcess),
    })
}

struct AttributeList {
    data: Vec<u8>,
}

impl AttributeList {
    fn new() -> Result<Self, ShellAccountError> {
        let mut bytes = 0usize;
        unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut bytes);
        }
        if bytes == 0 {
            return Err(last_error("size the process attribute list"));
        }
        let mut data = vec![0u8; bytes];
        let ok = unsafe {
            InitializeProcThreadAttributeList(data.as_mut_ptr().cast(), 1, 0, &mut bytes)
        };
        if ok == 0 {
            return Err(last_error("create the process attribute list"));
        }
        Ok(Self { data })
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.data.as_mut_ptr().cast()
    }

    fn set_console(&mut self, con: HPCON) -> Result<(), ShellAccountError> {
        let handle = con as HANDLE;
        let ok = unsafe {
            UpdateProcThreadAttribute(
                self.as_mut_ptr(),
                0,
                usize::try_from(PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE).unwrap_or(usize::MAX),
                handle.cast(),
                std::mem::size_of::<HANDLE>(),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        if ok == 0 {
            return Err(last_error("attach the console to the shell"));
        }
        Ok(())
    }
}

impl Drop for AttributeList {
    fn drop(&mut self) {
        if !self.data.is_empty() {
            unsafe { DeleteProcThreadAttributeList(self.as_mut_ptr()) }
        }
    }
}

fn token_for_sid(
    sid: &str,
    elevated: bool,
    user_label: &str,
) -> Result<OwnedHandle, ShellAccountError> {
    let session = session_for_sid(sid)
        .ok_or_else(|| ShellAccountError::UserNotLoggedOn(user_label.to_string()))?;
    let queried = session_token(session)?;
    let primary = duplicate_primary(queried.0)?;
    match (elevated, elevation_type(primary.0)?) {
        (false, TokenElevationTypeLimited | TokenElevationTypeDefault) => Ok(primary),
        (true, TokenElevationTypeFull) => Ok(primary),
        (false, TokenElevationTypeFull) | (true, TokenElevationTypeLimited) => {
            linked_token(primary.0)
        }
        _ => Err(ShellAccountError::NoElevatedToken),
    }
}

fn elevation_type(token: HANDLE) -> Result<i32, ShellAccountError> {
    let mut value = 0i32;
    let mut needed = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevationType,
            std::ptr::from_mut(&mut value).cast(),
            u32::try_from(std::mem::size_of_val(&value)).unwrap_or(u32::MAX),
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(last_error("read the token elevation type"));
    }
    Ok(value)
}

fn linked_token(token: HANDLE) -> Result<OwnedHandle, ShellAccountError> {
    let mut linked = TOKEN_LINKED_TOKEN {
        LinkedToken: ptr::null_mut(),
    };
    let mut needed = 0u32;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenLinkedToken,
            std::ptr::from_mut(&mut linked).cast(),
            u32::try_from(std::mem::size_of_val(&linked)).unwrap_or(u32::MAX),
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(ShellAccountError::NoElevatedToken);
    }
    let linked = OwnedHandle(linked.LinkedToken);
    duplicate_primary(linked.0)
}

fn duplicate_primary(token: HANDLE) -> Result<OwnedHandle, ShellAccountError> {
    let mut primary = ptr::null_mut();
    let access = TOKEN_ASSIGN_PRIMARY
        | TOKEN_DUPLICATE
        | TOKEN_QUERY
        | TOKEN_ADJUST_DEFAULT
        | TOKEN_ADJUST_SESSIONID;
    let ok = unsafe {
        DuplicateTokenEx(
            token,
            access,
            ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut primary,
        )
    };
    if ok == 0 {
        return Err(last_error("duplicate the user token"));
    }
    Ok(OwnedHandle(primary))
}

fn user_environment(token: HANDLE) -> Result<Vec<u16>, ShellAccountError> {
    let mut raw = ptr::null_mut();
    let ok = unsafe { CreateEnvironmentBlock(&mut raw, token, 0) };
    if ok == 0 {
        return Err(last_error("build the user environment"));
    }
    let block = copy_environment(raw.cast());
    unsafe {
        DestroyEnvironmentBlock(raw);
    }
    Ok(block)
}

fn copy_environment(block: *const u16) -> Vec<u16> {
    let mut copied = Vec::new();
    if block.is_null() {
        copied.push(0);
        return copied;
    }
    unsafe {
        let mut cursor = block;
        loop {
            let unit = *cursor;
            copied.push(unit);
            if unit == 0 && *cursor.add(1) == 0 {
                copied.push(0);
                break;
            }
            cursor = cursor.add(1);
        }
    }
    copied
}

fn session_token(session: u32) -> Result<OwnedHandle, ShellAccountError> {
    let mut raw = ptr::null_mut();
    let ok = unsafe { WTSQueryUserToken(session, &mut raw) };
    if ok == 0 {
        return Err(last_error("query the user token"));
    }
    Ok(OwnedHandle(raw))
}

fn session_for_sid(sid: &str) -> Option<u32> {
    let mut info: *mut WTS_SESSION_INFOW = ptr::null_mut();
    let mut count = 0u32;
    let ok = unsafe { WTSEnumerateSessionsW(ptr::null_mut(), 0, 1, &mut info, &mut count) };
    if ok == 0 || info.is_null() {
        return None;
    }
    let console = unsafe { WTSGetActiveConsoleSessionId() };
    let mut found = None;
    for index in 0..count {
        let session = unsafe { *info.add(usize::try_from(index).unwrap_or(0)) };
        if session.SessionId == 0 {
            continue;
        }
        let Ok(token) = session_token(session.SessionId) else {
            continue;
        };
        let Ok((_, got)) = account_from_token(token.0) else {
            continue;
        };
        if got.eq_ignore_ascii_case(sid) && (found.is_none() || session.SessionId == console) {
            found = Some(session.SessionId);
        }
    }
    unsafe { WTSFreeMemory(info.cast()) };
    found
}

fn account_from_token(token: HANDLE) -> Result<(String, String), ShellAccountError> {
    let mut needed = 0u32;
    unsafe {
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(last_error("read the token user"));
    }
    let mut buffer = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(last_error("read the token user"));
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let sid = sid_string(user.User.Sid)?;
    let name = account_name(user.User.Sid).unwrap_or_else(|_| sid.clone());
    Ok((name, sid))
}

fn sid_string(sid: windows_sys::Win32::Security::PSID) -> Result<String, ShellAccountError> {
    let mut raw = ptr::null_mut();
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut raw) };
    if ok == 0 || raw.is_null() {
        return Err(last_error("format the user SID"));
    }
    let mut len = 0usize;
    unsafe {
        while *raw.add(len) != 0 {
            len += 1;
        }
    }
    let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(raw, len) });
    unsafe {
        LocalFree(raw.cast());
    }
    Ok(text)
}

fn account_name(sid: windows_sys::Win32::Security::PSID) -> Result<String, ShellAccountError> {
    let mut name = vec![0u16; 256];
    let mut name_len = u32::try_from(name.len()).unwrap_or(u32::MAX);
    let mut domain = vec![0u16; 256];
    let mut domain_len = u32::try_from(domain.len()).unwrap_or(u32::MAX);
    let mut use_name: SID_NAME_USE = 0;
    let ok = unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut use_name,
        )
    };
    if ok == 0 {
        return Err(last_error("look up the account name"));
    }
    let len = usize::try_from(name_len).unwrap_or(0).saturating_sub(1);
    Ok(String::from_utf16_lossy(&name[..len.min(name.len())]))
}

fn enable_privileges() -> Result<(), ShellAccountError> {
    let token = open_process_token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY)?;
    for name in [
        "SeTcbPrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeIncreaseQuotaPrivilege",
    ] {
        enable_privilege(token.0, name)?;
    }
    Ok(())
}

fn enable_privilege(token: HANDLE, name: &str) -> Result<(), ShellAccountError> {
    let mut luid = windows_sys::Win32::Foundation::LUID {
        LowPart: 0,
        HighPart: 0,
    };
    let wide_name = wide(name);
    let found = unsafe { LookupPrivilegeValueW(ptr::null(), wide_name.as_ptr(), &mut luid) };
    if found == 0 {
        return Err(last_error("look up a service privilege"));
    }
    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [windows_sys::Win32::Security::LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    let ok = unsafe {
        AdjustTokenPrivileges(token, 0, &privileges, 0, ptr::null_mut(), ptr::null_mut())
    };
    if ok == 0 {
        return Err(last_error("enable a service privilege"));
    }
    Ok(())
}

fn open_process_token(access: u32) -> Result<OwnedHandle, ShellAccountError> {
    let mut token = ptr::null_mut();
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) };
    if ok == 0 {
        return Err(last_error("open the process token"));
    }
    Ok(OwnedHandle(token))
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn last_error(action: &str) -> ShellAccountError {
    ShellAccountError::Windows(format!("{action}: {}", std::io::Error::last_os_error()))
}

struct UserMaster {
    con: HPCON,
    readable: File,
    writable: Mutex<Option<File>>,
    size: Mutex<PtySize>,
}

impl Drop for UserMaster {
    fn drop(&mut self) {
        unsafe { ClosePseudoConsole(self.con) }
    }
}

impl MasterPty for UserMaster {
    fn resize(&self, size: PtySize) -> anyhow::Result<()> {
        let result = unsafe {
            ResizePseudoConsole(
                self.con,
                COORD {
                    X: i16::try_from(size.cols).unwrap_or(i16::MAX),
                    Y: i16::try_from(size.rows).unwrap_or(i16::MAX),
                },
            )
        };
        if result != 0 {
            anyhow::bail!("resize the console: HRESULT {result}");
        }
        *self.size.lock().expect("size lock poisoned") = size;
        Ok(())
    }

    fn get_size(&self) -> anyhow::Result<PtySize> {
        Ok(*self.size.lock().expect("size lock poisoned"))
    }

    fn try_clone_reader(&self) -> anyhow::Result<Box<dyn Read + Send>> {
        Ok(Box::new(self.readable.try_clone()?))
    }

    fn take_writer(&self) -> anyhow::Result<Box<dyn Write + Send>> {
        self.writable
            .lock()
            .expect("writer lock poisoned")
            .take()
            .map(|file| Box::new(file) as Box<dyn Write + Send>)
            .ok_or_else(|| anyhow::anyhow!("writer already taken"))
    }
}

struct UserChild {
    process: OwnedHandle,
}

impl std::fmt::Debug for UserChild {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UserChild")
            .field("pid", &self.process_id())
            .finish()
    }
}

impl Child for UserChild {
    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        let state = unsafe { WaitForSingleObject(self.process.0, 0) };
        if state == WAIT_TIMEOUT {
            return Ok(None);
        }
        if state != WAIT_OBJECT_0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut code = 0u32;
        let ok = unsafe { GetExitCodeProcess(self.process.0, &mut code) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if code == STILL_ACTIVE {
            return Ok(None);
        }
        Ok(Some(ExitStatus::with_exit_code(code)))
    }

    fn wait(&mut self) -> std::io::Result<ExitStatus> {
        let state = unsafe { WaitForSingleObject(self.process.0, u32::MAX) };
        if state != WAIT_OBJECT_0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut code = 0u32;
        let ok = unsafe { GetExitCodeProcess(self.process.0, &mut code) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(ExitStatus::with_exit_code(code))
    }

    fn process_id(&self) -> Option<u32> {
        let pid = unsafe { GetProcessId(self.process.0) };
        (pid != 0).then_some(pid)
    }

    fn as_raw_handle(&self) -> Option<RawHandle> {
        Some(self.process.0)
    }
}

impl ChildKiller for UserChild {
    fn kill(&mut self) -> std::io::Result<()> {
        let ok = unsafe { TerminateProcess(self.process.0, 1) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn clone_killer(&self) -> Box<dyn ChildKiller + Send + Sync> {
        let mut duplicated = ptr::null_mut();
        let ok = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                self.process.0,
                GetCurrentProcess(),
                &mut duplicated,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if ok == 0 {
            return Box::new(UserChild {
                process: OwnedHandle(ptr::null_mut()),
            });
        }
        Box::new(UserChild {
            process: OwnedHandle(duplicated),
        })
    }
}
