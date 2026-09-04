use anyhow::{Context, Result};
use std::path::Path;
use std::process::{Child, Command, Stdio};
#[cfg(target_os = "windows")]
use std::time::{Duration, Instant};

/// Candidate service names the WinDivert kernel driver can be registered under,
/// across Flowseal / zapret / GoodbyeDPI builds and driver versions. `winws.exe`
/// installs the driver on first use and (on a clean exit) removes it; a crash
/// leaves it resident and the next `winws` then fails with ERROR_ACCESS_DENIED
/// or "driver already loaded", which is the classic revive-loop trigger.
#[cfg(target_os = "windows")]
pub const WINDIVERT_SERVICE_NAMES: &[&str] = &["WinDivert", "WinDivert14", "windivert", "WinDivert1.4"];

/// True if any WinDivert service is still registered and not fully stopped.
#[cfg(target_os = "windows")]
pub fn windivert_is_resident() -> bool {
    for name in WINDIVERT_SERVICE_NAMES {
        if let Ok(out) = crate::engine::silent_command("sc.exe").args(["query", name]).output() {
            let s = String::from_utf8_lossy(&out.stdout);
            // 1060 == ERROR_SERVICE_DOES_NOT_EXIST -> definitively gone
            if s.contains("1060") {
                continue;
            }
            if s.contains("RUNNING") || s.contains("START_PENDING") || s.contains("STOP_PENDING") || s.contains("PAUSED") {
                return true;
            }
        }
    }
    false
}

/// Force any stray `winws.exe` to exit and wait (bounded) for the process list to clear.
#[cfg(target_os = "windows")]
pub fn kill_stray_winws() {
    let _ = crate::engine::silent_command("taskkill.exe")
        .args(["/F", "/T", "/IM", "winws.exe"])
        .status();

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        match crate::engine::silent_command("tasklist.exe")
            .args(["/FI", "IMAGENAME eq winws.exe", "/NH"])
            .output()
        {
            Ok(out) => {
                let s = String::from_utf8_lossy(&out.stdout);
                if !s.to_lowercase().contains("winws.exe") {
                    return;
                }
            }
            Err(_) => return,
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

/// Stop, wait for, and delete every WinDivert service variant. Returns `true` when
/// the driver is confirmed fully unloaded, `false` if something is still wedged
/// after `timeout` (the caller should then treat the engine as Faulted rather
/// than spinning up another `winws`).
#[cfg(target_os = "windows")]
pub fn teardown_windivert(timeout: Duration) -> bool {
    for name in WINDIVERT_SERVICE_NAMES {
        let _ = crate::engine::silent_command("net.exe").args(["stop", name]).output();
        let _ = crate::engine::silent_command("sc.exe").args(["stop", name]).output();
    }

    let deadline = Instant::now() + timeout;
    loop {
        // Attempt deletion each pass; harmless once already gone.
        for name in WINDIVERT_SERVICE_NAMES {
            let _ = crate::engine::silent_command("sc.exe").args(["delete", name]).output();
        }
        if !windivert_is_resident() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

pub struct ProcessHandle {
    child: Child,
    #[cfg(target_os = "windows")]
    _job_handle: Option<isize>,
    pub binary_path: std::path::PathBuf,
    pub args: Vec<String>,
}

impl ProcessHandle {
    /// Spawn the DPI engine process (tpws or winws) with the specified arguments.
    pub fn spawn(exe_path: &Path, args: &[String]) -> Result<Self> {
        let mut cmd = Command::new(exe_path);
        cmd.args(args);

        // Set working directory to binary's directory so WinDivert.dll/WinDivert64.sys/cygwin1.dll are found
        if let Some(parent) = exe_path.parent() {
            cmd.current_dir(parent);
        }

        // Security & Stability: Write engine logs to a stable path
        let log_path = {
            #[cfg(target_os = "windows")]
            {
                let pdata = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
                let dir = std::path::PathBuf::from(pdata).join("GhostLink").join("logs");
                let _ = std::fs::create_dir_all(&dir);
                dir.join("engine.log")
            }
            #[cfg(not(target_os = "windows"))]
            {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                let dir = std::path::PathBuf::from(home).join(".ghostlink");
                let _ = std::fs::create_dir_all(&dir);
                dir.join("engine.log")
            }
        };

        // Security: Refuse to open if path is a symlink (prevents symlink-following attacks)
        let can_open = if log_path.exists() {
            match std::fs::symlink_metadata(&log_path) {
                Ok(meta) => !meta.file_type().is_symlink(),
                Err(_) => false,
            }
        } else {
            true // File doesn't exist yet, safe to create
        };

        if can_open {
            if let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
                if let Ok(file_err) = file.try_clone() {
                    cmd.stdout(Stdio::from(file));
                    cmd.stderr(Stdio::from(file_err));
                } else {
                    cmd.stdout(Stdio::null()).stderr(Stdio::null());
                }
            } else {
                cmd.stdout(Stdio::null()).stderr(Stdio::null());
            }
        } else {
            eprintln!("⚠️ SECURITY: Refusing to open log file {:?} (symlink detected)", log_path);
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }

        #[cfg(target_os = "windows")]
        {
            // On Windows, hide command window
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x08000000;
            cmd.creation_flags(CREATE_NO_WINDOW);

            // NOTE: the WinDivert pre-flight (kill_stray_winws + teardown_windivert)
            // is the caller's job now. It is a multi-second, blocking operation and
            // used to run here synchronously on the tokio worker with the daemon
            // state lock held; UnblockEngine drives it once per transition through
            // spawn_blocking instead. See engine::reset_windivert_driver.
        }

        let child = cmd.spawn()
            .with_context(|| format!("Failed to spawn process {:?}", exe_path))?;

        #[cfg(target_os = "windows")]
        let job_handle = unsafe {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Foundation::*;
            use windows_sys::Win32::System::JobObjects::*;
            use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

            type FnCreateJobObjectW = unsafe extern "system" fn(*const std::ffi::c_void, *const u16) -> HANDLE;
            type FnSetInformationJobObject = unsafe extern "system" fn(HANDLE, u32, *const std::ffi::c_void, u32) -> BOOL;
            type FnAssignProcessToJobObject = unsafe extern "system" fn(HANDLE, HANDLE) -> BOOL;

            let k32_name: Vec<u16> = "kernel32.dll\0".encode_utf16().collect();
            let kernel32 = GetModuleHandleW(k32_name.as_ptr());
            if !kernel32.is_null() {
                if let (Some(p_create), Some(p_set), Some(p_assign)) = (
                    GetProcAddress(kernel32, b"CreateJobObjectW\0".as_ptr()),
                    GetProcAddress(kernel32, b"SetInformationJobObject\0".as_ptr()),
                    GetProcAddress(kernel32, b"AssignProcessToJobObject\0".as_ptr()),
                ) {
                    let create_job: FnCreateJobObjectW = std::mem::transmute(p_create);
                    let set_info: FnSetInformationJobObject = std::mem::transmute(p_set);
                    let assign_job: FnAssignProcessToJobObject = std::mem::transmute(p_assign);

                    let job = create_job(std::ptr::null(), std::ptr::null());
                    if !job.is_null() {
                        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                        set_info(
                            job,
                            JobObjectExtendedLimitInformation as u32,
                            &info as *const _ as *const _,
                            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                        );
                        let process_handle = child.as_raw_handle() as HANDLE;
                        assign_job(job, process_handle);
                        Some(job as isize)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };

        Ok(Self {
            child,
            #[cfg(target_os = "windows")]
            _job_handle: job_handle,
            binary_path: exe_path.to_path_buf(),
            args: args.to_vec(),
        })
    }

    /// Check if the child process is still actively running.
    pub fn is_alive(&mut self) -> bool {
        match self.child.try_wait() {
            Ok(None) => true,
            _ => false,
        }
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// Terminate the child process and release its job object.
    ///
    /// This is deliberately cheap and non-blocking: it does NOT unload the
    /// WinDivert driver winws leaves resident. Driver teardown is a slow,
    /// blocking operation and is owned by UnblockEngine, which runs it exactly
    /// once per stop/start transition off-thread (see reset_windivert_driver).
    /// Doing it here as well meant kill() + Drop::drop() ran it twice back to
    /// back for every handle.
    pub fn kill(&mut self) -> Result<()> {
        let _ = self.child.kill();
        let _ = self.child.wait();

        #[cfg(target_os = "windows")]
        {
            if let Some(job) = self._job_handle.take() {
                unsafe {
                    windows_sys::Win32::Foundation::CloseHandle(job as windows_sys::Win32::Foundation::HANDLE);
                }
            }
        }
        Ok(())
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}
