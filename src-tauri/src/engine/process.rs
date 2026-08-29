use anyhow::{Context, Result};
use std::path::Path;
use std::process::{Child, Command, Stdio};

pub struct ProcessHandle {
    child: Child,
    pub binary_path: std::path::PathBuf,
    pub args: Vec<String>,
}

impl ProcessHandle {
    /// Spawn the DPI engine process (tpws or winws) with the specified arguments.
    pub fn spawn(exe_path: &Path, args: &[String]) -> Result<Self> {
        let mut cmd = Command::new(exe_path);
        cmd.args(args);

        // Security: Write logs to ~/.ghostlink/engine.log (user-owned directory),
        // NOT /tmp (world-writable, vulnerable to symlink attacks when daemon runs as root).
        let log_path = {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            let dir = std::path::PathBuf::from(home).join(".ghostlink");
            let _ = std::fs::create_dir_all(&dir);
            dir.join("engine.log")
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
        }

        let child = cmd.spawn()
            .with_context(|| format!("Failed to spawn process {:?}", exe_path))?;

        Ok(Self {
            child,
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

    /// Terminate the child process immediately.
    pub fn kill(&mut self) -> Result<()> {
        let _ = self.child.kill();
        let _ = self.child.wait();
        Ok(())
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}
