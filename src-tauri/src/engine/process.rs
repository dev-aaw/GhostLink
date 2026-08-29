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
        cmd.args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

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
