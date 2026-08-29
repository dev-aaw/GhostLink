use anyhow::{anyhow, Context, Result};
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::engine::ipc::{DaemonClient, DEFAULT_SOCKET_PATH};

pub const PLIST_LABEL: &str = "com.ghostlink.helper";
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/com.ghostlink.helper.plist";
pub const SERVICE_INSTALL_DIR: &str = "/Library/Application Support/GhostLink";
pub const SERVICE_DAEMON_BIN: &str = "/Library/Application Support/GhostLink/ghostlink_daemon";

pub struct ServiceManager {
    daemon_client: DaemonClient,
}

impl Default for ServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ServiceManager {
    pub fn new() -> Self {
        Self {
            daemon_client: DaemonClient::default(),
        }
    }

    pub fn client(&self) -> &DaemonClient {
        &self.daemon_client
    }

    /// Checks if the LaunchDaemon is installed and loaded in launchd.
    pub fn is_plist_installed(&self) -> bool {
        Path::new(PLIST_PATH).exists()
    }

    /// Checks if launchctl reports the service as active.
    pub fn is_launchctl_loaded(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            let output = Command::new("launchctl")
                .args(["list", PLIST_LABEL])
                .output();
            if let Ok(out) = output {
                return out.status.success();
            }
        }
        false
    }

    /// Checks if the daemon process is running and responding to socket ping.
    pub async fn is_daemon_running(&self) -> bool {
        self.daemon_client.is_daemon_alive().await
    }

    /// Generates standard macOS LaunchDaemon plist content for GhostLink.
    pub fn generate_plist_content(daemon_bin_path: &Path) -> String {
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/ghostlink_daemon.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/ghostlink_daemon_err.log</string>
</dict>
</plist>
"#,
            PLIST_LABEL,
            daemon_bin_path.to_string_lossy()
        )
    }

    /// Installs the privileged LaunchDaemon service (requires sudo/root if called directly).
    pub async fn install(&self, source_daemon_bin: &Path) -> Result<()> {
        #[cfg(not(target_os = "macos"))]
        {
            return Err(anyhow!("LaunchDaemon is only supported on macOS"));
        }

        #[cfg(target_os = "macos")]
        {
            println!("⚙️  Installing GhostLink Privileged Helper Daemon (macOS LaunchDaemon)...");

            if !source_daemon_bin.exists() {
                return Err(anyhow!("Source daemon binary not found: {:?}", source_daemon_bin));
            }

            let is_root = unsafe { libc::geteuid() == 0 };

            // Helper: run a command optionally via sudo
            let run_cmd = |program: &str, args: &[&str]| -> Result<()> {
                let status = if is_root {
                    Command::new(program).args(args).status()
                } else {
                    let mut sudo_args = vec![program];
                    sudo_args.extend_from_slice(args);
                    Command::new("sudo").args(&sudo_args).status()
                };
                match status {
                    Ok(s) if s.success() => Ok(()),
                    Ok(s) => Err(anyhow!("{} {:?} exited with code {:?}", program, args, s.code())),
                    Err(e) => Err(anyhow!("Failed to execute {} {:?}: {}", program, args, e)),
                }
            };

            // 1. Create /Library/Application Support/GhostLink
            let install_dir = Path::new(SERVICE_INSTALL_DIR);
            if !install_dir.exists() {
                run_cmd("mkdir", &["-p", SERVICE_INSTALL_DIR])
                    .context("Failed to create install directory")?;
            }

            // 2. Copy daemon binary (safe: no shell interpolation)
            run_cmd("cp", &["-f", &source_daemon_bin.to_string_lossy(), SERVICE_DAEMON_BIN])
                .context("Failed to copy daemon binary")?;

            // 3. Set ownership and executable permissions
            run_cmd("chown", &["root:wheel", SERVICE_DAEMON_BIN])
                .context("Failed to set binary ownership")?;
            run_cmd("chmod", &["755", SERVICE_DAEMON_BIN])
                .context("Failed to set binary permissions")?;

            // 4. Generate and write plist
            let dest_bin = Path::new(SERVICE_DAEMON_BIN);
            let plist_content = Self::generate_plist_content(dest_bin);
            let tmp_plist = "/tmp/com.ghostlink.helper.plist";
            fs::write(tmp_plist, plist_content)?;

            run_cmd("cp", &["-f", tmp_plist, PLIST_PATH])
                .context("Failed to write LaunchDaemon plist")?;
            run_cmd("chown", &["root:wheel", PLIST_PATH])
                .context("Failed to set plist ownership")?;
            run_cmd("chmod", &["644", PLIST_PATH])
                .context("Failed to set plist permissions")?;

            let _ = fs::remove_file(tmp_plist);

            // 5. Unload previous instance if loaded
            if is_root {
                let _ = Command::new("launchctl").args(["unload", "-w", PLIST_PATH]).status();
            } else {
                let _ = Command::new("sudo").args(["launchctl", "unload", "-w", PLIST_PATH]).status();
            }

            // 6. Load daemon
            println!("🚀 Loading LaunchDaemon into launchd...");
            run_cmd("launchctl", &["load", "-w", PLIST_PATH])
                .context("Failed to load plist into launchctl")?;

            // 7. Wait for daemon socket to become ready
            println!("⏳ Waiting for privileged socket to initialize ({DEFAULT_SOCKET_PATH})...");
            let mut ready = false;
            for _ in 0..20 {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                if self.is_daemon_running().await {
                    ready = true;
                    break;
                }
            }

            if !ready {
                println!("⚠️ Daemon socket not responding yet. Check /var/log/ghostlink_daemon_err.log");
            } else {
                let (version, is_root, pid) = self.daemon_client.ping().await?;
                println!("✅ GhostLink Privileged Helper installed & running!");
                println!("   • Version: {}", version);
                println!("   • Running as root: {}", if is_root { "YES (Privileged)" } else { "NO" });
                println!("   • PID: {}", pid);
                println!("   • Socket: {}", DEFAULT_SOCKET_PATH);
            }

            Ok(())
        }
    }

    /// Uninstalls the privileged LaunchDaemon service.
    pub async fn uninstall(&self) -> Result<()> {
        #[cfg(not(target_os = "macos"))]
        {
            return Err(anyhow!("LaunchDaemon is only supported on macOS"));
        }

        #[cfg(target_os = "macos")]
        {
            println!("🛑 Uninstalling GhostLink Privileged Helper Daemon...");

            let is_root = unsafe { libc::geteuid() == 0 };

            let run_cmd = |program: &str, args: &[&str]| {
                if is_root {
                    let _ = Command::new(program).args(args).status();
                } else {
                    let mut sudo_args = vec![program];
                    sudo_args.extend_from_slice(args);
                    let _ = Command::new("sudo").args(&sudo_args).status();
                }
            };

            // 1. Tell daemon to stop engine gracefully
            if self.is_daemon_running().await {
                let _ = self.daemon_client.stop().await;
            }

            // 2. Unload from launchd
            if Path::new(PLIST_PATH).exists() {
                run_cmd("launchctl", &["unload", "-w", PLIST_PATH]);
                run_cmd("rm", &["-f", PLIST_PATH]);
            }

            // 3. Remove socket
            run_cmd("rm", &["-f", DEFAULT_SOCKET_PATH]);

            // 4. Remove installed binary
            if Path::new(SERVICE_DAEMON_BIN).exists() {
                run_cmd("rm", &["-rf", SERVICE_INSTALL_DIR]);
            }

            println!("✨ GhostLink Privileged Helper uninstalled successfully.");
            Ok(())
        }
    }
}
