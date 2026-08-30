use anyhow::{anyhow, Context, Result};
use std::path::Path;
use crate::engine::silent_command;
use crate::engine::ipc::DaemonClient;

pub const PLIST_LABEL: &str = "com.ghostlink.helper";
pub const PLIST_PATH: &str = "/Library/LaunchDaemons/com.ghostlink.helper.plist";
pub const SERVICE_INSTALL_DIR: &str = "/Library/Application Support/GhostLink";
pub const SERVICE_DAEMON_BIN: &str = "/Library/Application Support/GhostLink/ghostlink_daemon";

pub const WIN_TASK_NAME: &str = "GhostLinkService";

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

    /// Checks if the LaunchDaemon / Windows Task is installed.
    pub fn is_service_installed(&self) -> bool {
        #[cfg(target_os = "macos")]
        {
            Path::new(PLIST_PATH).exists()
        }
        #[cfg(target_os = "windows")]
        {
            let output = silent_command("schtasks.exe")
                .args(["/Query", "/TN", WIN_TASK_NAME])
                .output();
            if let Ok(out) = output {
                return out.status.success();
            }
            false
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            false
        }
    }

    /// Checks if the daemon process is running and responding to socket ping.
    pub async fn is_daemon_running(&self) -> bool {
        self.daemon_client.is_daemon_alive().await
    }

    /// Generates standard macOS LaunchDaemon plist content for GhostLink.
    #[cfg(target_os = "macos")]
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

    /// Installs the privileged helper service (macOS LaunchDaemon / Windows Task Scheduler).
    pub async fn install(&self, source_daemon_bin: &Path) -> Result<()> {
        if !source_daemon_bin.exists() {
            return Err(anyhow!("Source daemon binary not found: {:?}", source_daemon_bin));
        }

        #[cfg(target_os = "macos")]
        {
            println!("⚙️  Installing GhostLink Privileged Helper Daemon (macOS LaunchDaemon)...");

            let is_root = unsafe { libc::geteuid() == 0 };

            let run_cmd = |program: &str, args: &[&str]| -> Result<()> {
                let status = if is_root {
                    silent_command(program).args(args).status()
                } else {
                    let mut sudo_args = vec![program];
                    sudo_args.extend_from_slice(args);
                    silent_command("sudo").args(&sudo_args).status()
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
            std::fs::write(tmp_plist, plist_content)?;

            run_cmd("cp", &["-f", tmp_plist, PLIST_PATH])
                .context("Failed to write LaunchDaemon plist")?;
            run_cmd("chown", &["root:wheel", PLIST_PATH])
                .context("Failed to set plist ownership")?;
            run_cmd("chmod", &["644", PLIST_PATH])
                .context("Failed to set plist permissions")?;

            let _ = std::fs::remove_file(tmp_plist);

            // 5. Unload previous instance if loaded
            if is_root {
                let _ = silent_command("launchctl").args(["unload", "-w", PLIST_PATH]).status();
            } else {
                let _ = silent_command("sudo").args(["launchctl", "unload", "-w", PLIST_PATH]).status();
            }

            // 6. Load daemon
            println!("🚀 Loading LaunchDaemon into launchd...");
            run_cmd("launchctl", &["load", "-w", PLIST_PATH])
                .context("Failed to load plist into launchctl")?;

            // 7. Wait for daemon socket to become ready
            println!("⏳ Waiting for privileged socket to initialize...");
            let mut ready = false;
            for _ in 0..20 {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                if self.is_daemon_running().await {
                    ready = true;
                    break;
                }
            }

            if ready {
                let (version, is_root, pid) = self.daemon_client.ping().await?;
                println!("✅ GhostLink Privileged Helper installed & running!");
                println!("   • Version: {}", version);
                println!("   • Running as root: {}", if is_root { "YES (Privileged)" } else { "NO" });
                println!("   • PID: {}", pid);
            }

            Ok(())
        }

        #[cfg(target_os = "windows")]
        {
            println!("⚙️  Registering GhostLink Elevated Background Service (Windows Task Scheduler)...");

            let daemon_path_str = source_daemon_bin.to_string_lossy();

            // 1. Create elevated task scheduled to run with HIGHEST available privileges on logon
            let status = silent_command("schtasks.exe")
                .args([
                    "/Create",
                    "/TN", WIN_TASK_NAME,
                    "/TR", &format!("\"{}\"", daemon_path_str),
                    "/RL", "HIGHEST",
                    "/SC", "ONLOGON",
                    "/F"
                ])
                .status()
                .context("Failed to execute schtasks.exe to register service")?;

            if !status.success() {
                return Err(anyhow!("schtasks.exe /Create failed with code {:?}", status.code()));
            }

            // 2. Configure task reliability settings: auto-restart on crash, no battery restrictions, no 72h limit
            let _ = silent_command("powershell.exe")
                .args([
                    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                    "$t = Get-ScheduledTask -TaskName 'GhostLinkService' -ErrorAction SilentlyContinue; if ($t) { $t.Settings.DisallowStartIfOnBatteries = $false; $t.Settings.StopIfGoingOnBatteries = $false; $t.Settings.ExecutionTimeLimit = 'PT0S'; $t.Settings.RestartCount = 999; $t.Settings.RestartInterval = 'PT1M'; $t.Settings.StartWhenAvailable = $true; Set-ScheduledTask -InputObject $t -ErrorAction SilentlyContinue }"
                ])
                .status();

            // 3. Start the task immediately
            println!("🚀 Starting GhostLink Windows background service...");
            let _ = silent_command("schtasks.exe")
                .args(["/Run", "/TN", WIN_TASK_NAME])
                .status();

            // 3. Wait for IPC to become ready
            let mut ready = false;
            for _ in 0..20 {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                if self.is_daemon_running().await {
                    ready = true;
                    break;
                }
            }

            if ready {
                let (version, is_root, pid) = self.daemon_client.ping().await?;
                println!("✅ GhostLink Windows Elevated Service registered & active!");
                println!("   • Version: {}", version);
                println!("   • Elevated Admin: {}", if is_root { "YES" } else { "NO" });
                println!("   • PID: {}", pid);
            }

            Ok(())
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            Err(anyhow!("Service installation only supported on macOS and Windows"))
        }
    }

    /// Uninstalls the privileged helper service.
    pub async fn uninstall(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            println!("🛑 Uninstalling GhostLink Privileged Helper Daemon (macOS)...");

            let is_root = unsafe { libc::geteuid() == 0 };

            let run_cmd = |program: &str, args: &[&str]| {
                if is_root {
                    let _ = silent_command(program).args(args).status();
                } else {
                    let mut sudo_args = vec![program];
                    sudo_args.extend_from_slice(args);
                    let _ = silent_command("sudo").args(&sudo_args).status();
                }
            };

            if self.is_daemon_running().await {
                let _ = self.daemon_client.stop().await;
            }

            if Path::new(PLIST_PATH).exists() {
                run_cmd("launchctl", &["unload", "-w", PLIST_PATH]);
                run_cmd("rm", &["-f", PLIST_PATH]);
            }

            run_cmd("rm", &["-f", crate::engine::ipc::DEFAULT_SOCKET_PATH]);

            if Path::new(SERVICE_DAEMON_BIN).exists() {
                run_cmd("rm", &["-rf", SERVICE_INSTALL_DIR]);
            }

            println!("✨ GhostLink Privileged Helper uninstalled successfully.");
            Ok(())
        }

        #[cfg(target_os = "windows")]
        {
            println!("🛑 Deregistering GhostLink Background Service (Windows)...");

            if self.is_daemon_running().await {
                let _ = self.daemon_client.shutdown_daemon().await;
            }

            let _ = silent_command("schtasks.exe")
                .args(["/End", "/TN", WIN_TASK_NAME])
                .status();

            let _ = silent_command("schtasks.exe")
                .args(["/Delete", "/TN", WIN_TASK_NAME, "/F"])
                .status();

            println!("✨ GhostLink Windows Service deregistered successfully.");
            Ok(())
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            Err(anyhow!("Service uninstall only supported on macOS and Windows"))
        }
    }
}
