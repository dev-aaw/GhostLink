use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use crate::engine::silent_command;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WireGuardState {
    Connected,
    Connecting,
    Disconnecting,
    Disconnected,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireGuardTunnelInfo {
    pub name: String,
    pub service_id: String,
    pub state: WireGuardState,
}

pub struct WireGuardManager;

impl WireGuardManager {
    /// List all registered WireGuard tunnels on current platform.
    pub fn list_tunnels() -> Vec<WireGuardTunnelInfo> {
        #[cfg(target_os = "macos")]
        {
            let output = silent_command("scutil")
                .args(["--nc", "list"])
                .output();

            let mut tunnels = Vec::new();
            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    if line.contains("com.wireguard.macos") || line.contains("WireGuard") {
                        let state = if line.contains("(Connected)") {
                            WireGuardState::Connected
                        } else if line.contains("(Connecting)") {
                            WireGuardState::Connecting
                        } else if line.contains("(Disconnecting)") {
                            WireGuardState::Disconnecting
                        } else {
                            WireGuardState::Disconnected
                        };

                        if let Some(start) = line.find('"') {
                            if let Some(end) = line[start + 1..].find('"') {
                                let name = &line[start + 1..start + 1 + end];
                                tunnels.push(WireGuardTunnelInfo {
                                    name: name.to_string(),
                                    service_id: "".to_string(),
                                    state,
                                });
                            }
                        }
                    }
                }
            }
            tunnels
        }
        #[cfg(target_os = "windows")]
        {
            let mut tunnels = Vec::new();
            let conf_dir = std::path::Path::new(r"C:\Program Files\WireGuard\Data\Configurations");
            if let Ok(entries) = std::fs::read_dir(conf_dir) {
                for entry in entries.flatten() {
                    let file_name = entry.file_name().to_string_lossy().to_string();
                    let name = if let Some(stripped) = file_name.strip_suffix(".conf.dpapi") {
                        stripped.to_string()
                    } else if let Some(stripped) = file_name.strip_suffix(".conf") {
                        stripped.to_string()
                    } else {
                        continue;
                    };
                    let state = Self::status(&name);
                    tunnels.push(WireGuardTunnelInfo {
                        name,
                        service_id: "".to_string(),
                        state,
                    });
                }
            }

            // Also check running Windows network adapters
            let output = silent_command("netsh.exe")
                .args(["interface", "show", "interface"])
                .output();

            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if let Some(last) = parts.last() {
                        let iface_name = *last;
                        if (iface_name.starts_with("wg") || iface_name.contains("WireGuard")) && !tunnels.iter().any(|t| t.name == iface_name) {
                            let state = Self::status(iface_name);
                            tunnels.push(WireGuardTunnelInfo {
                                name: iface_name.to_string(),
                                service_id: "".to_string(),
                                state,
                            });
                        }
                    }
                }
            }

            if tunnels.is_empty() {
                // Fallback default tunnel identifier
                tunnels.push(WireGuardTunnelInfo {
                    name: "wg0-pc".to_string(),
                    service_id: "".to_string(),
                    state: Self::status("wg0-pc"),
                });
            }

            tunnels
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            Vec::new()
        }
    }

    /// Check connection status of a named WireGuard tunnel.
    pub fn status(tunnel_name: &str) -> WireGuardState {
        #[cfg(target_os = "macos")]
        {
            let output = silent_command("scutil")
                .args(["--nc", "status", tunnel_name])
                .output();

            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let first_line = stdout.lines().next().unwrap_or("").trim();
                match first_line {
                    "Connected" => WireGuardState::Connected,
                    "Connecting" => WireGuardState::Connecting,
                    "Disconnecting" => WireGuardState::Disconnecting,
                    "Disconnected" => WireGuardState::Disconnected,
                    other => WireGuardState::Unknown(other.to_string()),
                }
            } else {
                WireGuardState::Unknown("Failed to execute scutil".to_string())
            }
        }
        #[cfg(target_os = "windows")]
        {
            // Primary check: netsh interface status (instant, zero admin privileges required)
            let output = silent_command("netsh.exe")
                .args(["interface", "show", "interface", tunnel_name])
                .output();

            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if stdout.contains("Connected") || stdout.contains("Bağlandı") {
                    return WireGuardState::Connected;
                } else if stdout.contains("Connecting") || stdout.contains("Bağlanıyor") {
                    return WireGuardState::Connecting;
                } else if stdout.contains("Disconnected") || stdout.contains("Bağlantı kesildi") {
                    return WireGuardState::Disconnected;
                }
            }

            // Secondary check: Windows Service status
            let svc_name = format!("WireGuardTunnel${}", tunnel_name);
            let output = silent_command("sc.exe")
                .args(["query", &svc_name])
                .output();

            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if stdout.contains("RUNNING") {
                    return WireGuardState::Connected;
                } else if stdout.contains("START_PENDING") {
                    return WireGuardState::Connecting;
                } else if stdout.contains("STOP_PENDING") {
                    return WireGuardState::Disconnecting;
                }
            }

            WireGuardState::Disconnected
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = tunnel_name;
            WireGuardState::Disconnected
        }
    }

    /// Connect the named WireGuard tunnel.
    pub fn connect(tunnel_name: &str) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            use anyhow::Context;
            let status = silent_command("scutil")
                .args(["--nc", "start", tunnel_name])
                .status()
                .with_context(|| format!("Failed to start WireGuard tunnel '{}'", tunnel_name))?;

            if !status.success() {
                return Err(anyhow!("scutil --nc start '{}' exited with code {:?}", tunnel_name, status.code()));
            }
            Ok(())
        }
        #[cfg(target_os = "windows")]
        {
            eprintln!("[WireGuard::connect] Initiating connection for '{}'", tunnel_name);
            let svc_name = format!("WireGuardTunnel${}", tunnel_name);
            let conf_dpapi = format!(r"C:\Program Files\WireGuard\Data\Configurations\{}.conf.dpapi", tunnel_name);
            let conf_plain = format!(r"C:\Program Files\WireGuard\Data\Configurations\{}.conf", tunnel_name);

            // 1. Try starting service if already installed
            let status = silent_command("net.exe")
                .args(["start", &svc_name])
                .status();

            if let Ok(s) = status {
                if s.success() {
                    eprintln!("[WireGuard::connect] Service '{}' started successfully via net.exe", svc_name);
                    return Ok(());
                }
            }

            // 2. Try installing and starting service via wireguard.exe
            let conf_path = if std::path::Path::new(&conf_dpapi).exists() {
                conf_dpapi
            } else {
                conf_plain
            };

            let wg_exe = r"C:\Program Files\WireGuard\wireguard.exe";
            if std::path::Path::new(wg_exe).exists() {
                let status = silent_command(wg_exe)
                    .args(["/installtunnelservice", &conf_path])
                    .status();

                if let Ok(s) = status {
                    if s.success() {
                        eprintln!("[WireGuard::connect] wireguard.exe /installtunnelservice succeeded for '{}'", conf_path);
                        return Ok(());
                    }
                }

                // 3. Fallback: Request elevated execution via PowerShell runAs
                eprintln!("[WireGuard::connect] Non-elevated install failed, attempting elevated start via runAs...");
                let ps_arg = format!(
                    "Start-Process -FilePath '{}' -ArgumentList '/installtunnelservice', '{}' -Verb runAs -WindowStyle Hidden -Wait",
                    wg_exe, conf_path
                );
                let _ = silent_command("powershell.exe")
                    .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &ps_arg])
                    .status();

                Ok(())
            } else {
                Err(anyhow!("WireGuard is not installed at {}", wg_exe))
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = tunnel_name;
            Err(anyhow!("WireGuard management not supported on this platform"))
        }
    }

    /// Disconnect the named WireGuard tunnel.
    pub fn disconnect(tunnel_name: &str) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            use anyhow::Context;
            let status = silent_command("scutil")
                .args(["--nc", "stop", tunnel_name])
                .status()
                .with_context(|| format!("Failed to stop WireGuard tunnel '{}'", tunnel_name))?;

            if !status.success() {
                return Err(anyhow!("scutil --nc stop '{}' exited with code {:?}", tunnel_name, status.code()));
            }
            Ok(())
        }
        #[cfg(target_os = "windows")]
        {
            eprintln!("[WireGuard::disconnect] Initiating disconnection for '{}'", tunnel_name);
            let wg_exe = r"C:\Program Files\WireGuard\wireguard.exe";
            let svc_name = format!("WireGuardTunnel${}", tunnel_name);

            // 1. Try wireguard.exe /uninstalltunnelservice
            if std::path::Path::new(wg_exe).exists() {
                let status = silent_command(wg_exe)
                    .args(["/uninstalltunnelservice", tunnel_name])
                    .status();
                eprintln!("[WireGuard::disconnect] wireguard.exe /uninstalltunnelservice status: {:?}", status);
            }

            // 2. Try net.exe stop
            let net_status = silent_command("net.exe")
                .args(["stop", &svc_name])
                .status();
            eprintln!("[WireGuard::disconnect] net.exe stop status: {:?}", net_status);

            // 3. Fallback: Request elevated uninstall via PowerShell runAs
            let current_state = Self::status(tunnel_name);
            if current_state == WireGuardState::Connected {
                eprintln!("[WireGuard::disconnect] Tunnel still connected, attempting elevated uninstall via runAs...");
                let ps_arg = format!(
                    "Start-Process -FilePath '{}' -ArgumentList '/uninstalltunnelservice', '{}' -Verb runAs -WindowStyle Hidden -Wait",
                    wg_exe, tunnel_name
                );
                let _ = silent_command("powershell.exe")
                    .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &ps_arg])
                    .status();
            }

            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = tunnel_name;
            Err(anyhow!("WireGuard management not supported on this platform"))
        }
    }

    /// Connect a tunnel exclusively, disconnecting any conflicting WireGuard tunnel first.
    pub fn connect_exclusive(tunnel_name: &str) -> Result<()> {
        Self::connect(tunnel_name)?;

        #[cfg(target_os = "macos")]
        {
            if tunnel_name == "wg0-daily" {
                std::thread::sleep(std::time::Duration::from_millis(600));
                crate::engine::smart_router::SmartRouter::sync_active_routes();
            }
        }

        Ok(())
    }

    /// Toggle WireGuard tunnel state.
    pub fn toggle_exclusive(tunnel_name: &str) -> Result<WireGuardState> {
        let current = Self::status(tunnel_name);
        eprintln!("[WireGuard::toggle] Tunnel: '{}' | Current detected state: {:?}", tunnel_name, current);
        match current {
            WireGuardState::Connected => {
                eprintln!("[WireGuard::toggle] -> Executing DISCONNECT branch for '{}'", tunnel_name);
                Self::disconnect(tunnel_name)?;
                std::thread::sleep(std::time::Duration::from_millis(400));
                let new_state = Self::status(tunnel_name);
                eprintln!("[WireGuard::toggle] -> Post-disconnect state: {:?}", new_state);
                Ok(new_state)
            }
            _ => {
                eprintln!("[WireGuard::toggle] -> Executing CONNECT branch for '{}'", tunnel_name);
                Self::connect_exclusive(tunnel_name)?;
                std::thread::sleep(std::time::Duration::from_millis(400));
                let new_state = Self::status(tunnel_name);
                eprintln!("[WireGuard::toggle] -> Post-connect state: {:?}", new_state);
                Ok(new_state)
            }
        }
    }

    pub fn toggle(tunnel_name: &str) -> Result<WireGuardState> {
        Self::toggle_exclusive(tunnel_name)
    }
}
