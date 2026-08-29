use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

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
            let output = std::process::Command::new("scutil")
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

            // Also check running Windows services
            let output = std::process::Command::new("sc.exe")
                .args(["query", "type=", "service", "state=", "all"])
                .output();

            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("SERVICE_NAME: WireGuardTunnel$") {
                        let name = trimmed.trim_start_matches("SERVICE_NAME: WireGuardTunnel$").to_string();
                        if !tunnels.iter().any(|t| t.name == name) {
                            let state = Self::status(&name);
                            tunnels.push(WireGuardTunnelInfo {
                                name,
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
                    name: "wg0".to_string(),
                    service_id: "".to_string(),
                    state: Self::status("wg0"),
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
            let output = std::process::Command::new("scutil")
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
            let svc_name = format!("WireGuardTunnel${}", tunnel_name);
            let output = std::process::Command::new("sc.exe")
                .args(["query", &svc_name])
                .output();

            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                if stdout.contains("RUNNING") {
                    WireGuardState::Connected
                } else if stdout.contains("START_PENDING") {
                    WireGuardState::Connecting
                } else if stdout.contains("STOP_PENDING") {
                    WireGuardState::Disconnecting
                } else {
                    WireGuardState::Disconnected
                }
            } else {
                WireGuardState::Disconnected
            }
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
            let status = std::process::Command::new("scutil")
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
            let svc_name = format!("WireGuardTunnel${}", tunnel_name);
            let conf_dpapi = format!(r"C:\Program Files\WireGuard\Data\Configurations\{}.conf.dpapi", tunnel_name);
            let conf_plain = format!(r"C:\Program Files\WireGuard\Data\Configurations\{}.conf", tunnel_name);

            // If service already exists, start it
            let status = std::process::Command::new("net.exe")
                .args(["start", &svc_name])
                .status();

            if let Ok(s) = status {
                if s.success() {
                    return Ok(());
                }
            }

            // Otherwise install service using wireguard.exe
            let conf_path = if std::path::Path::new(&conf_dpapi).exists() {
                conf_dpapi
            } else {
                conf_plain
            };

            let wg_exe = r"C:\Program Files\WireGuard\wireguard.exe";
            if std::path::Path::new(wg_exe).exists() {
                let status = std::process::Command::new(wg_exe)
                    .args(["/installtunnelservice", &conf_path])
                    .status()?;

                if !status.success() {
                    return Err(anyhow!("wireguard.exe /installtunnelservice failed with code {:?}", status.code()));
                }
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
            let status = std::process::Command::new("scutil")
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
            let wg_exe = r"C:\Program Files\WireGuard\wireguard.exe";
            if std::path::Path::new(wg_exe).exists() {
                let _ = std::process::Command::new(wg_exe)
                    .args(["/uninstalltunnelservice", tunnel_name])
                    .status();
            }

            let svc_name = format!("WireGuardTunnel${}", tunnel_name);
            let _ = std::process::Command::new("net.exe")
                .args(["stop", &svc_name])
                .status();

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
        match current {
            WireGuardState::Connected => {
                Self::disconnect(tunnel_name)?;
                Ok(WireGuardState::Disconnected)
            }
            _ => {
                Self::connect_exclusive(tunnel_name)?;
                Ok(WireGuardState::Connected)
            }
        }
    }

    pub fn toggle(tunnel_name: &str) -> Result<WireGuardState> {
        Self::toggle_exclusive(tunnel_name)
    }
}
