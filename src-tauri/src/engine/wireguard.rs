use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::process::Command;

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
    /// List all registered WireGuard NetworkExtension tunnels on macOS.
    pub fn list_tunnels() -> Vec<WireGuardTunnelInfo> {
        #[cfg(target_os = "macos")]
        {
            let output = Command::new("scutil")
                .args(["--nc", "list"])
                .output();

            let mut tunnels = Vec::new();
            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    // Example: * (Disconnected)   8F41D33D-453B-4AF3-AF08-E540A9A0C9F7 VPN (com.wireguard.macos) "wg0-daily"
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

                        // Extract name inside quotes
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
        #[cfg(not(target_os = "macos"))]
        {
            Vec::new()
        }
    }

    /// Check connection status of a named WireGuard tunnel.
    pub fn status(tunnel_name: &str) -> WireGuardState {
        #[cfg(target_os = "macos")]
        {
            let output = Command::new("scutil")
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
        #[cfg(not(target_os = "macos"))]
        {
            WireGuardState::Disconnected
        }
    }

    /// Connect the named WireGuard tunnel.
    pub fn connect(tunnel_name: &str) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let status = Command::new("scutil")
                .args(["--nc", "start", tunnel_name])
                .status()
                .with_context(|| format!("Failed to start WireGuard tunnel '{}'", tunnel_name))?;

            if !status.success() {
                return Err(anyhow!("scutil --nc start '{}' exited with code {:?}", tunnel_name, status.code()));
            }
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(anyhow!("WireGuard management only implemented for macOS"))
        }
    }

    /// Disconnect the named WireGuard tunnel.
    pub fn disconnect(tunnel_name: &str) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let status = Command::new("scutil")
                .args(["--nc", "stop", tunnel_name])
                .status()
                .with_context(|| format!("Failed to stop WireGuard tunnel '{}'", tunnel_name))?;

            if !status.success() {
                return Err(anyhow!("scutil --nc stop '{}' exited with code {:?}", tunnel_name, status.code()));
            }
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(anyhow!("WireGuard management only implemented for macOS"))
        }
    }

    /// Connect a tunnel exclusively, disconnecting any conflicting WireGuard tunnel first.
    pub fn connect_exclusive(tunnel_name: &str) -> Result<()> {
        let other_tunnel = if tunnel_name == "wg0-mac" {
            "wg0-daily"
        } else {
            "wg0-mac"
        };

        if Self::status(other_tunnel) == WireGuardState::Connected {
            println!("🔄 Disconnecting active tunnel '{}' before starting '{}'...", other_tunnel, tunnel_name);
            let _ = Self::disconnect(other_tunnel);
            std::thread::sleep(std::time::Duration::from_millis(400));
        }

        Self::connect(tunnel_name)?;

        // If connecting wg0-daily, re-sync learned routes
        if tunnel_name == "wg0-daily" {
            std::thread::sleep(std::time::Duration::from_millis(600));
            crate::engine::smart_router::SmartRouter::sync_active_routes();
        }

        Ok(())
    }

    /// Toggle WireGuard tunnel state exclusively (connects target while ensuring other tunnel is off).
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

    /// Toggle WireGuard tunnel state (alias for toggle_exclusive).
    pub fn toggle(tunnel_name: &str) -> Result<WireGuardState> {
        Self::toggle_exclusive(tunnel_name)
    }
}
