use anyhow::{Context, Result};
use std::process::Command;

pub struct SystemProxyManager {
    #[allow(dead_code)]
    active_service: Option<String>,
    #[allow(dead_code)]
    socks_port: u16,
}

impl SystemProxyManager {
    pub fn new(socks_port: u16) -> Self {
        Self {
            active_service: Self::detect_primary_macos_service(),
            socks_port,
        }
    }

    /// Detect active primary network interface on macOS (e.g. "Wi-Fi" or "Ethernet").
    pub fn detect_primary_macos_service() -> Option<String> {
        #[cfg(target_os = "macos")]
        {
            let output = Command::new("networksetup")
                .args(["-listnetworkserviceorder"])
                .output()
                .ok()?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                if line.contains("Hardware Port: Wi-Fi") || line.contains("Wi-Fi") {
                    return Some("Wi-Fi".to_string());
                }
                if line.contains("Hardware Port: Ethernet") || line.contains("Ethernet") {
                    return Some("Ethernet".to_string());
                }
            }
            Some("Wi-Fi".to_string())
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    /// Enable SOCKS5 proxy on macOS.
    pub fn enable_macos_proxy(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let service = self.active_service.as_deref().unwrap_or("Wi-Fi");
            println!("🌐 Configuring macOS SOCKS proxy on [{}] -> 127.0.0.1:{}", service, self.socks_port);

            let status = Command::new("networksetup")
                .args(["-setsocksfirewallproxy", service, "127.0.0.1", &self.socks_port.to_string()])
                .status()
                .context("Failed to set SOCKS proxy")?;

            if !status.success() {
                return Err(anyhow::anyhow!("networksetup -setsocksfirewallproxy failed with code {:?}", status.code()));
            }

            let enable_status = Command::new("networksetup")
                .args(["-setsocksfirewallproxystate", service, "on"])
                .status()
                .context("Failed to enable SOCKS proxy state")?;

            if !enable_status.success() {
                return Err(anyhow::anyhow!("networksetup -setsocksfirewallproxystate on failed"));
            }
        }
        Ok(())
    }

    /// Disable SOCKS5 proxy on macOS.
    pub fn disable_macos_proxy(&self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let service = self.active_service.as_deref().unwrap_or("Wi-Fi");
            println!("🌐 Disabling macOS SOCKS proxy on [{}]...", service);

            let _ = Command::new("networksetup")
                .args(["-setsocksfirewallproxystate", service, "off"])
                .status();
        }
        Ok(())
    }
}

impl Drop for SystemProxyManager {
    fn drop(&mut self) {
        let _ = self.disable_macos_proxy();
    }
}
