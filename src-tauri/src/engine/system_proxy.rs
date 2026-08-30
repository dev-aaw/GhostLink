use anyhow::Result;
#[cfg(target_os = "macos")]
use anyhow::Context;
#[cfg(target_os = "macos")]
use std::process::Command;

pub struct SystemProxyManager {
    #[allow(dead_code)]
    active_service: Option<String>,
    #[allow(dead_code)]
    socks_port: u16,
    proxy_is_active: bool,
}

impl SystemProxyManager {
    pub fn new(socks_port: u16) -> Self {
        Self {
            active_service: Self::detect_primary_macos_service(),
            socks_port,
            proxy_is_active: false,
        }
    }

    /// Dynamically detect the active primary network service on macOS (e.g. "Wi-Fi", "Ethernet", "USB LAN").
    /// Matches the active default gateway interface (e.g. en0) against the macOS Network Service Order table.
    pub fn detect_primary_macos_service() -> Option<String> {
        #[cfg(target_os = "macos")]
        {
            // 1. Determine active default route interface (e.g. en0, en5)
            let mut active_device: Option<String> = None;
            if let Ok(output) = Command::new("route").args(["-n", "get", "default"]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("interface:") {
                        if let Some(dev) = trimmed.split(':').nth(1) {
                            let dev_clean = dev.trim();
                            if !dev_clean.is_empty() && !dev_clean.starts_with("utun") {
                                active_device = Some(dev_clean.to_string());
                                break;
                            }
                        }
                    }
                }
            }

            // 2. Query networkserviceorder table
            let output = Command::new("networksetup")
                .args(["-listnetworkserviceorder"])
                .output()
                .ok()?;

            let stdout = String::from_utf8_lossy(&output.stdout);

            let mut current_service: Option<String> = None;
            let mut first_valid_service: Option<String> = None;

            for line in stdout.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('(') && trimmed.contains(')') && !trimmed.contains("Hardware Port:") {
                    if let Some(idx) = trimmed.find(')') {
                        let sname = trimmed[idx + 1..].trim();
                        if !sname.is_empty() && !sname.starts_with('*') {
                            current_service = Some(sname.to_string());
                        }
                    }
                } else if trimmed.contains("Device:") && trimmed.contains("Hardware Port:") {
                    if let Some(dev_idx) = trimmed.find("Device:") {
                        let dev_part = &trimmed[dev_idx + 7..];
                        let dev_name = dev_part.trim_end_matches(')').trim();

                        if let Some(ref sname) = current_service {
                            if !dev_name.is_empty() {
                                if first_valid_service.is_none() {
                                    first_valid_service = Some(sname.clone());
                                }
                                if let Some(ref target_dev) = active_device {
                                    if dev_name.eq_ignore_ascii_case(target_dev) {
                                        return Some(sname.clone());
                                    }
                                }
                            }
                        }
                    }
                    current_service = None;
                }
            }

            // 3. Fallback to first non-disabled physical hardware service
            if let Some(svc) = first_valid_service {
                return Some(svc);
            }

            None
        }
        #[cfg(not(target_os = "macos"))]
        {
            None
        }
    }

    /// Enable SOCKS5 proxy and secure DNS on macOS.
    pub fn enable_macos_proxy(&mut self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let detected = self.active_service.clone().or_else(Self::detect_primary_macos_service);
            let service = match detected {
                Some(ref s) => s.as_str(),
                None => anyhow::bail!("Failed to detect active macOS network service (no Wi-Fi/Ethernet found)"),
            };

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

            // Also configure clean DNS servers (Cloudflare / Google) so DNS poisoning cannot redirect traffic to ISP block splash servers
            let _ = Command::new("networksetup")
                .args(["-setdnsservers", service, "1.1.1.1", "1.0.0.1", "8.8.8.8"])
                .status();

            self.proxy_is_active = true;
        }
        Ok(())
    }

    /// Disable SOCKS5 proxy and reset DNS on macOS.
    pub fn disable_macos_proxy(&mut self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let detected = self.active_service.clone().or_else(Self::detect_primary_macos_service);
            if let Some(ref service) = detected {
                println!("🌐 Disabling macOS SOCKS proxy and restoring network settings on [{}]...", service);

                let _ = Command::new("networksetup")
                    .args(["-setsocksfirewallproxystate", service, "off"])
                    .status();

                let _ = Command::new("networksetup")
                    .args(["-setdnsservers", service, "Empty"])
                    .status();
            }

            self.proxy_is_active = false;
        }
        Ok(())
    }

    /// Detect active physical network adapters on Windows.
    pub fn detect_active_windows_adapters() -> Vec<String> {
        #[cfg(target_os = "windows")]
        {
            let mut adapters = Vec::new();
            let output = crate::engine::silent_command("netsh.exe")
                .args(["interface", "ipv4", "show", "interfaces"])
                .output();

            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                for line in stdout.lines() {
                    let trimmed = line.trim();
                    if trimmed.contains("connected") || trimmed.contains("Bağlandı") {
                        if let Some(name_start) = trimmed.rfind("connected") {
                            let name = trimmed[name_start + 9..].trim();
                            if !name.is_empty() && !name.starts_with("Loopback") && !name.starts_with("wg") {
                                adapters.push(name.to_string());
                            }
                        } else if let Some(name_start) = trimmed.rfind("Bağlandı") {
                            let name = trimmed[name_start + 8..].trim();
                            if !name.is_empty() && !name.starts_with("Loopback") && !name.starts_with("wg") {
                                adapters.push(name.to_string());
                            }
                        }
                    }
                }
            }

            if adapters.is_empty() {
                adapters.push("Ethernet".to_string());
                adapters.push("Wi-Fi".to_string());
            }

            adapters
        }
        #[cfg(not(target_os = "windows"))]
        {
            Vec::new()
        }
    }

    /// Configure static clean DNS servers on all active Windows adapters.
    pub fn configure_windows_dns(servers: &[String]) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            if servers.is_empty() {
                return Self::reset_windows_dns();
            }

            let mut adapters = Self::detect_active_windows_adapters();
            if !adapters.iter().any(|a| a == "Ethernet") {
                adapters.push("Ethernet".to_string());
            }
            if !adapters.iter().any(|a| a == "Wi-Fi") {
                adapters.push("Wi-Fi".to_string());
            }

            println!("🌐 [Windows DNS] Configuring clean DNS on active adapters {:?} to {:?}", adapters, servers);

            let s_joined = servers.iter().map(|s| format!("'{}'", s)).collect::<Vec<_>>().join(",");

            for adapter in &adapters {
                // 1. PowerShell Set-DnsClientServerAddress (fastest & most reliable on Windows 10/11)
                let ps_cmd = format!(
                    "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses @({}) -ErrorAction SilentlyContinue",
                    adapter, s_joined
                );
                let _ = crate::engine::silent_command("powershell.exe")
                    .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &ps_cmd])
                    .status();

                // 2. netsh IPv4 static primary & secondary DNS fallback
                let _ = crate::engine::silent_command("netsh.exe")
                    .args(["interface", "ipv4", "set", "dns", adapter, "static", &servers[0], "primary"])
                    .status();

                for (idx, server) in servers.iter().skip(1).enumerate() {
                    let _ = crate::engine::silent_command("netsh.exe")
                        .args(["interface", "ipv4", "add", "dns", adapter, server, &format!("index={}", idx + 2)])
                        .status();
                }
            }

            // 3. Flush DNS Cache
            let _ = crate::engine::silent_command("ipconfig.exe")
                .args(["/flushdns"])
                .status();
            let _ = crate::engine::silent_command("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Clear-DnsClientCache -ErrorAction SilentlyContinue"])
                .status();

            println!("✨ [Windows DNS] Clean DNS configured and cache flushed successfully.");
        }
        Ok(())
    }

    /// Enable clean DNS on Windows for active engine state.
    pub fn enable_windows_dns(&mut self, servers: &[String]) -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            Self::configure_windows_dns(servers)?;
            self.proxy_is_active = true;
        }
        Ok(())
    }

    /// Reset DNS settings on all Windows adapters to DHCP (Automatic) and flush DNS cache.
    pub fn reset_windows_dns() -> Result<()> {
        #[cfg(target_os = "windows")]
        {
            let mut adapters = Self::detect_active_windows_adapters();
            if !adapters.iter().any(|a| a == "Ethernet") {
                adapters.push("Ethernet".to_string());
            }
            if !adapters.iter().any(|a| a == "Wi-Fi") {
                adapters.push("Wi-Fi".to_string());
            }

            println!("🌐 [Windows DNS] Resetting DNS on adapters {:?} to DHCP (Automatic)...", adapters);

            for adapter in &adapters {
                // 1. PowerShell Set-DnsClientServerAddress reset
                let ps_cmd = format!("Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses -ErrorAction SilentlyContinue", adapter);
                let _ = crate::engine::silent_command("powershell.exe")
                    .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &ps_cmd])
                    .status();

                // 2. netsh IPv4 DHCP reset
                let _ = crate::engine::silent_command("netsh.exe")
                    .args(["interface", "ipv4", "set", "dns", adapter, "source=dhcp"])
                    .status();

                // 3. netsh IPv6 DHCP reset
                let _ = crate::engine::silent_command("netsh.exe")
                    .args(["interface", "ipv6", "set", "dns", adapter, "source=dhcp"])
                    .status();
            }

            // 4. Flush DNS Resolver Cache
            let _ = crate::engine::silent_command("ipconfig.exe")
                .args(["/flushdns"])
                .status();
            let _ = crate::engine::silent_command("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Clear-DnsClientCache -ErrorAction SilentlyContinue"])
                .status();

            println!("✨ [Windows DNS] DNS reset to DHCP and cache flushed successfully.");
        }
        Ok(())
    }

    /// Restore all system network settings on current platform (Proxy + DNS).
    pub fn restore_all_system_settings(&mut self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            self.disable_macos_proxy()?;
        }
        #[cfg(target_os = "windows")]
        {
            Self::reset_windows_dns()?;
        }
        self.proxy_is_active = false;
        Ok(())
    }
}

impl Drop for SystemProxyManager {
    fn drop(&mut self) {
        let _ = self.restore_all_system_settings();
    }
}
