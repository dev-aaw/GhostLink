use anyhow::Result;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use anyhow::Context;
#[cfg(target_os = "macos")]
use std::process::Command;

/// Fixed system path that records the exact `networksetup` service name the SOCKS
/// proxy was last enabled on. The primary network service can change while
/// GhostLink runs (Wi-Fi <-> Ethernet) and the teardown may run from a
/// *different* process (`ghostlink_cli stop`, the watchdog, the daemon after a
/// restart); re-detecting the primary service at disable time then turns the
/// proxy off on the wrong service and silently leaves it enabled on the
/// original one — no internet, no error.
///
/// This must NOT be derived from `$HOME`: the production helper runs as a
/// launchd LaunchDaemon, which gets no `HOME`, and even where `HOME` is set the
/// root daemon (`enable`) and the console-user CLI (`stop`) would resolve to
/// different files. `/Library/Application Support/GhostLink` is created by
/// `service install` as root:wheel; the daemon (root) writes the record 0644 so
/// any process can read it. In standalone (non-root, no daemon) mode the write
/// is a harmless no-op and `SystemProxyManager::active_service` in memory covers
/// the single-process enable/disable pair.
#[cfg(target_os = "macos")]
const ACTIVE_SERVICE_FILE: &str = "/Library/Application Support/GhostLink/active_service";

/// Security: `/Library/Application Support` is `root:admin`, group-writable, so
/// any local user in the admin group (the common case for a Mac's primary
/// account) can delete the `GhostLink` subdir `service install` created and
/// replace it with a symlink to an arbitrary directory. Without the checks
/// below, the root daemon would `create_dir_all()` straight through that
/// symlink and write `active_service` wherever the attacker pointed — a local
/// root file-write primitive. Same defense pattern as `ipc.rs`'s
/// `is_trusted_socket()` and `process.rs`'s log-file open: verify with
/// `symlink_metadata` (never follows the final component) before touching
/// anything, and close the remaining TOCTOU on the leaf file with `O_NOFOLLOW`
/// at open time.
#[cfg(target_os = "macos")]
pub fn record_active_service(service: &str) {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let path = std::path::Path::new(ACTIVE_SERVICE_FILE);
    let parent = match path.parent() {
        Some(p) => p,
        None => return,
    };

    let parent_is_plain_dir = |p: &std::path::Path| {
        matches!(std::fs::symlink_metadata(p), Ok(meta) if meta.file_type().is_dir() && !meta.file_type().is_symlink())
    };

    if !parent_is_plain_dir(parent) {
        // Parent missing entirely (first run before `service install`) is fine
        // to create; anything else that already exists there and isn't a plain
        // directory (in particular, a symlink) is refused outright.
        if std::fs::symlink_metadata(parent).is_ok() {
            eprintln!("⚠️ SECURITY: Refusing to write {ACTIVE_SERVICE_FILE}: parent is not a plain directory");
            return;
        }
        if std::fs::create_dir_all(parent).is_err() || !parent_is_plain_dir(parent) {
            eprintln!("⚠️ SECURITY: Refusing to write {ACTIVE_SERVICE_FILE}: could not create a plain parent directory");
            return;
        }
    }

    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            eprintln!("⚠️ SECURITY: Refusing to write {ACTIVE_SERVICE_FILE}: target is a symlink");
            return;
        }
    }

    // O_NOFOLLOW closes the window between the check above and this open: if a
    // symlink appears at `path` in between, the open fails (ELOOP) instead of
    // writing through it.
    match std::fs::OpenOptions::new().write(true).create(true).truncate(true).custom_flags(libc::O_NOFOLLOW).open(path) {
        Ok(mut f) => {
            use std::io::Write;
            if f.write_all(service.as_bytes()).is_ok() {
                let _ = f.set_permissions(std::fs::Permissions::from_mode(0o644));
            }
        }
        Err(e) => {
            eprintln!("⚠️ SECURITY: Refusing to write {ACTIVE_SERVICE_FILE}: {e}");
        }
    }
}

#[cfg(target_os = "macos")]
pub fn recorded_active_service() -> Option<String> {
    let raw = std::fs::read_to_string(ACTIVE_SERVICE_FILE).ok()?;
    let name = raw.trim();
    if name.is_empty() { None } else { Some(name.to_string()) }
}

#[cfg(target_os = "macos")]
pub fn clear_recorded_service() {
    let _ = std::fs::remove_file(ACTIVE_SERVICE_FILE);
}

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

            // Pin the exact service so teardown targets it even if the primary
            // network service changes or a different process performs the stop.
            record_active_service(service);
            self.active_service = Some(service.to_string());
            self.proxy_is_active = true;
        }
        Ok(())
    }

    /// Disable SOCKS5 proxy and reset DNS on macOS.
    pub fn disable_macos_proxy(&mut self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            // Prefer the service the proxy was actually enabled on (recorded to
            // disk), then this instance's memory, then a fresh detection.
            let target = recorded_active_service()
                .or_else(|| self.active_service.clone())
                .or_else(Self::detect_primary_macos_service);

            if let Some(ref service) = target {
                println!("🌐 Disabling macOS SOCKS proxy and restoring network settings on [{}]...", service);

                let _ = Command::new("networksetup")
                    .args(["-setsocksfirewallproxystate", service, "off"])
                    .status();

                let _ = Command::new("networksetup")
                    .args(["-setdnsservers", service, "Empty"])
                    .status();
            }

            clear_recorded_service();
            self.active_service = None;
            self.proxy_is_active = false;
        }
        Ok(())
    }

    /// Detect active network adapters on Windows.
    ///
    /// Primary path is the IP Helper API (`GetAdaptersAddresses`) — zero process
    /// spawn. This is polled by the daemon's transition monitor, so the old
    /// "spawn powershell.exe every 30s" approach was pure background noise.
    /// PowerShell / netsh remain only as fallbacks if the API yields nothing.
    pub fn detect_active_windows_adapters() -> Vec<String> {
        #[cfg(target_os = "windows")]
        {
            let mut adapters = adapters_via_iphelper();

            // Fallback 1: PowerShell Get-NetAdapter (locale-independent)
            if adapters.is_empty() {
                let ps_output = crate::engine::silent_command("powershell.exe")
                    .args([
                        "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                        "-Command",
                        "Get-NetAdapter -Physical | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty InterfaceAlias"
                    ])
                    .output();

                if let Ok(out) = ps_output {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    for line in stdout.lines() {
                        let name = line.trim();
                        if !name.is_empty() && !name.starts_with("Loopback") && !name.starts_with("wg") {
                            adapters.push(name.to_string());
                        }
                    }
                }
            }

            // Fallback 2: netsh with multi-locale parsing
            if adapters.is_empty() {
                let output = crate::engine::silent_command("netsh.exe")
                    .args(["interface", "ipv4", "show", "interfaces"])
                    .output();

                if let Ok(out) = output {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    // Known locale keywords for "connected" status
                    let connected_keywords = ["connected", "Bağlandı", "Verbunden", "Connecté", "Conectado", "Подключен"];
                    for line in stdout.lines() {
                        let trimmed = line.trim();
                        for keyword in &connected_keywords {
                            if trimmed.contains(keyword) {
                                if let Some(name_start) = trimmed.rfind(keyword) {
                                    let name = trimmed[name_start + keyword.len()..].trim();
                                    if !name.is_empty() && !name.starts_with("Loopback") && !name.starts_with("wg") {
                                        adapters.push(name.to_string());
                                    }
                                }
                                break;
                            }
                        }
                    }
                }
            }

            // Last resort fallback
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

            // Validate DNS server addresses (must be valid IPs)
            for server in servers {
                if !server.chars().all(|c| c.is_ascii_digit() || c == '.' || c == ':') {
                    return Err(anyhow::anyhow!("Invalid DNS server address: {}", server));
                }
            }

            println!("🌐 [Windows DNS] Configuring clean DNS on active adapters {:?} to {:?}", adapters, servers);

            // Back up current DNS configuration before overwriting
            Self::backup_dns_config(&adapters);

            let s_joined = servers.iter().map(|s| format!("'{}'", s)).collect::<Vec<_>>().join(",");

            for adapter in &adapters {
                // Security: Sanitize adapter name to prevent PowerShell injection
                // Only allow alphanumeric, spaces, hyphens, underscores, dots, and parentheses
                let safe_adapter: String = adapter.chars()
                    .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_' || *c == '.' || *c == '(' || *c == ')')
                    .collect();
                if safe_adapter.is_empty() || safe_adapter.len() != adapter.len() {
                    eprintln!("⚠️ Skipping adapter with suspicious name: {:?}", adapter);
                    continue;
                }

                // 1. PowerShell Set-DnsClientServerAddress (InterfaceAlias and InterfaceIndex)
                let ps_cmd = format!(
                    "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses @({}) -ErrorAction SilentlyContinue",
                    safe_adapter, s_joined
                );
                let _ = crate::engine::silent_command("powershell.exe")
                    .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &ps_cmd])
                    .status();

                // 2. netsh IPv4 static primary & secondary DNS fallback (with validate=no for immediate application)
                let _ = crate::engine::silent_command("netsh.exe")
                    .args(["interface", "ipv4", "set", "dnsservers", &format!("name={}", safe_adapter), "source=static", &format!("address={}", servers[0]), "validate=no"])
                    .status();

                for (idx, server) in servers.iter().skip(1).enumerate() {
                    let _ = crate::engine::silent_command("netsh.exe")
                        .args(["interface", "ipv4", "add", "dnsservers", &format!("name={}", safe_adapter), &format!("address={}", server), &format!("index={}", idx + 2), "validate=no"])
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

    #[cfg(target_os = "windows")]
    fn get_dns_backup_path() -> std::path::PathBuf {
        let pdata = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
        std::path::PathBuf::from(pdata).join("GhostLink").join("dns_backup.json")
    }

    /// Backup the current DNS configuration on Windows adapters before overriding.
    #[cfg(target_os = "windows")]
    pub fn backup_dns_config(adapters: &[String]) {
        let backup_path = Self::get_dns_backup_path();
        if backup_path.exists() {
            // Do not overwrite existing backup; it holds user's true pre-GhostLink settings
            return;
        }

        #[derive(Serialize, Deserialize)]
        struct AdapterDnsInfo {
            adapter: String,
            servers: Vec<String>,
        }

        let mut entries = Vec::new();
        for adapter in adapters {
            let safe_adapter: String = adapter.chars()
                .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_' || *c == '.' || *c == '(' || *c == ')')
                .collect();
            if safe_adapter.is_empty() {
                continue;
            }

            let ps_cmd = format!(
                "(Get-DnsClientServerAddress -InterfaceAlias '{}' -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses -join ','",
                safe_adapter
            );
            if let Ok(out) = crate::engine::silent_command("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &ps_cmd])
                .output()
            {
                let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let servers: Vec<String> = if stdout.is_empty() {
                    Vec::new()
                } else {
                    stdout.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
                };
                entries.push(AdapterDnsInfo {
                    adapter: safe_adapter,
                    servers,
                });
            }
        }

        if !entries.is_empty() {
            if let Some(parent) = backup_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(json) = serde_json::to_string_pretty(&entries) {
                let _ = std::fs::write(&backup_path, json);
                println!("💾 [Windows DNS] Original DNS configuration backed up to {:?}", backup_path);
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn backup_dns_config(_adapters: &[String]) {}

    /// Reset DNS settings on all Windows adapters (restoring backup if present, otherwise DHCP) and flush DNS cache.
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

            let backup_path = Self::get_dns_backup_path();
            let mut restored_from_backup = false;

            #[derive(Serialize, Deserialize)]
            struct AdapterDnsInfo {
                adapter: String,
                servers: Vec<String>,
            }

            if backup_path.exists() {
                if let Ok(data) = std::fs::read_to_string(&backup_path) {
                    if let Ok(entries) = serde_json::from_str::<Vec<AdapterDnsInfo>>(&data) {
                        println!("🌐 [Windows DNS] Restoring original DNS configuration from backup...");
                        for entry in entries {
                            let safe_adapter: String = entry.adapter.chars()
                                .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_' || *c == '.' || *c == '(' || *c == ')')
                                .collect();
                            if safe_adapter.is_empty() {
                                continue;
                            }

                            if entry.servers.is_empty() {
                                // Original was DHCP
                                let ps_cmd = format!("Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses -ErrorAction SilentlyContinue", safe_adapter);
                                let _ = crate::engine::silent_command("powershell.exe")
                                    .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &ps_cmd])
                                    .status();
                                let _ = crate::engine::silent_command("netsh.exe")
                                    .args(["interface", "ipv4", "set", "dnsservers", &format!("name={}", safe_adapter), "source=dhcp"])
                                    .status();
                            } else {
                                // Restore original static servers
                                let s_joined = entry.servers.iter().map(|s| format!("'{}'", s)).collect::<Vec<_>>().join(",");
                                let ps_cmd = format!(
                                    "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses @({}) -ErrorAction SilentlyContinue",
                                    safe_adapter, s_joined
                                );
                                let _ = crate::engine::silent_command("powershell.exe")
                                    .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &ps_cmd])
                                    .status();

                                let _ = crate::engine::silent_command("netsh.exe")
                                    .args(["interface", "ipv4", "set", "dnsservers", &format!("name={}", safe_adapter), "source=static", &format!("address={}", entry.servers[0]), "validate=no"])
                                    .status();
                                for (idx, server) in entry.servers.iter().skip(1).enumerate() {
                                    let _ = crate::engine::silent_command("netsh.exe")
                                        .args(["interface", "ipv4", "add", "dnsservers", &format!("name={}", safe_adapter), &format!("address={}", server), &format!("index={}", idx + 2), "validate=no"])
                                        .status();
                                }
                            }
                        }
                        restored_from_backup = true;
                    }
                }
                let _ = std::fs::remove_file(&backup_path);
            }

            if !restored_from_backup {
                println!("🌐 [Windows DNS] Resetting DNS on adapters {:?} to DHCP (Automatic)...", adapters);

                for adapter in &adapters {
                    let safe_adapter: String = adapter.chars()
                        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_' || *c == '.' || *c == '(' || *c == ')')
                        .collect();
                    if safe_adapter.is_empty() {
                        continue;
                    }

                    // 1. PowerShell Set-DnsClientServerAddress reset
                    let ps_cmd = format!("Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses -ErrorAction SilentlyContinue", safe_adapter);
                    let _ = crate::engine::silent_command("powershell.exe")
                        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &ps_cmd])
                        .status();

                    // 2. netsh IPv4 DHCP reset
                    let _ = crate::engine::silent_command("netsh.exe")
                        .args(["interface", "ipv4", "set", "dnsservers", &format!("name={}", safe_adapter), "source=dhcp"])
                        .status();

                    // 3. netsh IPv6 DHCP reset
                    let _ = crate::engine::silent_command("netsh.exe")
                        .args(["interface", "ipv6", "set", "dnsservers", &format!("name={}", safe_adapter), "source=dhcp"])
                        .status();
                }
            }

            // Flush DNS Resolver Cache
            let _ = crate::engine::silent_command("ipconfig.exe")
                .args(["/flushdns"])
                .status();
            let _ = crate::engine::silent_command("powershell.exe")
                .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Clear-DnsClientCache -ErrorAction SilentlyContinue"])
                .status();

            println!("✨ [Windows DNS] DNS reset/restored and cache flushed successfully.");
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
        if self.proxy_is_active {
            let _ = self.restore_all_system_settings();
        }
    }
}

/// Enumerate "Up", non-loopback, non-tunnel adapters via the IP Helper API with no
/// child process. Returns friendly names (e.g. "Wi-Fi", "Ethernet").
#[cfg(target_os = "windows")]
fn adapters_via_iphelper() -> Vec<String> {
    use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };

    const AF_UNSPEC: u32 = 0;
    const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
    const IF_TYPE_TUNNEL: u32 = 131;
    const IF_OPER_STATUS_UP: i32 = 1;

    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 16 * 1024;
    // GetAdaptersAddresses writes IP_ADAPTER_ADDRESSES_LH structs (64-bit fields and
    // pointers) into this buffer, and MS docs require it to be pointer-aligned. A
    // `Vec<u8>` is only 1-byte aligned, so back the buffer with `u64` — that gives a
    // guaranteed 8-byte alignment, enough for every field in the struct chain.
    let mut buf: Vec<u64> = Vec::new();
    let u64s_for = |bytes: u32| ((bytes as usize) + 7) / 8;
    let mut adapters: Vec<String> = Vec::new();

    unsafe {
        for _ in 0..4 {
            buf.clear();
            buf.resize(u64s_for(size), 0);
            let ret = GetAdaptersAddresses(
                AF_UNSPEC,
                flags,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            );

            if ret == ERROR_BUFFER_OVERFLOW {
                continue; // `size` was updated with the required length; retry
            }
            if ret != ERROR_SUCCESS {
                break;
            }

            let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
            while !cur.is_null() {
                let a = &*cur;
                if a.IfType != IF_TYPE_SOFTWARE_LOOPBACK
                    && a.IfType != IF_TYPE_TUNNEL
                    && a.OperStatus == IF_OPER_STATUS_UP
                    && !a.FriendlyName.is_null()
                {
                    let mut len = 0usize;
                    while *a.FriendlyName.add(len) != 0 {
                        len += 1;
                    }
                    let name = String::from_utf16_lossy(std::slice::from_raw_parts(a.FriendlyName, len));
                    let low = name.to_lowercase();
                    if !name.is_empty()
                        && !low.starts_with("loopback")
                        && !low.starts_with("wg")
                        && !low.contains("wireguard")
                    {
                        adapters.push(name);
                    }
                }
                cur = a.Next;
            }
            break;
        }
    }

    adapters.sort();
    adapters.dedup();
    adapters
}
