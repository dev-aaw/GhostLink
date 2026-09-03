#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::{anyhow, Result};
use ghostlink_engine::engine::ipc::{
    DaemonStatusInfo, IpcEnvelope, IpcRequest, IpcResponse, WINDOWS_IPC_ADDR,
};
#[cfg(unix)]
use ghostlink_engine::engine::ipc::{DEFAULT_SOCKET_PATH, FALLBACK_SOCKET_PATH};
use ghostlink_engine::{EngineConfig, EngineState, ProbeRunner, Strategy, UnblockEngine};
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};

#[cfg(windows)]
use tokio::net::{TcpListener, TcpStream};

struct DaemonState {
    engine: UnblockEngine,
    active_strategy: Option<Strategy>,
    start_time: Instant,
}

#[tokio::main]
async fn main() -> Result<()> {
    ghostlink_engine::init_logger("daemon");
    println!("👻 GhostLink Privileged Helper Daemon starting...");

    #[cfg(unix)]
    let is_root = unsafe { libc::geteuid() == 0 };
    #[cfg(windows)]
    let is_root = is_windows_admin();

    println!("   • Privileges: {}", if is_root { "Admin/Root (Privileged)" } else { "Standard (Non-Privileged)" });
    println!("   • PID: {}", std::process::id());

    // 1. Initialize Engine State
    let config = EngineConfig::default();
    let engine = UnblockEngine::new(config);
    let state = Arc::new(Mutex::new(DaemonState {
        engine,
        active_strategy: None,
        start_time: Instant::now(),
    }));

    #[cfg(unix)]
    {
        // 1. Determine socket path and prepare directory
        let socket_path = if is_root {
            PathBuf::from(DEFAULT_SOCKET_PATH)
        } else {
            PathBuf::from(FALLBACK_SOCKET_PATH)
        };

        // Remove stale socket if exists
        if socket_path.exists() {
            let _ = fs::remove_file(&socket_path);
        }

        // 2. Bind Unix domain socket
        let listener = match UnixListener::bind(&socket_path) {
            Ok(l) => l,
            Err(e) => {
                if is_root && socket_path != PathBuf::from(FALLBACK_SOCKET_PATH) {
                    eprintln!("⚠️ Failed to bind to {:?}: {}. Falling back to {:?}", socket_path, e, FALLBACK_SOCKET_PATH);
                    let fallback = PathBuf::from(FALLBACK_SOCKET_PATH);
                    if fallback.exists() {
                        let _ = fs::remove_file(&fallback);
                    }
                    UnixListener::bind(&fallback)?
                } else {
                    return Err(anyhow!("Failed to bind to socket {:?}: {}", socket_path, e));
                }
            }
        };

        let actual_socket_path = socket_path.clone();

        // 3. Security Hardening on Unix:
        // Set socket permissions to 0600 (strictly owner-only).
        let (console_uid, console_gid) = get_console_user().unwrap_or((501, 20));

        if is_root {
            use std::ffi::CString;
            if let Ok(c_path) = CString::new(actual_socket_path.to_string_lossy().as_bytes()) {
                unsafe {
                    libc::chown(c_path.as_ptr(), console_uid, console_gid);
                }
            }
        }

        if let Ok(metadata) = fs::metadata(&actual_socket_path) {
            let mut perms = metadata.permissions();
            perms.set_mode(0o600);
            let _ = fs::set_permissions(&actual_socket_path, perms);
        }

        println!("📡 Listening on IPC socket: {:?} (permissions: 0600, owner UID: {})", actual_socket_path, console_uid);

        // 4. Setup signal listeners for graceful shutdown
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;

        let state_for_signals = Arc::clone(&state);
        let socket_for_signals = actual_socket_path.clone();

        tokio::spawn(async move {
            tokio::select! {
                _ = sigterm.recv() => {
                    println!("\n🛑 Received SIGTERM, stopping engine and cleaning up...");
                }
                _ = sigint.recv() => {
                    println!("\n🛑 Received SIGINT (Ctrl+C), stopping engine and cleaning up...");
                }
            }

            let mut st = state_for_signals.lock().await;
            let _ = st.engine.stop().await;
            if socket_for_signals.exists() {
                let _ = fs::remove_file(&socket_for_signals);
            }
            println!("✨ Daemon shutdown complete. Exiting.");
            std::process::exit(0);
        });

        // 5. Main accept loop (Unix)
        println!("✅ GhostLink Daemon is ready to process requests.");
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let state_clone = Arc::clone(&state);
                    tokio::spawn(async move {
                        if let Err(e) = handle_unix_connection(stream, state_clone).await {
                            eprintln!("⚠️ Error handling client connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("⚠️ Socket accept error: {}", e);
                }
            }
        }
    }

    #[cfg(windows)]
    {
        // 1. Register Windows Console Control Handler for graceful shutdown/logoff/close
        unsafe {
            use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
            unsafe extern "system" fn ctrl_handler(ctrl_type: u32) -> windows_sys::Win32::Foundation::BOOL {
                let _ = ctrl_type;
                // Kill winws process
                let _ = ghostlink_engine::silent_command("taskkill.exe")
                    .args(["/F", "/IM", "winws.exe"])
                    .status();
                // Reset DNS to DHCP on all adapters
                let _ = ghostlink_engine::silent_command("powershell.exe")
                    .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                        "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias -ResetServerAddresses -ErrorAction SilentlyContinue }"])
                    .status();
                // Flush DNS cache
                let _ = ghostlink_engine::silent_command("ipconfig.exe")
                    .args(["/flushdns"])
                    .status();
                1
            }
            SetConsoleCtrlHandler(Some(ctrl_handler), 1);
        }

        let listener = TcpListener::bind(WINDOWS_IPC_ADDR).await
            .map_err(|e| anyhow!("Failed to bind GhostLink Windows service to {}: {}", WINDOWS_IPC_ADDR, e))?;

        println!("📡 Listening on Local IPC (Loopback): {}", WINDOWS_IPC_ADDR);

        let state_for_signals = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            println!("\n🛑 Received Ctrl+C, stopping GhostLink Windows Engine and cleaning up...");
            let mut st = state_for_signals.lock().await;
            let _ = st.engine.stop().await;
            std::process::exit(0);
        });

        println!("📡 Listening on Windows TCP IPC: {} (127.0.0.1:49281)", WINDOWS_IPC_ADDR);

        // 1.5 Ensure Clean Hosts Mappings for Discord & WikiLeaks against ISP DNS Poisoning
        ensure_clean_hosts();

        // 2. Production 24/7 Engine AutoStart on Boot
        let state_for_autostart = Arc::clone(&state);
        let default_strategy = state.lock().await.engine.list_strategies().into_iter().find(|s| s.id == "win-general");
        tokio::spawn(async move {
            let saved_strat_id = ghostlink_engine::StrategyConfigManager::load_selected_strategy();
            let strat_opt = {
                let st = state_for_autostart.lock().await;
                let list = st.engine.list_strategies();
                list.into_iter().find(|s| s.id == saved_strat_id)
            }.or(default_strategy);

            if let Some(strat) = strat_opt {
                println!("🚀 [AutoStart] Automatically starting engine on boot with strategy [{}]...", strat.name);
                let mut st = state_for_autostart.lock().await;
                if let Err(e) = st.engine.start(&strat).await {
                    eprintln!("⚠️ [AutoStart] Failed to auto-start engine on boot: {}", e);
                } else {
                    st.active_strategy = Some(strat.clone());
                    let _ = ghostlink_engine::StrategyConfigManager::save_selected_strategy(&strat.id);
                    println!("✨ [AutoStart] Engine is ACTIVE on boot with strategy [{}] (winws desync).", strat.name);
                }
            }
        });

        // 3. Resilience Watchdog & Network Transition Monitor (Wi-Fi <-> Ethernet / Sleep-Wake)
        let state_for_watchdog = Arc::clone(&state);
        tokio::spawn(async move {
            let mut last_adapters = ghostlink_engine::SystemProxyManager::detect_active_windows_adapters();
            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(3000)).await;

                // Watchdog Check
                let (needs_revival, strat_to_revive) = {
                    let mut st = state_for_watchdog.lock().await;
                    if st.engine.is_running() && !st.engine.check_health() {
                        (true, st.active_strategy.clone())
                    } else {
                        (false, None)
                    }
                };

                if needs_revival {
                    if let Some(strat) = strat_to_revive {
                        ghostlink_engine::log_warn!("Detected winws crash/stop! Reviving engine immediately with [{}]...", strat.name);
                        let mut st = state_for_watchdog.lock().await;
                        let _ = st.engine.start(&strat).await;
                        ghostlink_engine::log_info!("winws revived successfully with strategy [{}].", strat.name);
                    }
                }

                // Network Transition Check
                let current_adapters = ghostlink_engine::SystemProxyManager::detect_active_windows_adapters();
                if !last_adapters.is_empty() && last_adapters != current_adapters {
                    ghostlink_engine::log_info!("Network interface change detected: {:?} -> {:?}. Reapplying clean DNS...", last_adapters, current_adapters);
                    let _ = ghostlink_engine::silent_command("ipconfig.exe").args(["/flushdns"]).status();
                    // Reapply clean DNS to new active adapters
                    let _ = ghostlink_engine::silent_command("powershell.exe")
                        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                            "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias -ServerAddresses @('1.1.1.1','1.0.0.1') -ErrorAction SilentlyContinue }"])
                        .status();
                }
                last_adapters = current_adapters;
            }
        });

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let state_clone = Arc::clone(&state);
                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_connection(stream, state_clone).await {
                            eprintln!("⚠️ Error handling client connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("⚠️ TCP accept error: {}", e);
                }
            }
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}

#[cfg(unix)]
async fn handle_unix_connection(stream: UnixStream, state: Arc<Mutex<DaemonState>>) -> Result<()> {
    let (console_uid, _) = get_console_user().unwrap_or((501, 20));
    let my_uid = unsafe { libc::geteuid() };
    if let Ok((peer_uid, _)) = get_peer_credentials(&stream) {
        // Security verification: Only allow root, daemon runner, or console user
        if peer_uid != 0 && peer_uid != my_uid && peer_uid != console_uid {
            eprintln!("🛑 SECURITY REJECTION: Unauthorized IPC connection from UID {}. Refusing.", peer_uid);
            return Err(anyhow!("Unauthorized caller UID {}", peer_uid));
        }
    }

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        let request: IpcRequest = match serde_json::from_str(trimmed) {
            Ok(req) => req,
            Err(e) => {
                let err_resp = IpcResponse::Error {
                    error: format!("Invalid JSON request: {}", e),
                };
                let mut out = serde_json::to_string(&err_resp)?;
                out.push('\n');
                writer.write_all(out.as_bytes()).await?;
                writer.flush().await?;
                line.clear();
                continue;
            }
        };

        let response = process_ipc_request(request, &state).await;
        let mut out = serde_json::to_string(&response)?;
        out.push('\n');
        writer.write_all(out.as_bytes()).await?;
        writer.flush().await?;

        line.clear();
    }

    Ok(())
}

#[cfg(windows)]
async fn handle_tcp_connection(stream: TcpStream, state: Arc<Mutex<DaemonState>>) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let expected_token = get_or_create_daemon_token();

    loop {
        line.clear();
        // Slowloris & OOM protection: take at most 65536 bytes per request line
        let bytes_read = {
            let mut limited_reader = (&mut reader).take(65536);
            limited_reader.read_line(&mut line).await?
        };

        if bytes_read == 0 {
            break;
        }

        if bytes_read >= 65536 && !line.ends_with('\n') {
            let err_resp = IpcResponse::Error {
                error: "Payload too large (exceeds 64KB limit without newline)".to_string(),
            };
            let mut out = serde_json::to_string(&err_resp)?;
            out.push('\n');
            let _ = writer.write_all(out.as_bytes()).await;
            let _ = writer.flush().await;
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let (req_token, request) = if let Ok(envelope) = serde_json::from_str::<IpcEnvelope>(trimmed) {
            (envelope.token, envelope.request)
        } else if let Ok(req) = serde_json::from_str::<IpcRequest>(trimmed) {
            (None, req)
        } else {
            let err_resp = IpcResponse::Error {
                error: "Invalid JSON request".to_string(),
            };
            let mut out = serde_json::to_string(&err_resp)?;
            out.push('\n');
            writer.write_all(out.as_bytes()).await?;
            writer.flush().await?;
            continue;
        };

        // Authentication verification
        if !matches!(request, IpcRequest::Ping) {
            if req_token.as_deref() != Some(&expected_token) {
                eprintln!("🚨 [IPC SECURITY] Rejected unauthenticated request from loopback client!");
                let err_resp = IpcResponse::Error {
                    error: "Unauthorized: Invalid or missing IPC authentication token".to_string(),
                };
                let mut out = serde_json::to_string(&err_resp)?;
                out.push('\n');
                writer.write_all(out.as_bytes()).await?;
                writer.flush().await?;
                continue;
            }
        }

        let response = process_ipc_request(request, &state).await;
        let mut out = serde_json::to_string(&response)?;
        out.push('\n');
        writer.write_all(out.as_bytes()).await?;
        writer.flush().await?;
    }

    Ok(())
}

async fn process_ipc_request(request: IpcRequest, state: &Arc<Mutex<DaemonState>>) -> IpcResponse {
    match request {
        IpcRequest::Ping => {
            #[cfg(unix)]
            let is_root = unsafe { libc::geteuid() == 0 };
            #[cfg(windows)]
            let is_root = is_windows_admin();

            IpcResponse::Pong {
                version: env!("CARGO_PKG_VERSION").to_string(),
                is_root,
                pid: std::process::id(),
            }
        }

        IpcRequest::GetStatus => {
            let st = state.lock().await;
            let is_running = st.engine.is_running();
            let active_strat = st.active_strategy.as_ref();
            let uptime = st.start_time.elapsed().as_secs();

            #[cfg(unix)]
            let is_root = unsafe { libc::geteuid() == 0 };
            #[cfg(windows)]
            let is_root = is_windows_admin();

            let (socks_port, strat_id, strat_name) = if let EngineState::Running { strategy_name, port } = st.engine.state() {
                (Some(*port), active_strat.map(|s| s.id.clone()), Some(strategy_name.clone()))
            } else {
                (None, None, None)
            };

            IpcResponse::Status(DaemonStatusInfo {
                is_running,
                active_strategy_id: strat_id,
                active_strategy_name: strat_name,
                socks_port,
                engine_pid: st.engine.active_pid(),
                daemon_pid: std::process::id(),
                is_root,
                uptime_secs: uptime,
            })
        }

        IpcRequest::Start { strategy_id, .. } => {
            let mut st = state.lock().await;
            let strats = st.engine.list_strategies();
            let target_strat = strats.into_iter().find(|s| s.id == strategy_id);

            match target_strat {
                Some(strat) => {
                    let _ = ghostlink_engine::StrategyConfigManager::save_selected_strategy(&strat.id);
                    match st.engine.start(&strat).await {
                        Ok(()) => {
                            st.active_strategy = Some(strat.clone());
                            ghostlink_engine::log_info!("GhostLink engine started with strategy: [{}]", strat.name);
                            IpcResponse::Ok {
                                message: format!("Engine started successfully with strategy [{}]", strat.name),
                            }
                        }
                        Err(e) => {
                            ghostlink_engine::log_error!("Failed to start engine: {}", e);
                            IpcResponse::Error {
                                error: format!("Failed to start engine: {}", e),
                            }
                        }
                    }
                }
                None => IpcResponse::Error {
                    error: format!("Strategy with ID '{}' not found", strategy_id),
                },
            }
        }

        IpcRequest::Stop => {
            let mut st = state.lock().await;
            match st.engine.stop().await {
                Ok(()) => {
                    st.active_strategy = None;
                    ghostlink_engine::log_info!("GhostLink engine stopped and system settings restored.");
                    IpcResponse::Ok {
                        message: "Engine stopped and system settings restored".to_string(),
                    }
                }
                Err(e) => IpcResponse::Error {
                    error: format!("Error stopping engine: {}", e),
                },
            }
        }

        IpcRequest::ProbeDirect => {
            let runner = ProbeRunner::new();
            let summary = runner.run_suite("direct", None).await;
            IpcResponse::ProbeResult(summary)
        }

        IpcRequest::TestStrategy { strategy_id } => {
            let mut st = state.lock().await;
            let strats = st.engine.list_strategies();
            let target_strat = strats.into_iter().find(|s| s.id == strategy_id);

            match target_strat {
                Some(strat) => match st.engine.test_strategy(&strat).await {
                    Ok(summary) => IpcResponse::ProbeResult(summary),
                    Err(e) => IpcResponse::Error {
                        error: format!("Strategy test failed: {}", e),
                    },
                },
                None => IpcResponse::Error {
                    error: format!("Strategy with ID '{}' not found", strategy_id),
                },
            }
        }

        IpcRequest::AutoTune => {
            let mut st = state.lock().await;
            match st.engine.auto_tune(|curr, total, strat, maybe_sum| {
                if let Some(sum) = maybe_sum {
                    println!("   • [{}/{}] {} -> {}", curr, total, strat.name, if sum.success { "PASS" } else { "FAIL" });
                } else {
                    println!("   • [{}/{}] Testing {}...", curr, total, strat.name);
                }
            }).await {
                Ok(Some(strat)) => {
                    IpcResponse::AutoTuneResult {
                        best_strategy: Some(strat),
                        latency_ms: None,
                    }
                }
                Ok(None) => {
                    IpcResponse::AutoTuneResult {
                        best_strategy: None,
                        latency_ms: None,
                    }
                }
                Err(e) => IpcResponse::Error {
                    error: format!("AutoTune failed: {}", e),
                },
            }
        }

        IpcRequest::ConfigureDns { servers } => {
            #[cfg(target_os = "macos")]
            {
                if let Some(service) = ghostlink_engine::engine::system_proxy::SystemProxyManager::detect_primary_macos_service() {
                    let mut args = vec!["-setdnsservers", &service];
                    let s_refs: Vec<&str> = servers.iter().map(|s| s.as_str()).collect();
                    args.extend(s_refs);

                    println!("🌐 [Daemon Root] Configuring DNS on [{}] to {:?}", service, servers);
                    let status = std::process::Command::new("networksetup").args(&args).status();
                    match status {
                        Ok(s) if s.success() => IpcResponse::Ok {
                            message: format!("DNS servers configured on {}", service),
                        },
                        Ok(s) => IpcResponse::Error {
                            error: format!("networksetup exited with code {:?}", s.code()),
                        },
                        Err(e) => IpcResponse::Error {
                            error: format!("Failed to execute networksetup: {}", e),
                        },
                    }
                } else {
                    IpcResponse::Error {
                        error: "Could not detect active macOS network service".to_string(),
                    }
                }
            }
            #[cfg(target_os = "windows")]
            {
                match ghostlink_engine::engine::system_proxy::SystemProxyManager::configure_windows_dns(&servers) {
                    Ok(()) => IpcResponse::Ok {
                        message: format!("Windows DNS servers configured to {:?}", servers),
                    },
                    Err(e) => IpcResponse::Error {
                        error: format!("Failed to configure Windows DNS: {}", e),
                    },
                }
            }
            #[cfg(not(any(target_os = "macos", target_os = "windows")))]
            {
                let _ = servers;
                IpcResponse::Ok { message: "DNS configuration is automatic on this platform".to_string() }
            }
        }

        IpcRequest::ResetDns => {
            #[cfg(target_os = "macos")]
            {
                if let Some(service) = ghostlink_engine::engine::system_proxy::SystemProxyManager::detect_primary_macos_service() {
                    println!("🌐 [Daemon Root] Resetting DNS on [{}] to DHCP default...", service);
                    let status = std::process::Command::new("networksetup")
                        .args(["-setdnsservers", &service, "Empty"])
                        .status();
                    match status {
                        Ok(s) if s.success() => IpcResponse::Ok {
                            message: format!("DNS reset to default DHCP on {}", service),
                        },
                        Ok(s) => IpcResponse::Error {
                            error: format!("networksetup exited with code {:?}", s.code()),
                        },
                        Err(e) => IpcResponse::Error {
                            error: format!("Failed to execute networksetup: {}", e),
                        },
                    }
                } else {
                    IpcResponse::Error {
                        error: "Could not detect active macOS network service".to_string(),
                    }
                }
            }
            #[cfg(target_os = "windows")]
            {
                match ghostlink_engine::engine::system_proxy::SystemProxyManager::reset_windows_dns() {
                    Ok(()) => IpcResponse::Ok {
                        message: "Windows DNS reset to DHCP default and cache flushed".to_string(),
                    },
                    Err(e) => IpcResponse::Error {
                        error: format!("Failed to reset Windows DNS: {}", e),
                    },
                }
            }
            #[cfg(not(any(target_os = "macos", target_os = "windows")))]
            {
                IpcResponse::Ok { message: "DNS reset completed".to_string() }
            }
        }

        IpcRequest::WireGuardList => {
            let list = ghostlink_engine::WireGuardManager::list_tunnels();
            IpcResponse::WireGuardList(list)
        }

        IpcRequest::WireGuardStatus { tunnel } => {
            let state = ghostlink_engine::WireGuardManager::status(&tunnel);
            IpcResponse::WireGuardStatus { tunnel, state }
        }

        IpcRequest::WireGuardConnect { tunnel } => {
            match ghostlink_engine::WireGuardManager::connect_exclusive(&tunnel) {
                Ok(()) => IpcResponse::Ok {
                    message: format!("WireGuard tunnel '{}' connected exclusively", tunnel),
                },
                Err(e) => IpcResponse::Error {
                    error: format!("Failed to connect WireGuard tunnel '{}': {}", tunnel, e),
                },
            }
        }

        IpcRequest::WireGuardDisconnect { tunnel } => {
            match ghostlink_engine::WireGuardManager::disconnect(&tunnel) {
                Ok(()) => IpcResponse::Ok {
                    message: format!("WireGuard tunnel '{}' disconnected", tunnel),
                },
                Err(e) => IpcResponse::Error {
                    error: format!("Failed to disconnect WireGuard tunnel '{}': {}", tunnel, e),
                },
            }
        }

        IpcRequest::WireGuardToggle { tunnel } => {
            match ghostlink_engine::WireGuardManager::toggle_exclusive(&tunnel) {
                Ok(state) => IpcResponse::WireGuardStatus { tunnel, state },
                Err(e) => IpcResponse::Error {
                    error: format!("Failed to toggle WireGuard tunnel '{}': {}", tunnel, e),
                },
            }
        }

        IpcRequest::AddRoute { ip, router, iface } => {
            if ip.parse::<std::net::Ipv4Addr>().is_err() {
                return IpcResponse::Error { error: format!("Invalid destination IP: {}", ip) };
            }
            if router.parse::<std::net::Ipv4Addr>().is_err() {
                return IpcResponse::Error { error: format!("Invalid router IP: {}", router) };
            }
            if iface.is_empty() || iface.len() > 16 || !iface.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
                return IpcResponse::Error { error: format!("Invalid interface name: {}", iface) };
            }

            println!("🌐 [Daemon Root] Adding host route {} -> {} (interface {})", ip, router, iface);
            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("/sbin/route")
                    .args(["-n", "add", "-host", &ip, &router])
                    .status();
                let _ = std::process::Command::new("/sbin/route")
                    .args(["-n", "add", "-host", &ip, "-interface", &iface])
                    .status();
            }
            #[cfg(target_os = "windows")]
            {
                let _ = ghostlink_engine::silent_command("route.exe")
                    .args(["add", &ip, "mask", "255.255.255.255", &router])
                    .status();
            }

            IpcResponse::Ok {
                message: format!("Route to {} added via {}", ip, router),
            }
        }

        IpcRequest::DeleteRoute { ip, router, iface } => {
            if ip.parse::<std::net::Ipv4Addr>().is_err() {
                return IpcResponse::Error { error: format!("Invalid destination IP: {}", ip) };
            }
            if router.parse::<std::net::Ipv4Addr>().is_err() {
                return IpcResponse::Error { error: format!("Invalid router IP: {}", router) };
            }
            if iface.is_empty() || iface.len() > 16 || !iface.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
                return IpcResponse::Error { error: format!("Invalid interface name: {}", iface) };
            }

            println!("🌐 [Daemon Root] Deleting host route {} -> {} (interface {})", ip, router, iface);
            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("/sbin/route")
                    .args(["-n", "delete", "-host", &ip, &router])
                    .status();
                let _ = std::process::Command::new("/sbin/route")
                    .args(["-n", "delete", "-host", &ip, "-interface", &iface])
                    .status();
            }
            #[cfg(target_os = "windows")]
            {
                let _ = ghostlink_engine::silent_command("route.exe")
                    .args(["delete", &ip])
                    .status();
            }

            IpcResponse::Ok {
                message: format!("Route to {} removed", ip),
            }
        }

        IpcRequest::GetRecentLogs { max_lines } => {
            let count = max_lines.unwrap_or(50);
            let logs = ghostlink_engine::logging::get_recent_log_entries(count);
            IpcResponse::RecentLogs(logs)
        }

        IpcRequest::ShutdownDaemon => {
            let mut st = state.lock().await;
            let _ = st.engine.stop().await;
            tokio::spawn(async {
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                std::process::exit(0);
            });
            IpcResponse::Ok {
                message: "Daemon shutting down...".to_string(),
            }
        }
    }
}

#[cfg(unix)]
fn get_console_user() -> Option<(u32, u32)> {
    if let Ok(m) = fs::metadata("/dev/console") {
        use std::os::unix::fs::MetadataExt;
        return Some((m.uid(), m.gid()));
    }
    None
}

#[cfg(unix)]
fn get_peer_credentials(stream: &UnixStream) -> Result<(u32, u32)> {
    use std::os::unix::io::AsRawFd;
    let raw_fd = stream.as_raw_fd();
    let mut euid: libc::uid_t = 0;
    let mut egid: libc::gid_t = 0;
    let res = unsafe { libc::getpeereid(raw_fd, &mut euid, &mut egid) };
    if res != 0 {
        return Err(anyhow!("Failed to get peer credentials: {}", std::io::Error::last_os_error()));
    }
    Ok((euid as u32, egid as u32))
}

#[cfg(windows)]
fn is_windows_admin() -> bool {
    let output = ghostlink_engine::silent_command("net.exe")
        .args(["session"])
        .output();
    if let Ok(out) = output {
        return out.status.success();
    }
    false
}

#[cfg(windows)]
fn get_or_create_daemon_token() -> String {
    use rand::RngCore;
    let token_path = ghostlink_engine::engine::ipc::get_token_path();
    if let Ok(existing) = std::fs::read_to_string(&token_path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }

    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = hex::encode(bytes);

    if let Some(parent) = token_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&token_path, &token);

    let _ = ghostlink_engine::silent_command("icacls.exe")
        .args([
            token_path.to_str().unwrap_or(""),
            "/inheritance:r",
            "/grant:r", "SYSTEM:(F)",
            "/grant:r", "Administrators:(F)",
            "/grant:r", "Users:(R)",
        ])
        .status();

    token
}

#[cfg(windows)]
fn ensure_clean_hosts() {
    let hosts_path = r"C:\Windows\System32\drivers\etc\hosts";
    let entries = [
        "162.159.138.232 discord.com",
        "162.159.138.232 discord.gg",
        "162.159.138.232 discordapp.com",
        "162.159.138.232 discordapp.net",
        "162.159.138.232 updates.discord.com",
        "162.159.138.232 dl2.discordapp.net",
        "162.159.138.232 stable.dl2.discordapp.net",
        "162.159.138.232 discord.media",
        "162.159.138.232 discordcdn.com",
        "162.159.138.232 gateway.discord.gg",
        "162.159.138.232 cdn.discordapp.com",
        "162.159.138.232 media.discordapp.net",
        "162.159.138.232 status.discord.com",
        "162.159.138.232 latency.discord.media",
        "162.159.138.232 router.discordapp.net",
        "162.159.138.232 fingerprint.discord.com",
        "162.159.138.232 remote-auth-gateway.discord.gg",
        "51.159.197.136 wikileaks.org",
        "51.159.197.136 www.wikileaks.org",
    ];

    if let Ok(content) = std::fs::read_to_string(hosts_path) {
        let mut new_content = content.clone();
        let mut modified = false;
        let existing_lines: Vec<&str> = content.lines().collect();

        for entry in &entries {
            let domain = entry.split_whitespace().nth(1).unwrap_or("");
            if domain.is_empty() {
                continue;
            }

            // Word-boundary check: exact domain match on active non-comment lines
            let already_present = existing_lines.iter().any(|line| {
                let trimmed = line.trim();
                if trimmed.starts_with('#') {
                    return false;
                }
                trimmed.split_whitespace().skip(1).any(|host| host.eq_ignore_ascii_case(domain))
            });

            if !already_present {
                if !new_content.ends_with('\n') && !new_content.is_empty() {
                    new_content.push('\n');
                }
                new_content.push_str(&format!("{}\n", entry));
                modified = true;
            }
        }
        if modified {
            let _ = std::fs::write(hosts_path, new_content);
            let _ = ghostlink_engine::silent_command("ipconfig.exe").arg("/flushdns").output();
            println!("🛡️ [DNS] Clean hosts mappings synchronized for Discord & WikiLeaks.");
        }
    }
}

