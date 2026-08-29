use anyhow::{anyhow, Result};
use ghostlink_engine::engine::ipc::{
    DaemonStatusInfo, IpcRequest, IpcResponse, DEFAULT_SOCKET_PATH, FALLBACK_SOCKET_PATH,
};
use ghostlink_engine::{EngineConfig, EngineState, ProbeRunner, Strategy, UnblockEngine};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Mutex;

struct DaemonState {
    engine: UnblockEngine,
    active_strategy: Option<Strategy>,
    start_time: Instant,
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("👻 GhostLink Privileged Helper Daemon starting...");

    let is_root = unsafe { libc::geteuid() == 0 };
    println!("   • Privileges: {}", if is_root { "root (Privileged)" } else { "non-root (Standard)" });
    println!("   • PID: {}", std::process::id());

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

    // 3. Security Hardening:
    // Set socket permissions to 0600 (strictly owner-only).
    // If running as root, transfer ownership of the socket to the logged-in console user (UID/GID)
    // so only that user's processes (and root) can access the socket.
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

    // 4. Initialize engine state
    let config = EngineConfig::default();
    let engine = UnblockEngine::new(config);
    let state = Arc::new(Mutex::new(DaemonState {
        engine,
        active_strategy: None,
        start_time: Instant::now(),
    }));

    // 5. Setup signal listeners for graceful shutdown
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

    // 6. Main accept loop
    println!("✅ GhostLink Daemon is ready to process requests.");
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let state_clone = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, state_clone).await {
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

async fn handle_connection(stream: UnixStream, state: Arc<Mutex<DaemonState>>) -> Result<()> {
    #[cfg(unix)]
    {
        let (console_uid, _) = get_console_user().unwrap_or((501, 20));
        let my_uid = unsafe { libc::geteuid() };
        if let Ok((peer_uid, _)) = get_peer_credentials(&stream) {
            // Security verification: Only allow root, daemon runner, or console user
            if peer_uid != 0 && peer_uid != my_uid && peer_uid != console_uid {
                eprintln!("🛑 SECURITY REJECTION: Unauthorized IPC connection from UID {}. Refusing.", peer_uid);
                return Err(anyhow!("Unauthorized caller UID {}", peer_uid));
            }
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

async fn process_ipc_request(request: IpcRequest, state: &Arc<Mutex<DaemonState>>) -> IpcResponse {
    match request {
        IpcRequest::Ping => {
            let is_root = unsafe { libc::geteuid() == 0 };
            IpcResponse::Pong {
                version: env!("CARGO_PKG_VERSION").to_string(),
                is_root,
                pid: std::process::id(),
            }
        }

        IpcRequest::GetStatus => {
            let st = state.lock().await;
            let is_root = unsafe { libc::geteuid() == 0 };
            let is_running = matches!(st.engine.state(), EngineState::Running { .. });

            IpcResponse::Status(DaemonStatusInfo {
                is_running,
                active_strategy_id: st.active_strategy.as_ref().map(|s| s.id.clone()),
                active_strategy_name: st.active_strategy.as_ref().map(|s| s.name.clone()),
                socks_port: if is_running { Some(st.engine.config().socks_port) } else { None },
                engine_pid: None,
                daemon_pid: std::process::id(),
                is_root,
                uptime_secs: st.start_time.elapsed().as_secs(),
            })
        }

        IpcRequest::Start { strategy_id, socks_port: _, apply_system_proxy: _ } => {
            let mut st = state.lock().await;

            let strategies = st.engine.list_strategies();
            let target_strat = strategies.iter().find(|s| s.id.eq_ignore_ascii_case(&strategy_id) || s.name.to_lowercase().contains(&strategy_id.to_lowercase()));

            match target_strat {
                Some(strat) => {
                    let strat_clone = strat.clone();
                    match st.engine.start(&strat_clone).await {
                        Ok(()) => {
                            st.active_strategy = Some(strat_clone.clone());
                            IpcResponse::Ok {
                                message: format!("GhostLink Engine started successfully with strategy [{}] on SOCKS port {}", strat_clone.name, st.engine.config().socks_port),
                            }
                        }
                        Err(e) => IpcResponse::Error {
                            error: format!("Failed to start engine: {}", e),
                        },
                    }
                }
                None => IpcResponse::Error {
                    error: format!("Strategy '{}' not found", strategy_id),
                },
            }
        }

        IpcRequest::Stop => {
            let mut st = state.lock().await;
            match st.engine.stop().await {
                Ok(()) => {
                    st.active_strategy = None;
                    IpcResponse::Ok {
                        message: "GhostLink Engine stopped and system network settings restored.".to_string(),
                    }
                }
                Err(e) => IpcResponse::Error {
                    error: format!("Failed to stop engine: {}", e),
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
            let strategies = st.engine.list_strategies();
            let target_strat = strategies.iter().find(|s| s.id.eq_ignore_ascii_case(&strategy_id) || s.name.to_lowercase().contains(&strategy_id.to_lowercase()));

            match target_strat {
                Some(strat) => {
                    let strat_clone = strat.clone();
                    match st.engine.test_strategy(&strat_clone).await {
                        Ok(summary) => IpcResponse::ProbeResult(summary),
                        Err(e) => IpcResponse::Error {
                            error: format!("Strategy test failed: {}", e),
                        },
                    }
                }
                None => IpcResponse::Error {
                    error: format!("Strategy '{}' not found", strategy_id),
                },
            }
        }

        IpcRequest::AutoTune => {
            let mut st = state.lock().await;
            match st.engine.auto_tune(|_, _, _, _| {}).await {
                Ok(Some(best)) => IpcResponse::AutoTuneResult {
                    best_strategy: Some(best),
                    latency_ms: None,
                },
                Ok(None) => IpcResponse::AutoTuneResult {
                    best_strategy: None,
                    latency_ms: None,
                },
                Err(e) => IpcResponse::Error {
                    error: format!("AutoTune failed: {}", e),
                },
            }
        }

        IpcRequest::ConfigureDns { servers } => {
            #[cfg(target_os = "macos")]
            {
                // Security: Validate all DNS server IPs
                for s in &servers {
                    if s.parse::<std::net::IpAddr>().is_err() {
                        return IpcResponse::Error {
                            error: format!("Invalid DNS server IP address: {}", s),
                        };
                    }
                }

                let service = match ghostlink_engine::engine::system_proxy::SystemProxyManager::detect_primary_macos_service() {
                    Some(s) => s,
                    None => return IpcResponse::Error {
                        error: "No active network interface detected for DNS configuration".to_string(),
                    },
                };
                let mut cmd = std::process::Command::new("networksetup");
                cmd.arg("-setdnsservers").arg(&service);
                for s in &servers {
                    cmd.arg(s);
                }
                match cmd.status() {
                    Ok(st) if st.success() => IpcResponse::Ok {
                        message: format!("DNS servers updated to {:?} on [{}]", servers, service),
                    },
                    Ok(st) => IpcResponse::Error {
                        error: format!("networksetup returned exit code {:?}", st.code()),
                    },
                    Err(e) => IpcResponse::Error {
                        error: format!("Failed to run networksetup: {}", e),
                    },
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                IpcResponse::Error {
                    error: "DNS configuration not implemented for non-macOS".to_string(),
                }
            }
        }

        IpcRequest::ResetDns => {
            #[cfg(target_os = "macos")]
            {
                let service = match ghostlink_engine::engine::system_proxy::SystemProxyManager::detect_primary_macos_service() {
                    Some(s) => s,
                    None => return IpcResponse::Error {
                        error: "No active network interface detected for DNS reset".to_string(),
                    },
                };
                let mut cmd = std::process::Command::new("networksetup");
                cmd.args(["-setdnsservers", &service, "Empty"]);
                match cmd.status() {
                    Ok(st) if st.success() => IpcResponse::Ok {
                        message: format!("DNS reset to DHCP default on [{}]", service),
                    },
                    Ok(st) => IpcResponse::Error {
                        error: format!("networksetup returned exit code {:?}", st.code()),
                    },
                    Err(e) => IpcResponse::Error {
                        error: format!("Failed to run networksetup: {}", e),
                    },
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                IpcResponse::Error {
                    error: "DNS reset not implemented for non-macOS".to_string(),
                }
            }
        }

        IpcRequest::WireGuardList => {
            let tunnels = ghostlink_engine::engine::wireguard::WireGuardManager::list_tunnels();
            IpcResponse::WireGuardList(tunnels)
        }

        IpcRequest::WireGuardStatus { tunnel } => {
            let state = ghostlink_engine::engine::wireguard::WireGuardManager::status(&tunnel);
            IpcResponse::WireGuardStatus { tunnel, state }
        }

        IpcRequest::WireGuardConnect { tunnel } => {
            match ghostlink_engine::engine::wireguard::WireGuardManager::connect(&tunnel) {
                Ok(()) => IpcResponse::Ok {
                    message: format!("WireGuard tunnel '{}' connected", tunnel),
                },
                Err(e) => IpcResponse::Error {
                    error: format!("Failed to connect WireGuard tunnel '{}': {}", tunnel, e),
                },
            }
        }

        IpcRequest::WireGuardDisconnect { tunnel } => {
            match ghostlink_engine::engine::wireguard::WireGuardManager::disconnect(&tunnel) {
                Ok(()) => IpcResponse::Ok {
                    message: format!("WireGuard tunnel '{}' disconnected", tunnel),
                },
                Err(e) => IpcResponse::Error {
                    error: format!("Failed to disconnect WireGuard tunnel '{}': {}", tunnel, e),
                },
            }
        }

        IpcRequest::WireGuardToggle { tunnel } => {
            match ghostlink_engine::engine::wireguard::WireGuardManager::toggle(&tunnel) {
                Ok(new_state) => IpcResponse::WireGuardStatus {
                    tunnel,
                    state: new_state,
                },
                Err(e) => IpcResponse::Error {
                    error: format!("Failed to toggle WireGuard tunnel '{}': {}", tunnel, e),
                },
            }
        }

        IpcRequest::AddRoute { ip, router, iface } => {
            // Security: Validate all arguments before executing as root
            if ip.parse::<std::net::Ipv4Addr>().is_err() {
                return IpcResponse::Error { error: format!("Invalid IP address: {}", ip) };
            }
            if router.parse::<std::net::Ipv4Addr>().is_err() {
                return IpcResponse::Error { error: format!("Invalid router IP: {}", router) };
            }
            if iface.is_empty() || iface.len() > 16 || !iface.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
                return IpcResponse::Error { error: format!("Invalid interface name: {}", iface) };
            }

            println!("🌐 [Daemon Root] Adding host route {} -> {} (interface {})", ip, router, iface);
            let _ = std::process::Command::new("/sbin/route")
                .args(["-n", "add", "-host", &ip, &router])
                .status();
            let _ = std::process::Command::new("/sbin/route")
                .args(["-n", "add", "-host", &ip, "-interface", &iface])
                .status();
            IpcResponse::Ok {
                message: format!("Route to {} via {} added", ip, iface),
            }
        }

        IpcRequest::DeleteRoute { ip, router, iface } => {
            // Security: Validate all arguments before executing as root
            if ip.parse::<std::net::Ipv4Addr>().is_err() {
                return IpcResponse::Error { error: format!("Invalid IP address: {}", ip) };
            }
            if router.parse::<std::net::Ipv4Addr>().is_err() {
                return IpcResponse::Error { error: format!("Invalid router IP: {}", router) };
            }
            if iface.is_empty() || iface.len() > 16 || !iface.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
                return IpcResponse::Error { error: format!("Invalid interface name: {}", iface) };
            }

            println!("🌐 [Daemon Root] Deleting host route {} -> {} (interface {})", ip, router, iface);
            let _ = std::process::Command::new("/sbin/route")
                .args(["-n", "delete", "-host", &ip, &router])
                .status();
            let _ = std::process::Command::new("/sbin/route")
                .args(["-n", "delete", "-host", &ip, "-interface", &iface])
                .status();
            IpcResponse::Ok {
                message: format!("Route to {} removed", ip),
            }
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

fn get_console_user() -> Option<(u32, u32)> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(m) = fs::metadata("/dev/console") {
            return Some((m.uid(), m.gid()));
        }
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

