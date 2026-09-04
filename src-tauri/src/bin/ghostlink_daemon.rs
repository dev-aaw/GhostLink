#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use anyhow::{anyhow, Result};
use ghostlink_engine::engine::ipc::{
    DaemonStatusInfo, IpcEnvelope, IpcRequest, IpcResponse,
};
#[cfg(windows)]
use ghostlink_engine::engine::ipc::WINDOWS_PIPE_NAME;
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
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

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
    #[cfg(target_os = "macos")]
    let socks_port = config.socks_port;
    let engine = UnblockEngine::new(config);
    let state = Arc::new(Mutex::new(DaemonState {
        engine,
        active_strategy: None,
        start_time: Instant::now(),
    }));

    // Grab both engine-child PID handles now, while the lock is uncontended, so
    // the shutdown-timeout path can kill an orphaned tpws without the state
    // lock. Two separate handles because the real engine (engine_pid_handle)
    // and a `test_strategy()` benchmark run (benchmark_pid_handle) can be alive
    // at the same time — IpcRequest::TestStrategy does not stop() the real
    // engine first, by design, so they must never share a slot.
    #[cfg(unix)]
    let engine_pid = { state.lock().await.engine.engine_pid_handle() };
    #[cfg(unix)]
    let benchmark_pid = { state.lock().await.engine.benchmark_pid_handle() };

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

        // A fresh daemon owns no engine, so any SOCKS proxy still pointing at our
        // loopback port is stale — left by a previous daemon that was SIGKILLed
        // (launchd's shutdown timeout during a long AutoTune) before it could
        // restore the network. launchd's KeepAlive would otherwise leave the
        // user stuck: GUI says "stopped" while traffic dead-ends at an orphan
        // tpws. Reconcile only when the proxy is provably ours (loopback + our
        // port). Run it AFTER bind and on the blocking pool: it forks several
        // `route`/`networksetup` subprocesses (~1-2s) and must not stall the
        // async executor or delay the listener coming up.
        #[cfg(target_os = "macos")]
        {
            let _ = tokio::task::spawn_blocking(move || reconcile_stale_proxy(socks_port)).await;
        }

        // 4. Setup signal listeners for graceful shutdown
        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;

        let state_for_signals = Arc::clone(&state);
        let socket_for_signals = actual_socket_path.clone();
        let engine_pid_for_signals = engine_pid.clone();
        let benchmark_pid_for_signals = benchmark_pid.clone();

        tokio::spawn(async move {
            tokio::select! {
                _ = sigterm.recv() => {
                    println!("\n🛑 Received SIGTERM, stopping engine and cleaning up...");
                }
                _ = sigint.recv() => {
                    println!("\n🛑 Received SIGINT (Ctrl+C), stopping engine and cleaning up...");
                }
            }

            // Do not let a busy state lock (an in-flight AutoTune) delay cleanup
            // past launchd's kill window — that is how a stale proxy gets left
            // behind. Try the graceful path briefly, then fall back to a
            // best-effort network restore without the lock.
            match tokio::time::timeout(std::time::Duration::from_secs(3), state_for_signals.lock()).await {
                Ok(mut st) => {
                    let _ = st.engine.stop().await;
                }
                Err(_) => {
                    eprintln!("⚠️ State lock busy during shutdown — best-effort restore without it.");
                    #[cfg(target_os = "macos")]
                    best_effort_proxy_off();
                    // engine.stop() never ran, so the real engine child
                    // (tpws/winws) would be reparented to launchd still holding
                    // the SOCKS port. A concurrent test_strategy() benchmark
                    // child (IpcRequest::TestStrategy does not stop() the real
                    // engine first) would orphan the same way, in its own slot.
                    // Both are independent and both may be non-zero at once.
                    // kill_orphan_if_alive is #[cfg(target_os = "macos")] (libc
                    // is a macOS-only dependency); gate these call sites the
                    // same way rather than relying on the enclosing #[cfg(unix)]
                    // block, to keep the cfgs honest with each other.
                    #[cfg(target_os = "macos")]
                    {
                        let pid_a = engine_pid_for_signals.load(std::sync::atomic::Ordering::SeqCst);
                        let pid_b = benchmark_pid_for_signals.load(std::sync::atomic::Ordering::SeqCst);
                        kill_orphan_if_alive(pid_a, "engine");
                        kill_orphan_if_alive(pid_b, "benchmark");
                    }
                }
            }
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

        // Named-pipe security descriptor: SYSTEM + local Administrators get full
        // control, interactively logged-on users get read/write (the tray/CLI run
        // in the user's session). Nothing else — no anonymous, network, or
        // sandboxed-AppContainer access.
        let mut pipe_sa = PipeSecurityAttributes::new()
            .ok_or_else(|| anyhow!("Failed to build named-pipe security descriptor"))?;

        let mut listener: NamedPipeServer = unsafe {
            ServerOptions::new()
                .first_pipe_instance(true)
                .create_with_security_attributes_raw(WINDOWS_PIPE_NAME, pipe_sa.as_mut_ptr())
        }
        .map_err(|e| anyhow!("Failed to create GhostLink daemon pipe {}: {}", WINDOWS_PIPE_NAME, e))?;

        println!("📡 Listening on secured named pipe: {}", WINDOWS_PIPE_NAME);

        let state_for_signals = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            println!("\n🛑 Received Ctrl+C, stopping GhostLink Windows Engine and cleaning up...");
            let mut st = state_for_signals.lock().await;
            let _ = st.engine.stop().await;
            std::process::exit(0);
        });

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

        // 3. Resilience Watchdog & Network Transition Monitor with a bounded circuit breaker.
        //
        //    Revival budget: REVIVAL_LIMIT restarts inside REVIVAL_WINDOW. Cross that and
        //    the driver is genuinely wedged — we stop trying, mark the engine Faulted,
        //    and tell the user a reboot is required (instead of spinning winws forever).
        let state_for_watchdog = Arc::clone(&state);
        tokio::spawn(async move {
            use std::time::{Duration, Instant};
            const REVIVAL_WINDOW: Duration = Duration::from_secs(300);
            const REVIVAL_LIMIT: usize = 6;

            let mut last_adapters = ghostlink_engine::SystemProxyManager::detect_active_windows_adapters();
            let mut revival_times: Vec<Instant> = Vec::new();
            let mut tried_fallback = false;
            let mut iteration = 0u64;

            loop {
                tokio::time::sleep(Duration::from_millis(5000)).await;
                iteration += 1;

                // Watchdog Check
                let (needs_revival, strat_to_revive) = {
                    let mut st = state_for_watchdog.lock().await;
                    if st.engine.is_running() && !st.engine.check_health() {
                        (true, st.active_strategy.clone())
                    } else {
                        if st.engine.is_running() {
                            // Healthy run — decay the revival history so a later, unrelated
                            // blip doesn't inherit an old strike count.
                            revival_times.clear();
                            tried_fallback = false;
                        }
                        (false, None)
                    }
                };

                if needs_revival {
                    let now = Instant::now();
                    revival_times.retain(|t| now.duration_since(*t) < REVIVAL_WINDOW);
                    revival_times.push(now);
                    let strikes = revival_times.len();

                    if strikes >= REVIVAL_LIMIT {
                        ghostlink_engine::log_error!(
                            "winws revival budget exhausted ({}/{} in {}s). WinDivert appears wedged — marking engine Faulted; a reboot is required.",
                            strikes, REVIVAL_LIMIT, REVIVAL_WINDOW.as_secs()
                        );
                        {
                            let mut st = state_for_watchdog.lock().await;
                            st.engine.mark_faulted(
                                "WinDivert kernel driver is wedged after repeated restart attempts. Please reboot Windows to recover GhostLink."
                            ).await;
                        }
                        ghostlink_engine::notify(
                            "GhostLink — Yeniden Başlatma Gerekli",
                            "Ağ sürücüsü (WinDivert) kilitlendi ve GhostLink kendini onaramıyor. Lütfen bilgisayarınızı yeniden başlatın; açılışta otomatik düzelecektir.",
                        );
                        // Stop watching. On the next boot the daemon starts fresh (state = Stopped)
                        // and AutoStart brings the engine back up on a clean driver.
                        break;
                    } else if strikes <= 3 {
                        if let Some(strat) = strat_to_revive {
                            ghostlink_engine::log_warn!("Detected winws crash/stop (strike {}/{})! Reviving with [{}]...", strikes, REVIVAL_LIMIT, strat.name);
                            let mut st = state_for_watchdog.lock().await;
                            match st.engine.start(&strat).await {
                                Ok(()) => ghostlink_engine::log_info!("winws revived with strategy [{}].", strat.name),
                                Err(e) => ghostlink_engine::log_error!("Revival start failed: {}", e),
                            }
                        }
                    } else if !tried_fallback {
                        // One-shot: switch to an ISP-hardened fallback strategy.
                        tried_fallback = true;
                        ghostlink_engine::log_error!("Repeated winws crashes (strike {}). One-shot fallback to [win-superonline]/[win-alt]...", strikes);
                        let mut st = state_for_watchdog.lock().await;
                        let list = st.engine.list_strategies();
                        if let Some(fallback) = list.into_iter().find(|s| s.id == "win-superonline" || s.id == "win-alt") {
                            match st.engine.start(&fallback).await {
                                Ok(()) => {
                                    st.active_strategy = Some(fallback.clone());
                                    let _ = ghostlink_engine::StrategyConfigManager::save_selected_strategy(&fallback.id);
                                }
                                Err(e) => ghostlink_engine::log_error!("Fallback start failed: {}", e),
                            }
                        }
                    } else {
                        // Strikes 4..LIMIT after the fallback was already tried: brief backoff,
                        // then keep reviving the current strategy until the budget runs out.
                        ghostlink_engine::log_warn!("winws still unstable (strike {}/{}); backing off 15s.", strikes, REVIVAL_LIMIT);
                        tokio::time::sleep(Duration::from_secs(15)).await;
                        if let Some(strat) = strat_to_revive {
                            let mut st = state_for_watchdog.lock().await;
                            let _ = st.engine.start(&strat).await;
                        }
                    }
                }

                // Network Transition Check - only run periodically (every 30s / 6 iterations) to prevent process spawning
                if iteration % 6 == 0 {
                    let current_adapters = ghostlink_engine::SystemProxyManager::detect_active_windows_adapters();
                    if !last_adapters.is_empty() && last_adapters != current_adapters {
                        ghostlink_engine::log_info!("Network interface change detected: {:?} -> {:?}. Reapplying clean DNS...", last_adapters, current_adapters);
                        let _ = ghostlink_engine::silent_command("ipconfig.exe").args(["/flushdns"]).status();
                        let _ = ghostlink_engine::silent_command("powershell.exe")
                            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                                "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceAlias $_.InterfaceAlias -ServerAddresses @('1.1.1.1','1.0.0.1') -ErrorAction SilentlyContinue }"])
                            .status();
                    }
                    last_adapters = current_adapters;
                }
            }
        });

        loop {
            // Wait for a client on the current instance.
            if let Err(e) = listener.connect().await {
                eprintln!("⚠️ Pipe connect error: {}", e);
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                continue;
            }

            // Immediately stand up the next instance so there is always a pipe to
            // connect to, then hand the connected instance to a task.
            let next = loop {
                match unsafe {
                    ServerOptions::new()
                        .create_with_security_attributes_raw(WINDOWS_PIPE_NAME, pipe_sa.as_mut_ptr())
                } {
                    Ok(s) => break s,
                    Err(e) => {
                        eprintln!("⚠️ Failed to create next pipe instance, retrying: {}", e);
                        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                    }
                }
            };
            let connected = std::mem::replace(&mut listener, next);

            let state_clone = Arc::clone(&state);
            tokio::spawn(async move {
                if let Err(e) = handle_pipe_connection(connected, state_clone).await {
                    eprintln!("⚠️ Error handling client connection: {}", e);
                }
            });
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}

/// Turn off a SOCKS proxy on the primary service only when it is provably the
/// one GhostLink set (loopback address + our port). Runs at daemon startup to
/// recover from a previous instance that was killed before restoring the network.
#[cfg(target_os = "macos")]
fn reconcile_stale_proxy(socks_port: u16) {
    use ghostlink_engine::engine::system_proxy as sp;

    // The recorded service first (a network switch means it differs from the
    // current primary, and the stale proxy sits on the recorded one), then the
    // current primary service.
    let mut candidates: Vec<String> = Vec::new();
    if let Some(s) = sp::recorded_active_service() {
        candidates.push(s);
    }
    if let Some(s) = sp::SystemProxyManager::detect_primary_macos_service() {
        if !candidates.contains(&s) {
            candidates.push(s);
        }
    }

    let mut disabled_any = false;
    for service in candidates {
        let out = match std::process::Command::new("networksetup")
            .args(["-getsocksfirewallproxy", &service])
            .output()
        {
            Ok(o) => o,
            Err(_) => continue,
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let (mut enabled, mut server, mut port) = (false, String::new(), String::new());
        for line in text.lines() {
            let l = line.trim();
            if let Some(v) = l.strip_prefix("Enabled:") {
                enabled = v.trim().eq_ignore_ascii_case("yes");
            } else if let Some(v) = l.strip_prefix("Server:") {
                server = v.trim().to_string();
            } else if let Some(v) = l.strip_prefix("Port:") {
                port = v.trim().to_string();
            }
        }
        let is_loopback = server == "127.0.0.1" || server.eq_ignore_ascii_case("localhost");
        if enabled && is_loopback && port == socks_port.to_string() {
            let _ = std::process::Command::new("networksetup")
                .args(["-setsocksfirewallproxystate", &service, "off"])
                .status();
            let _ = std::process::Command::new("networksetup")
                .args(["-setdnsservers", &service, "Empty"])
                .status();
            println!("🧹 Startup reconcile: disabled stale GhostLink SOCKS proxy on [{}] (loopback:{} had no owning engine).", service, socks_port);
            disabled_any = true;
        }
    }
    if disabled_any {
        sp::clear_recorded_service();
    }
}

/// Best-effort SOCKS/DNS restore, mirroring the engine's own disable path.
/// Only reached on shutdown when the state lock cannot be acquired in time.
/// No detect_primary_macos_service() fallback: only a recorded service means
/// the daemon's engine actually enabled the system proxy at some point; absent
/// a record there is nothing of ours to tear down, and guessing the primary
/// service would disable a proxy GhostLink never touched.
#[cfg(target_os = "macos")]
fn best_effort_proxy_off() {
    use ghostlink_engine::engine::system_proxy as sp;
    let target = sp::recorded_active_service();
    if let Some(service) = target {
        let _ = std::process::Command::new("networksetup")
            .args(["-setsocksfirewallproxystate", &service, "off"])
            .status();
        let _ = std::process::Command::new("networksetup")
            .args(["-setdnsservers", &service, "Empty"])
            .status();
    }
    sp::clear_recorded_service();
}

/// Kill `pid` if it is still alive, on the shutdown-timeout fallback path.
/// `label` is only used in the log line ("engine" / "benchmark").
///
/// kill(pid, 0) is a pure existence check (sends no signal). It narrows the
/// PID-reuse window (the child already exited on its own and the OS recycled
/// its PID before this fallback ran) down to the gap between this check and
/// the SIGKILL below, instead of the whole 3s+ timeout that preceded it. Not a
/// complete fix — only an OS process handle (pidfd / kqueue EVFILT_PROC)
/// closes that gap entirely — but a cheap reduction of an already-narrow,
/// theoretical risk, and ProcessHandle::spawn/kill clear their slot promptly
/// on every normal path, so a genuinely stale PID here should be rare.
///
/// macOS-only (not `#[cfg(unix)]`): `libc` is a macOS-only Cargo dependency
/// (see Cargo.toml) and this crate is only ever shipped for macOS and Windows,
/// so a `kill -9` subprocess fallback "for a hypothetical non-macOS unix
/// build" was dead code that could never actually compile for any supported
/// or even hypothetical target of this project.
#[cfg(target_os = "macos")]
fn kill_orphan_if_alive(pid: u32, label: &str) {
    if pid == 0 {
        return;
    }
    let still_alive = unsafe { libc::kill(pid as libc::pid_t, 0) == 0 };
    if still_alive {
        eprintln!("   killing orphaned {label} child pid {pid}");
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
        }
    } else {
        eprintln!("   {label} child pid {pid} already exited; nothing to kill");
    }
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
async fn handle_pipe_connection(stream: NamedPipeServer, state: Arc<Mutex<DaemonState>>) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

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

        // The named-pipe DACL (SYSTEM + Administrators + INTERACTIVE only) is the
        // authentication boundary on Windows, so no per-request token check here.
        // Both the envelope form and a bare IpcRequest are accepted.
        let request = if let Ok(envelope) = serde_json::from_str::<IpcEnvelope>(trimmed) {
            envelope.request
        } else if let Ok(req) = serde_json::from_str::<IpcRequest>(trimmed) {
            req
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

            let engine_state = st.engine.state().to_string();
            let faulted_reason = match st.engine.state() {
                EngineState::Faulted(reason) => Some(reason.clone()),
                _ => None,
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
                engine_state,
                faulted_reason,
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

/// Whether the current process token is elevated. This is polled on every Ping /
/// GetStatus (the tray refreshes status every couple of seconds), so it must not
/// spawn a child process — the old implementation ran `net.exe session` each call.
#[cfg(windows)]
fn is_windows_admin() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Owns a self-relative SECURITY_DESCRIPTOR (built from SDDL) plus the
/// SECURITY_ATTRIBUTES that points at it, for use with
/// `ServerOptions::create_with_security_attributes_raw`.
///
/// SDDL: SYSTEM (SY) and the local Administrators group (BA) get GENERIC_ALL;
/// interactively logged-on users (IU) get GENERIC_READ | GENERIC_WRITE — enough
/// for the tray/CLI in the user's session to talk to the pipe, and nothing for
/// anonymous, network, service, or AppContainer callers.
#[cfg(windows)]
struct PipeSecurityAttributes {
    sd: *mut core::ffi::c_void,
    sa: windows_sys::Win32::Security::SECURITY_ATTRIBUTES,
}

#[cfg(windows)]
impl PipeSecurityAttributes {
    fn new() -> Option<Self> {
        use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

        const SDDL_REVISION_1: u32 = 1;
        let sddl: Vec<u16> = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut sd: *mut core::ffi::c_void = std::ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || sd.is_null() {
            return None;
        }

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        Some(Self { sd, sa })
    }

    fn as_mut_ptr(&mut self) -> *mut core::ffi::c_void {
        &mut self.sa as *mut _ as *mut core::ffi::c_void
    }
}

#[cfg(windows)]
impl Drop for PipeSecurityAttributes {
    fn drop(&mut self) {
        if !self.sd.is_null() {
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.sd); }
        }
    }
}

#[cfg(windows)]
const HOSTS_BLOCK_BEGIN: &str = "# >>> GhostLink managed hosts (do not edit inside this block) >>>";
#[cfg(windows)]
const HOSTS_BLOCK_END: &str = "# <<< GhostLink managed hosts <<<";

/// Synchronize a small, marker-delimited block of hosts entries.
///
/// Design notes:
///  * Only lines *between* the two markers are ever touched — a user's own hosts
///    entries (including unrelated 162.159.* or discord lines) are never removed.
///  * The Discord updater hosts (updates.discord.com, dl2.discordapp.net) are
///    deliberately NOT pinned here. They live on rotating Google/Fastly IPs, and a
///    stale pin is exactly what causes the "Checking for updates" hang. They are
///    handled by the winws DPI-desync rule (list-discord.txt) + system DoH instead.
///  * Only the DNS-poisoned Discord control-plane apexes get a Cloudflare pin, as a
///    safety net for the brief window before system DoH is in effect.
#[cfg(windows)]
fn ensure_clean_hosts() {
    let hosts_path = r"C:\Windows\System32\drivers\etc\hosts";

    // Discord's Cloudflare anycast address for the control plane (gateway / API / auth).
    // These apexes are DNS-poisoned by TR ISPs; CDN / media / updater hosts are intentionally absent.
    let managed: [&str; 4] = [
        "162.159.138.232 discord.com",
        "162.159.138.232 discord.gg",
        "162.159.138.232 discordapp.com",
        "162.159.138.232 gateway.discord.gg",
    ];

    // If we cannot read the current hosts file, do NOT write one — that would
    // wipe the user's existing entries. Fall back to DoH + DPI desync only.
    let content = match std::fs::read_to_string(hosts_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("⚠️ [DNS] Cannot read hosts file ({e}); skipping managed block, relying on DoH + DPI desync.");
            return;
        }
    };

    // Split out any previous GhostLink block, keeping everything else verbatim.
    let mut kept: Vec<&str> = Vec::new();
    let mut inside = false;
    let mut had_block = false;
    for line in content.lines() {
        let t = line.trim();
        if t == HOSTS_BLOCK_BEGIN {
            inside = true;
            had_block = true;
            continue;
        }
        if t == HOSTS_BLOCK_END {
            inside = false;
            continue;
        }
        if !inside {
            kept.push(line);
        }
    }

    // Trim trailing blank lines from the preserved section for a clean append.
    while matches!(kept.last(), Some(l) if l.trim().is_empty()) {
        kept.pop();
    }

    let mut new_content = kept.join("\r\n");
    new_content.push_str("\r\n");
    new_content.push_str(HOSTS_BLOCK_BEGIN);
    new_content.push_str("\r\n");
    for e in &managed {
        new_content.push_str(e);
        new_content.push_str("\r\n");
    }
    new_content.push_str(HOSTS_BLOCK_END);
    new_content.push_str("\r\n");

    // Only write if the effective content changed (avoids a flush-dns storm on every boot).
    let normalized_old = content.replace('\r', "");
    let normalized_new = new_content.replace('\r', "");
    if normalized_old != normalized_new {
        if std::fs::write(hosts_path, &new_content).is_ok() {
            let _ = ghostlink_engine::silent_command("ipconfig.exe").arg("/flushdns").output();
            println!(
                "🛡️ [DNS] GhostLink hosts block synchronized ({} entries, block {}).",
                managed.len(),
                if had_block { "refreshed" } else { "created" }
            );
        } else {
            eprintln!("⚠️ [DNS] Could not write hosts file (permission?). Relying on DoH + DPI desync only.");
        }
    }
}

