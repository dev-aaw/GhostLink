pub mod autostart;
pub mod binary_manager;
pub mod ipc;
pub mod logging;
pub mod notifications;
pub mod payloads;
pub mod probes;
pub mod process;
pub mod smart_router;
pub mod strategies;
pub mod system_proxy;
pub mod types;
pub mod wireguard;
pub mod service;

use anyhow::{anyhow, Result};
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

pub use binary_manager::BinaryManager;
pub use ipc::{DaemonClient, IpcRequest, IpcResponse};
pub use notifications::notify;
pub use payloads::PayloadManager;
pub use probes::ProbeRunner;
pub use process::ProcessHandle;
pub use smart_router::SmartRouter;
pub use strategies::{StrategyManager, StrategyConfigManager};
pub use system_proxy::SystemProxyManager;
pub use types::{EngineConfig, EngineState, Platform, ProbeResult, ProbeSummary, Strategy};
pub use wireguard::{WireGuardManager, WireGuardState};
pub use autostart::AutoStartManager;
pub use service::ServiceManager;
pub use logging::{init_logger, log_msg, get_recent_log_entries, Logger};

pub fn silent_command<S: AsRef<std::ffi::OsStr>>(program: S) -> std::process::Command {
    let mut cmd = std::process::Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    cmd
}

/// Best-effort tail of the winws engine log, used to attach a concrete reason when
/// the process dies on startup instead of the opaque "crashed on startup".
#[cfg(target_os = "windows")]
fn read_engine_log_tail(lines: usize) -> String {
    let pdata = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    let log_path = std::path::PathBuf::from(pdata).join("GhostLink").join("logs").join("engine.log");
    let Ok(content) = std::fs::read_to_string(&log_path) else {
        return String::new();
    };
    let tail: Vec<&str> = content
        .lines()
        .rev()
        .filter(|l| !l.trim().is_empty())
        .take(lines)
        .collect();
    tail.into_iter().rev().collect::<Vec<_>>().join(" | ")
}

/// Single canonical WinDivert teardown for a stop/start transition: force any
/// stray `winws.exe` to exit, then stop+delete every WinDivert service variant
/// and wait (bounded) for the kernel driver to actually unload. Returns `false`
/// if the driver is still wedged after `timeout` (caller should refuse to spawn
/// a fresh `winws` and surface "a reboot is required").
///
/// `teardown_windivert` blocks (child processes + sleeps, up to several seconds),
/// so it runs on a blocking thread and is awaited — never inline on a tokio
/// worker while the daemon state lock is held.
#[cfg(target_os = "windows")]
async fn reset_windivert_driver(timeout: Duration) -> bool {
    tokio::task::spawn_blocking(move || {
        process::kill_stray_winws();
        process::teardown_windivert(timeout)
    })
    .await
    .unwrap_or(false)
}

pub struct UnblockEngine {
    config: EngineConfig,
    state: EngineState,
    binary_mgr: BinaryManager,
    strategy_mgr: StrategyManager,
    payload_mgr: PayloadManager,
    proxy_mgr: SystemProxyManager,
    probe_runner: ProbeRunner,
    active_process: Option<ProcessHandle>,
    watchdog_running: Arc<AtomicBool>,
    /// PID of the live engine child (tpws / winws), or 0. Kept outside the
    /// daemon's state Mutex so a shutdown path that cannot acquire the lock can
    /// still kill the child instead of orphaning it on the SOCKS port.
    active_engine_pid: Arc<AtomicU32>,
}

impl UnblockEngine {
    pub fn new(config: EngineConfig) -> Self {
        let base_dir = config.base_dir.clone();

        let binary_mgr = BinaryManager::new(&base_dir);
        let strategy_mgr = StrategyManager::new(&base_dir);
        let payload_mgr = PayloadManager::new(&base_dir);
        let proxy_mgr = SystemProxyManager::new(config.socks_port);
        let probe_runner = ProbeRunner::new();

        Self {
            config,
            state: EngineState::Stopped,
            binary_mgr,
            strategy_mgr,
            payload_mgr,
            proxy_mgr,
            probe_runner,
            active_process: None,
            watchdog_running: Arc::new(AtomicBool::new(false)),
            active_engine_pid: Arc::new(AtomicU32::new(0)),
        }
    }

    /// A handle to the live engine child's PID (0 = none), readable without the
    /// daemon state lock. Used by the daemon's shutdown-timeout path.
    pub fn engine_pid_handle(&self) -> Arc<AtomicU32> {
        self.active_engine_pid.clone()
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    pub fn state(&self) -> &EngineState {
        &self.state
    }

    pub fn is_running(&self) -> bool {
        matches!(self.state, EngineState::Running { .. })
    }

    /// Check if the active DPI bypass process is healthy and alive.
    pub fn check_health(&mut self) -> bool {
        if let Some(ref mut proc) = self.active_process {
            proc.is_alive()
        } else {
            !self.is_running()
        }
    }

    /// Return the OS process ID of the active engine process if running.
    pub fn active_pid(&self) -> Option<u32> {
        self.active_process.as_ref().map(|p| p.id())
    }

    pub fn list_strategies(&self) -> Vec<Strategy> {
        let bin_dir = self.binary_mgr.bin_dir();
        self.strategy_mgr.list_strategies(bin_dir, self.config.socks_port)
    }

    /// Prepares binaries, fake payloads and hostlists.
    pub async fn prepare(&self) -> Result<()> {
        self.binary_mgr.ensure_binaries().await?;
        self.payload_mgr.ensure_payloads()?;
        self.strategy_mgr.ensure_lists()?;

        Ok(())
    }

    /// Starts the engine with a specific strategy.
    pub async fn start(&mut self, strategy: &Strategy) -> Result<()> {
        // An explicit start is the user's (or watchdog's) retry: leave any Faulted
        // state so a WinDivert driver that has since recovered isn't locked out
        // until the daemon process restarts.
        self.clear_faulted();

        // stop() below tears down the WinDivert driver as part of shutdown; track
        // whether it ran so the Windows pre-flight doesn't repeat that teardown.
        let stopped_first = self.is_running() || self.active_process.is_some();
        if stopped_first {
            self.stop().await?;
        }

        self.prepare().await?;

        let exe_path = self.binary_mgr.get_executable_path();
        if !exe_path.exists() {
            return Err(anyhow!("Binary executable not found: {:?}", exe_path));
        }

        #[cfg(target_os = "windows")]
        {
            // Canonical pre-flight for the start transition: no stray winws holding
            // the WinDivert handle, and the driver from a prior crash fully
            // unloaded, before we spawn a fresh instance. Skip when stop() above
            // already unloaded it and nothing re-registered it since.
            let needs_teardown = !stopped_first || process::windivert_is_resident();
            if needs_teardown && !reset_windivert_driver(Duration::from_secs(6)).await {
                return Err(anyhow!(
                    "WinDivert kernel driver is wedged and will not unload; refusing to spawn winws. A reboot is required."
                ));
            }
        }

        println!("🚀 Launching engine with strategy: [{}]", strategy.name);
        let proc = ProcessHandle::spawn(&exe_path, &strategy.args)?;
        self.active_engine_pid.store(proc.id(), std::sync::atomic::Ordering::SeqCst);
        self.active_process = Some(proc);

        // Give the process a brief moment to initialize its socket/driver
        sleep(Duration::from_millis(600)).await;

        #[cfg(target_os = "macos")]
        {
            // 1. Strict Pre-Proxy Port Verification (macOS tpws SOCKS proxy)
            let mut port_listening = false;
            for _ in 0..30 {
                if tokio::net::TcpStream::connect(("127.0.0.1", self.config.socks_port)).await.is_ok() {
                    port_listening = true;
                    break;
                }
                sleep(Duration::from_millis(60)).await;
            }

            if !port_listening {
                eprintln!("❌ CRITICAL ERROR: Engine process spawned but port {} is NOT accepting TCP connections! Refusing to enable system proxy.", self.config.socks_port);
                let _ = self.stop().await;
                return Err(anyhow!("tpws failed to bind and listen on 127.0.0.1:{}", self.config.socks_port));
            }

            println!("✅ Port {} verified actively listening and accepting traffic.", self.config.socks_port);

            // 2. On macOS, configure system SOCKS proxy only AFTER port is 100% verified
            if self.config.apply_system_proxy {
                if let Err(e) = self.proxy_mgr.enable_macos_proxy() {
                    let _ = self.stop().await;
                    return Err(e);
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            if let Some(ref mut p) = self.active_process {
                if !p.is_alive() {
                    let detail = read_engine_log_tail(6);
                    let _ = self.stop().await;
                    let msg = if detail.is_empty() {
                        "winws.exe crashed on startup (no log output)".to_string()
                    } else {
                        format!("winws.exe crashed on startup: {}", detail)
                    };
                    self.state = EngineState::Error(msg.clone());
                    return Err(anyhow!(msg));
                }
            }
            println!("✅ WinDivert kernel packet filter active & transparently desyncing L3/L4 TCP & UDP traffic.");
        }

        self.state = EngineState::Running {
            strategy_name: strategy.name.clone(),
            port: self.config.socks_port,
        };

        // 3. Start Active Emergency Watchdog.
        //    On Windows the daemon owns health/revival (via check_health + a rolling
        //    circuit breaker), so this internal loop — and the watchdog_running flag
        //    that drives it — are macOS-only. On Windows there is no loop to arm.
        #[cfg(target_os = "macos")]
        {
            let watchdog_flag = self.watchdog_running.clone();
            watchdog_flag.store(true, std::sync::atomic::Ordering::SeqCst);
            let socks_port = self.config.socks_port;

            tokio::spawn(async move {
            use std::sync::atomic::Ordering::SeqCst;
            // Only a *sustained* outage should tear down the user's network
            // config. A single failed probe is expected under transient load
            // (tpws saturated at --maxconn, CPU spike, sleep/wake) and must not
            // orphan tpws while silently flipping the system proxy + DNS off.
            // 3 strikes * 1.5s ≈ 4.5s of continuous unresponsiveness.
            const MAX_CONSECUTIVE_FAILURES: u32 = 3;
            let mut consecutive_failures: u32 = 0;

            while watchdog_flag.load(SeqCst) {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                if !watchdog_flag.load(SeqCst) {
                    break;
                }

                // Actively probe localhost port with timeout
                let check = tokio::time::timeout(
                    Duration::from_millis(600),
                    tokio::net::TcpStream::connect(("127.0.0.1", socks_port)),
                ).await;
                let port_ok = matches!(check, Ok(Ok(_)));

                if port_ok {
                    if consecutive_failures > 0 {
                        eprintln!("✅ Watchdog: local proxy port {} responsive again after {} failed check(s).", socks_port, consecutive_failures);
                    }
                    consecutive_failures = 0;
                    continue;
                }

                consecutive_failures += 1;
                eprintln!("⚠️ Watchdog: local proxy port {} unresponsive ({}/{}).", socks_port, consecutive_failures, MAX_CONSECUTIVE_FAILURES);
                if consecutive_failures < MAX_CONSECUTIVE_FAILURES {
                    continue;
                }

                if watchdog_flag.swap(false, SeqCst) {
                    eprintln!("\n🚨 EMERGENCY WATCHDOG TRIGGERED: proxy port {} down for {} consecutive checks. Restoring system network settings...", socks_port, MAX_CONSECUTIVE_FAILURES);
                    let target = crate::engine::system_proxy::recorded_active_service()
                        .or_else(SystemProxyManager::detect_primary_macos_service);
                    if let Some(service) = target {
                        let _ = std::process::Command::new("networksetup")
                            .args(["-setsocksfirewallproxystate", &service, "off"])
                            .status();
                        let _ = std::process::Command::new("networksetup")
                            .args(["-setdnsservers", &service, "Empty"])
                            .status();
                    }
                    crate::engine::system_proxy::clear_recorded_service();
                    crate::engine::notifications::notify(
                        "GhostLink Emergency Recovery",
                        "GhostLink recovered from an error automatically (network restored)",
                    );
                    eprintln!("✨ System network settings restored to normal.\n");
                }
                break;
            }
            });
        }

        Ok(())
    }

    /// Stops the running engine and restores system settings.
    pub async fn stop(&mut self) -> Result<()> {
        self.watchdog_running.store(false, std::sync::atomic::Ordering::SeqCst);
        self.active_engine_pid.store(0, std::sync::atomic::Ordering::SeqCst);

        let active_pid = if let Some(mut proc) = self.active_process.take() {
            let pid = proc.id();
            println!("🛑 Stopping engine process (PID: {})...", pid);
            let _ = proc.kill();
            Some(pid)
        } else {
            None
        };

        let _ = self.proxy_mgr.restore_all_system_settings();

        #[cfg(target_os = "windows")]
        {
            if let Some(pid) = active_pid {
                // Scoped termination: kill only our specific child process PID
                let _ = silent_command("taskkill.exe")
                    .args(["/F", "/PID", &pid.to_string()])
                    .status();
            } else {
                // Fallback only if no active process handle was tracked
                let _ = silent_command("taskkill.exe")
                    .args(["/F", "/IM", "winws.exe"])
                    .status();
            }

            // winws is dead but its WinDivert driver stays resident; unload it
            // here (once, off-thread) so the next start is clean. This is the
            // single teardown point for the stop transition.
            if active_pid.is_some() {
                let _ = reset_windivert_driver(Duration::from_secs(5)).await;
            }
        }

        self.state = EngineState::Stopped;
        Ok(())
    }

    /// Put the engine into the unrecoverable Faulted state: stop everything, restore
    /// system settings, and record why. The daemon watchdog calls this after it has
    /// exhausted its revival budget (a wedged WinDivert driver that a reboot must clear).
    pub async fn mark_faulted(&mut self, reason: impl Into<String>) {
        let reason = reason.into();
        self.watchdog_running.store(false, std::sync::atomic::Ordering::SeqCst);
        self.active_engine_pid.store(0, std::sync::atomic::Ordering::SeqCst);
        if let Some(mut proc) = self.active_process.take() {
            let _ = proc.kill();
        }
        let _ = self.proxy_mgr.restore_all_system_settings();
        self.state = EngineState::Faulted(reason);
    }

    /// Clear a Faulted state back to Stopped. Called at the top of `start()` so an
    /// explicit start/SetStrategy retry can recover once WinDivert is healthy again,
    /// without waiting for a daemon restart.
    pub fn clear_faulted(&mut self) {
        if matches!(self.state, EngineState::Faulted(_)) {
            self.state = EngineState::Stopped;
        }
    }

    /// Benchmark test a specific strategy.
    pub async fn test_strategy(&mut self, strategy: &Strategy) -> Result<ProbeSummary> {
        // Temporarily launch process without changing system-wide proxy
        self.prepare().await?;

        let exe_path = self.binary_mgr.get_executable_path();

        #[cfg(target_os = "windows")]
        {
            // One teardown per benchmark spawn (was previously done three times per
            // strategy: here in auto_tune, again inside ProcessHandle::spawn, and a
            // third time on kill()/Drop).
            if !reset_windivert_driver(Duration::from_secs(6)).await {
                return Err(anyhow!(
                    "WinDivert kernel driver is wedged and will not unload; a reboot is required."
                ));
            }
        }

        let mut proc = ProcessHandle::spawn(&exe_path, &strategy.args)?;
        sleep(Duration::from_millis(700)).await;

        if !proc.is_alive() {
            return Ok(ProbeSummary {
                strategy_id: strategy.id.clone(),
                success: false,
                total_latency_ms: 0,
                results: vec![ProbeResult {
                    rule_id: "process_startup".to_string(),
                    label: "Process Launch".to_string(),
                    url: "".to_string(),
                    success: false,
                    status_code: None,
                    latency_ms: 0,
                    error: Some("Process crashed immediately on launch".to_string()),
                }],
            });
        }

        // On macOS, we probe through the local SOCKS proxy; on Windows WinDivert intercepts transparently
        let proxy_url = if cfg!(target_os = "macos") {
            Some(format!("socks5h://127.0.0.1:{}", self.config.socks_port))
        } else {
            None
        };

        let summary = self.probe_runner.run_suite(&strategy.id, proxy_url.as_deref()).await;

        // Clean up temporary process
        let _ = proc.kill();

        Ok(summary)
    }

    /// Automatically benchmarks all strategies for current OS and returns the best one.
    pub async fn auto_tune<F>(&mut self, mut progress_cb: F) -> Result<Option<Strategy>>
    where
        F: FnMut(usize, usize, &Strategy, Option<&ProbeSummary>),
    {
        // If the engine is currently running, stop it temporarily so benchmark processes
        // don't conflict over the WinDivert kernel filter handle on Windows.
        if self.is_running() {
            println!("🛑 [AutoTune] Temporarily stopping active engine for conflict-free benchmarking...");
            let _ = self.stop().await;
            sleep(Duration::from_millis(300)).await;
        }

        // Pause the macOS emergency watchdog during auto-tune so its port probe
        // doesn't fire a false recovery while we kill/spawn winws per strategy.
        // (On Windows there is no such loop — the daemon circuit breaker already
        // stands down while auto_tune holds the state lock — so there is nothing
        // to pause and no reason to dead-wait.)
        #[cfg(target_os = "macos")]
        if self.watchdog_running.load(std::sync::atomic::Ordering::SeqCst) {
            self.watchdog_running.store(false, std::sync::atomic::Ordering::SeqCst);
            // Give the watchdog loop time to notice the flag and exit
            sleep(Duration::from_millis(200)).await;
            println!("⏸️ [AutoTune] Watchdog paused during strategy benchmarking.");
        }

        let strategies = self.list_strategies();
        let total = strategies.len();
        let mut best: Option<(Strategy, ProbeSummary)> = None;

        for (idx, strat) in strategies.iter().enumerate() {
            progress_cb(idx + 1, total, strat, None);

            // test_strategy() runs the single per-spawn WinDivert teardown itself
            // (once), so there is nothing to clean up here between iterations.
            match self.test_strategy(strat).await {
                Ok(summary) => {
                    progress_cb(idx + 1, total, strat, Some(&summary));

                    if summary.success {
                        let is_better = match &best {
                            None => true,
                            Some((_, prev_best)) => summary.total_latency_ms < prev_best.total_latency_ms,
                        };
                        if is_better {
                            best = Some((strat.clone(), summary));
                        }
                    }
                }
                Err(e) => {
                    progress_cb(idx + 1, total, strat, None);
                    // A wedged WinDivert driver won't clear for the next strategy
                    // either — stop the sweep instead of failing every remaining one.
                    let msg = e.to_string();
                    if msg.contains("wedged") || msg.contains("reboot") {
                        println!("⛔ [AutoTune] WinDivert driver wedged; aborting benchmark early. A reboot is required.");
                        break;
                    }
                }
            }
        }

        // Note: watchdog will be re-armed when the caller invokes start() with the winning strategy
        Ok(best.map(|(s, _)| s))
    }
}
