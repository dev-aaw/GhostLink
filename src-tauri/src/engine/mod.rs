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
use std::sync::atomic::AtomicBool;
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
        }
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
        if self.is_running() {
            self.stop().await?;
        }

        self.prepare().await?;

        let exe_path = self.binary_mgr.get_executable_path();
        if !exe_path.exists() {
            return Err(anyhow!("Binary executable not found: {:?}", exe_path));
        }

        println!("🚀 Launching engine with strategy: [{}]", strategy.name);
        let proc = ProcessHandle::spawn(&exe_path, &strategy.args)?;
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
        //    circuit breaker), so this internal loop is macOS-only — spawning it on
        //    Windows just leaked an idle task that spun until stop().
        let watchdog_flag = self.watchdog_running.clone();
        watchdog_flag.store(true, std::sync::atomic::Ordering::SeqCst);
        #[cfg(target_os = "macos")]
        let socks_port = self.config.socks_port;

        #[cfg(target_os = "macos")]
        tokio::spawn(async move {
            while watchdog_flag.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                if !watchdog_flag.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }

                {
                    // Actively probe localhost port with timeout
                    let check = tokio::time::timeout(
                        Duration::from_millis(350),
                        tokio::net::TcpStream::connect(("127.0.0.1", socks_port)),
                    ).await;

                    let port_ok = matches!(check, Ok(Ok(_)));

                    if !port_ok {
                        if watchdog_flag.swap(false, std::sync::atomic::Ordering::SeqCst) {
                            eprintln!("\n🚨 EMERGENCY WATCHDOG TRIGGERED: GhostLink engine dropped! Restoring system network settings instantly...");
                            if let Some(service) = SystemProxyManager::detect_primary_macos_service() {
                                let _ = std::process::Command::new("networksetup")
                                    .args(["-setsocksfirewallproxystate", &service, "off"])
                                    .status();
                                let _ = std::process::Command::new("networksetup")
                                    .args(["-setdnsservers", &service, "Empty"])
                                    .status();
                            }
                            crate::engine::notifications::notify(
                                "GhostLink Emergency Recovery",
                                "GhostLink recovered from an error automatically (network restored)",
                            );
                            eprintln!("✨ System network settings restored to normal.\n");
                            break;
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Stops the running engine and restores system settings.
    pub async fn stop(&mut self) -> Result<()> {
        self.watchdog_running.store(false, std::sync::atomic::Ordering::SeqCst);

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
        if let Some(mut proc) = self.active_process.take() {
            let _ = proc.kill();
        }
        let _ = self.proxy_mgr.restore_all_system_settings();
        self.state = EngineState::Faulted(reason);
    }

    /// Clear a Faulted state back to Stopped (e.g. after the user reboots and the
    /// daemon restarts, or an explicit manual reset).
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

        // Pause watchdog during auto-tune to prevent false restarts while we kill/spawn winws per strategy
        let was_watchdog_active = self.watchdog_running.load(std::sync::atomic::Ordering::SeqCst);
        if was_watchdog_active {
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

            // Between benchmark spawns, make sure the previous winws is gone and the
            // WinDivert driver has fully unloaded before the next one grabs the handle.
            #[cfg(target_os = "windows")]
            {
                if crate::engine::process::windivert_is_resident() {
                    let cleared = crate::engine::process::teardown_windivert(std::time::Duration::from_secs(6));
                    if !cleared {
                        println!("⛔ [AutoTune] WinDivert driver wedged; aborting benchmark early. A reboot is required.");
                        break;
                    }
                }
                sleep(Duration::from_millis(400)).await;
            }

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
                Err(_) => {
                    progress_cb(idx + 1, total, strat, None);
                }
            }
        }

        // Note: watchdog will be re-armed when the caller invokes start() with the winning strategy
        Ok(best.map(|(s, _)| s))
    }
}
