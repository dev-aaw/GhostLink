pub mod autostart;
pub mod binary_manager;
pub mod ipc;
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
pub use strategies::StrategyManager;
pub use system_proxy::SystemProxyManager;
pub use types::{EngineConfig, EngineState, Platform, ProbeResult, ProbeSummary, Strategy};
pub use wireguard::{WireGuardManager, WireGuardState};
pub use autostart::AutoStartManager;
pub use service::ServiceManager;

pub fn silent_command<S: AsRef<std::ffi::OsStr>>(program: S) -> std::process::Command {
    let mut cmd = std::process::Command::new(program);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000);
    }
    cmd
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

    pub fn list_strategies(&self) -> Vec<Strategy> {
        let bin_dir = self.binary_mgr.bin_dir();
        self.strategy_mgr.list_strategies(bin_dir, self.config.socks_port)
    }

    /// Prepares binaries, fake payloads and hostlists.
    pub async fn prepare(&self) -> Result<()> {
        self.binary_mgr.ensure_binaries().await?;
        self.payload_mgr.ensure_payloads()?;
        self.strategy_mgr.ensure_lists()?;

        #[cfg(target_os = "windows")]
        {
            let _ = silent_command("taskkill.exe")
                .args(["/F", "/IM", "winws.exe"])
                .status();
        }

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
                    let _ = self.stop().await;
                    return Err(anyhow!("winws.exe process failed to launch or crashed on startup"));
                }
            }
            println!("✅ WinDivert kernel packet filter active & transparently desyncing L3/L4 TCP & UDP traffic.");

            // Configure clean DNS servers (Cloudflare / Google) to defeat ISP DNS poisoning/hijacking
            let clean_dns = vec![
                "1.1.1.1".to_string(),
                "1.0.0.1".to_string(),
                "8.8.8.8".to_string(),
            ];
            let _ = self.proxy_mgr.enable_windows_dns(&clean_dns);
        }

        self.state = EngineState::Running {
            strategy_name: strategy.name.clone(),
            port: self.config.socks_port,
        };

        // 3. Start Active Emergency Watchdog
        let socks_port = self.config.socks_port;
        let watchdog_flag = self.watchdog_running.clone();
        watchdog_flag.store(true, std::sync::atomic::Ordering::SeqCst);

        tokio::spawn(async move {
            while watchdog_flag.load(std::sync::atomic::Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                if !watchdog_flag.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }

                #[cfg(target_os = "macos")]
                {
                    // Actively probe localhost port with timeout
                    let check = tokio::time::timeout(
                        Duration::from_millis(350),
                        tokio::net::TcpStream::connect(("127.0.0.1", socks_port)),
                    ).await;

                    let port_ok = match check {
                        Ok(Ok(_)) => true,
                        _ => false,
                    };

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

                #[cfg(not(target_os = "macos"))]
                {
                    // On Windows, WinDivert driver unloads automatically on process exit
                    let _ = socks_port;
                }
            }
        });

        Ok(())
    }

    /// Stops the running engine and restores system settings.
    pub async fn stop(&mut self) -> Result<()> {
        self.watchdog_running.store(false, std::sync::atomic::Ordering::SeqCst);

        if let Some(mut proc) = self.active_process.take() {
            println!("🛑 Stopping engine process...");
            let _ = proc.kill();
        }

        let _ = self.proxy_mgr.restore_all_system_settings();

        #[cfg(target_os = "windows")]
        {
            let _ = silent_command("taskkill.exe")
                .args(["/F", "/IM", "winws.exe"])
                .status();
        }

        self.state = EngineState::Stopped;
        Ok(())
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
        let strategies = self.list_strategies();
        let total = strategies.len();
        let mut best: Option<(Strategy, ProbeSummary)> = None;

        for (idx, strat) in strategies.iter().enumerate() {
            progress_cb(idx + 1, total, strat, None);

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

        Ok(best.map(|(s, _)| s))
    }
}
