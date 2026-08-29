pub mod autostart;
pub mod binary_manager;
pub mod ipc;
pub mod notifications;
pub mod payloads;
pub mod process;
pub mod probes;
pub mod service;
pub mod smart_router;
pub mod strategies;
pub mod system_proxy;
pub mod types;
pub mod wireguard;

use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::time::sleep;

pub use autostart::AutoStartManager;
pub use ipc::{DaemonClient, DaemonStatusInfo, IpcRequest, IpcResponse};
pub use notifications::notify;
pub use service::ServiceManager;
pub use smart_router::{SmartRouteEntry, SmartRouter};
pub use types::{EngineConfig, EngineState, Platform, ProbeResult, ProbeSummary, Strategy};
pub use wireguard::{WireGuardManager, WireGuardState, WireGuardTunnelInfo};
use binary_manager::BinaryManager;
use process::ProcessHandle;
use probes::ProbeRunner;
use strategies::StrategyManager;
use system_proxy::SystemProxyManager;

pub struct UnblockEngine {
    config: EngineConfig,
    binary_mgr: BinaryManager,
    strategy_mgr: StrategyManager,
    proxy_mgr: SystemProxyManager,
    probe_runner: ProbeRunner,
    active_process: Option<ProcessHandle>,
    state: EngineState,
    watchdog_running: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl UnblockEngine {
    pub fn new(config: EngineConfig) -> Self {
        let binary_mgr = BinaryManager::new(&config.base_dir);
        let strategy_mgr = StrategyManager::new(&config.base_dir);
        let proxy_mgr = SystemProxyManager::new(config.socks_port);
        let probe_runner = ProbeRunner::new();

        Self {
            config,
            binary_mgr,
            strategy_mgr,
            proxy_mgr,
            probe_runner,
            active_process: None,
            state: EngineState::Stopped,
            watchdog_running: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    pub fn state(&self) -> &EngineState {
        &self.state
    }

    pub fn is_running(&self) -> bool {
        matches!(self.state, EngineState::Running { .. })
    }

    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    /// Prepare environment: downloads/verifies binary, generates payloads and domain lists.
    pub async fn prepare(&self) -> Result<()> {
        // 1. Ensure domain lists
        self.strategy_mgr.ensure_lists()?;

        // 2. Ensure payload .bin files in binary directory
        payloads::ensure_payload_files(self.binary_mgr.bin_dir())?;

        // 3. Ensure executables exist and have proper permissions
        self.binary_mgr.ensure_binaries().await?;

        Ok(())
    }

    /// Returns all available strategies for current operating system.
    pub fn list_strategies(&self) -> Vec<Strategy> {
        let platform = Platform::current();
        self.strategy_mgr.get_strategies_for_platform(platform, self.binary_mgr.bin_dir(), self.config.socks_port)
    }

    /// Starts the engine with the chosen strategy.
    pub async fn start(&mut self, strategy: &Strategy) -> Result<()> {
        self.stop().await?;
        self.prepare().await?;

        let exe_path = self.binary_mgr.get_executable_path();
        if !exe_path.exists() {
            return Err(anyhow!("Binary executable not found: {:?}", exe_path));
        }

        // Note: Previous process cleanup is handled by self.stop() above (line 96),
        // which uses ProcessHandle::kill() to terminate the specific child process.
        // We intentionally do NOT use pkill -f here as it would kill unrelated processes.

        println!("🚀 Launching engine with strategy: [{}]", strategy.name);
        let proc = ProcessHandle::spawn(&exe_path, &strategy.args)?;
        self.active_process = Some(proc);

        // Give the process a brief moment to initialize its socket/driver
        sleep(Duration::from_millis(600)).await;

        // 1. Strict Pre-Proxy Port Verification: Verify that the process is actually listening on 127.0.0.1:port
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
        if cfg!(target_os = "macos") && self.config.apply_system_proxy {
            if let Err(e) = self.proxy_mgr.enable_macos_proxy() {
                let _ = self.stop().await;
                return Err(e);
            }
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
                        #[cfg(target_os = "macos")]
                        {
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
                        }
                        eprintln!("✨ System network settings restored to normal.\n");
                        break;
                    }
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

        if cfg!(target_os = "macos") {
            let _ = self.proxy_mgr.disable_macos_proxy();
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

        // On macOS, we probe through the local SOCKS proxy
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

    /// Auto-tune: Iterates through all available strategies to find the best working one.
    pub async fn auto_tune<F>(&mut self, mut progress_callback: F) -> Result<Option<Strategy>>
    where
        F: FnMut(usize, usize, &Strategy, Option<&ProbeSummary>),
    {
        let strategies = self.list_strategies();
        let total = strategies.len();

        for (index, strategy) in strategies.iter().enumerate() {
            progress_callback(index + 1, total, strategy, None);

            match self.test_strategy(strategy).await {
                Ok(summary) => {
                    progress_callback(index + 1, total, strategy, Some(&summary));
                    if summary.success {
                        println!("🎉 Working strategy found: [{}] (Total probe latency: {}ms)", strategy.name, summary.total_latency_ms);
                        return Ok(Some(strategy.clone()));
                    }
                }
                Err(err) => {
                    println!("⚠️ Strategy [{}] failed with error: {}", strategy.name, err);
                }
            }
        }

        Ok(None)
    }
}
