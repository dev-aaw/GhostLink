pub mod binary_manager;
pub mod payloads;
pub mod process;
pub mod probes;
pub mod strategies;
pub mod system_proxy;
pub mod types;

use anyhow::{anyhow, Result};
use std::time::Duration;
use tokio::time::sleep;

pub use types::{EngineConfig, EngineState, Platform, ProbeResult, ProbeSummary, Strategy};
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
        }
    }

    pub fn state(&self) -> &EngineState {
        &self.state
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

        println!("🚀 Launching engine with strategy: [{}]", strategy.name);
        let proc = ProcessHandle::spawn(&exe_path, &strategy.args)?;
        self.active_process = Some(proc);

        // Give the process a brief moment to initialize its socket/driver
        sleep(Duration::from_millis(600)).await;

        if let Some(ref mut p) = self.active_process {
            if !p.is_alive() {
                self.active_process = None;
                self.state = EngineState::Error("Engine process exited unexpectedly upon startup".to_string());
                return Err(anyhow!("Engine process failed to stay alive"));
            }
        }

        // On macOS, configure system SOCKS proxy if enabled
        if cfg!(target_os = "macos") && self.config.apply_system_proxy {
            let _ = self.proxy_mgr.enable_macos_proxy();
        }

        self.state = EngineState::Running {
            strategy_name: strategy.name.clone(),
            port: self.config.socks_port,
        };

        Ok(())
    }

    /// Stops the running engine and restores system settings.
    pub async fn stop(&mut self) -> Result<()> {
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
