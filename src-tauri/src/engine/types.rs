use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    MacOS,
    Windows,
    Linux,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Platform::MacOS
        } else if cfg!(target_os = "windows") {
            Platform::Windows
        } else {
            Platform::Linux
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Strategy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub platform: Platform,
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeTier {
    Screen,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeRule {
    pub id: String,
    pub label: String,
    pub url: String,
    pub tier: ProbeTier,
    pub expected_statuses: Vec<u16>,
    pub required_body_pattern: Option<String>,
    pub reject_body_pattern: Option<String>,
    pub expected_hex_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub rule_id: String,
    pub label: String,
    pub url: String,
    pub success: bool,
    pub status_code: Option<u16>,
    pub latency_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeSummary {
    pub strategy_id: String,
    pub success: bool,
    pub total_latency_ms: u64,
    pub results: Vec<ProbeResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EngineState {
    Stopped,
    Starting,
    Running { strategy_name: String, port: u16 },
    AutoTuning { current: usize, total: usize, candidate: String },
    Error(String),
}

impl fmt::Display for EngineState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EngineState::Stopped => write!(f, "Stopped"),
            EngineState::Starting => write!(f, "Starting..."),
            EngineState::Running { strategy_name, port } => {
                write!(f, "Running (Strategy: {}, Port: {})", strategy_name, port)
            }
            EngineState::AutoTuning { current, total, candidate } => {
                write!(f, "AutoTuning [{}/{}] testing {}", current, total, candidate)
            }
            EngineState::Error(err) => write!(f, "Error: {}", err),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub base_dir: PathBuf,
    pub socks_port: u16,
    pub apply_system_proxy: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        #[cfg(target_os = "windows")]
        {
            let base_dir = std::env::var("ProgramData")
                .map(|p| PathBuf::from(p).join("GhostLink"))
                .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData\GhostLink"));
            Self {
                base_dir,
                socks_port: 10808,
                apply_system_proxy: true,
            }
        }
        #[cfg(not(target_os = "windows"))]
        {
            let home = std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .unwrap_or_else(|_| ".".to_string());
            let base_dir = PathBuf::from(home).join(".ghostlink");
            Self {
                base_dir,
                socks_port: 10808,
                apply_system_proxy: true,
            }
        }
    }
}
