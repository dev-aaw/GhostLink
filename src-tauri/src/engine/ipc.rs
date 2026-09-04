use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::engine::types::{ProbeSummary, Strategy};

pub const DEFAULT_SOCKET_PATH: &str = "/var/run/ghostlink.sock";
pub const FALLBACK_SOCKET_PATH: &str = "/tmp/ghostlink.sock";

/// Windows IPC transport. A named pipe whose DACL (built in the daemon) grants
/// access only to SYSTEM, the local Administrators group, and interactively
/// logged-on users — so an arbitrary local/sandboxed process can no longer reach
/// the privileged daemon the way it could with the old `127.0.0.1:49281` TCP
/// loopback socket. The pipe ACL is the authentication boundary; no shared bearer
/// token file is written any more.
pub const WINDOWS_PIPE_NAME: &str = r"\\.\pipe\ghostlink-daemon";

/// True if `path` is a real socket owned by root or by the current effective
/// user.
///
/// Security: `/tmp` is world-writable + sticky on macOS. When the daemon runs as
/// root it binds `/var/run/ghostlink.sock` and leaves `/tmp/ghostlink.sock` free,
/// so any local user can plant a rogue listener there. The daemon's own
/// `getpeereid` check protects the *daemon*, but nothing stopped the CLI / menu
/// bar from connecting to that rogue socket, trusting its `Pong`/`Status`
/// (spoofed "protected" state) and sending it `Start`/`Stop`/`AutoTune`. Verify
/// ownership before trusting a candidate path; `/var/run` is root-only so a
/// socket there is inherently fine, but we check uniformly.
#[cfg(target_os = "macos")]
fn is_trusted_socket(path: &Path) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return false;
            }
            let owner = meta.uid();
            owner == 0 || owner == unsafe { libc::geteuid() }
        }
        Err(_) => false,
    }
}

#[cfg(not(target_os = "macos"))]
fn is_trusted_socket(_path: &Path) -> bool {
    true
}

/// Returns the primary active socket path or fallback.
///
/// A candidate path is only used when `is_trusted_socket` accepts it; an
/// untrusted file at a candidate path is ignored (the caller then falls back to
/// standalone mode instead of talking to a possibly hostile listener).
pub fn get_socket_path() -> PathBuf {
    let var_run = Path::new(DEFAULT_SOCKET_PATH);
    if var_run.exists() {
        if is_trusted_socket(var_run) {
            return var_run.to_path_buf();
        }
        eprintln!("⚠️ SECURITY: Ignoring untrusted daemon socket at {DEFAULT_SOCKET_PATH} (unexpected owner or type)");
    }
    let tmp = Path::new(FALLBACK_SOCKET_PATH);
    if tmp.exists() {
        if is_trusted_socket(tmp) {
            return tmp.to_path_buf();
        }
        eprintln!("⚠️ SECURITY: Ignoring untrusted daemon socket at {FALLBACK_SOCKET_PATH} (not a socket owned by root or the current user)");
    }
    var_run.to_path_buf()
}

/// Returns the path to the daemon authentication secret token (Unix only).
/// On Windows the named-pipe DACL is the authentication boundary and no token
/// file is used.
#[cfg(not(target_os = "windows"))]
pub fn get_token_path() -> PathBuf {
    PathBuf::from("/var/run/ghostlink.token")
}

/// Wrapper envelope to authenticate IPC requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcEnvelope {
    pub token: Option<String>,
    pub request: IpcRequest,
}

/// Commands that client (CLI / GUI) sends to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum IpcRequest {
    Ping,
    GetStatus,
    Start {
        strategy_id: String,
        socks_port: Option<u16>,
        apply_system_proxy: bool,
    },
    Stop,
    ProbeDirect,
    TestStrategy {
        strategy_id: String,
    },
    AutoTune,
    ConfigureDns {
        servers: Vec<String>,
    },
    ResetDns,
    WireGuardList,
    WireGuardStatus {
        tunnel: String,
    },
    WireGuardConnect {
        tunnel: String,
    },
    WireGuardDisconnect {
        tunnel: String,
    },
    WireGuardToggle {
        tunnel: String,
    },
    AddRoute {
        ip: String,
        router: String,
        iface: String,
    },
    DeleteRoute {
        ip: String,
        router: String,
        iface: String,
    },
    GetRecentLogs {
        max_lines: Option<usize>,
    },
    ShutdownDaemon,
}

/// Responses returned by daemon to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum IpcResponse {
    Ok {
        message: String,
    },
    Pong {
        version: String,
        is_root: bool,
        pid: u32,
    },
    Status(DaemonStatusInfo),
    ProbeResult(ProbeSummary),
    AutoTuneResult {
        best_strategy: Option<Strategy>,
        latency_ms: Option<u64>,
    },
    WireGuardList(Vec<crate::engine::wireguard::WireGuardTunnelInfo>),
    WireGuardStatus {
        tunnel: String,
        state: crate::engine::wireguard::WireGuardState,
    },
    RecentLogs(Vec<String>),
    Error {
        error: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatusInfo {
    pub is_running: bool,
    pub active_strategy_id: Option<String>,
    pub active_strategy_name: Option<String>,
    pub socks_port: Option<u16>,
    pub engine_pid: Option<u32>,
    pub daemon_pid: u32,
    pub is_root: bool,
    pub uptime_secs: u64,
    /// Human-readable engine state ("Stopped", "Running (...)", "Faulted (reboot required): ...").
    /// Older clients that don't send/expect this still deserialize via the default.
    #[serde(default)]
    pub engine_state: String,
    /// Set when the engine has entered the unrecoverable Faulted state and a reboot is needed.
    #[serde(default)]
    pub faulted_reason: Option<String>,
}

/// IPC client to interact with running ghostlink_daemon.
pub struct DaemonClient {
    #[allow(dead_code)]
    socket_path: PathBuf,
    token: Option<String>,
}

impl Default for DaemonClient {
    fn default() -> Self {
        Self::new(get_socket_path())
    }
}

impl DaemonClient {
    pub fn new(socket_path: PathBuf) -> Self {
        #[cfg(not(target_os = "windows"))]
        let token = std::fs::read_to_string(get_token_path())
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        #[cfg(target_os = "windows")]
        let token: Option<String> = None; // pipe DACL is the auth boundary on Windows
        Self { socket_path, token }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub async fn is_daemon_alive(&self) -> bool {
        match self.ping().await {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    pub async fn send_request(&self, request: &IpcRequest) -> Result<IpcResponse> {
        // Wrap entire IPC communication in a 10-second timeout to prevent
        // indefinite hangs if daemon is unresponsive or deadlocked
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            self.send_request_inner(request),
        ).await {
            Ok(result) => result,
            Err(_) => Err(anyhow!("IPC request timed out after 10 seconds (daemon may be unresponsive)")),
        }
    }

    async fn send_request_inner(&self, request: &IpcRequest) -> Result<IpcResponse> {
        #[cfg(unix)]
        let (reader, mut writer) = {
            let stream = tokio::net::UnixStream::connect(&self.socket_path)
                .await
                .with_context(|| format!("Failed to connect to daemon socket at {:?}", self.socket_path))?;
            stream.into_split()
        };

        #[cfg(windows)]
        let (reader, mut writer) = {
            use tokio::net::windows::named_pipe::ClientOptions;
            // ERROR_PIPE_BUSY (231): all pipe instances are momentarily in use; back off briefly.
            const ERROR_PIPE_BUSY: i32 = 231;
            let mut attempt = 0u32;
            let client = loop {
                match ClientOptions::new().open(WINDOWS_PIPE_NAME) {
                    Ok(c) => break c,
                    Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempt < 25 => {
                        attempt += 1;
                        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                    }
                    Err(e) => {
                        return Err(anyhow!("Failed to connect to GhostLink daemon pipe {}: {}", WINDOWS_PIPE_NAME, e));
                    }
                }
            };
            tokio::io::split(client)
        };

        let mut reader = BufReader::new(reader);

        // On Unix the daemon still verifies a shared token; on Windows `token` is
        // always None and the pipe DACL is the boundary.
        #[cfg(not(target_os = "windows"))]
        let token_val = self.token.clone().or_else(|| {
            std::fs::read_to_string(get_token_path())
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        });
        #[cfg(target_os = "windows")]
        let token_val = self.token.clone();

        let envelope = IpcEnvelope {
            token: token_val,
            request: request.clone(),
        };

        let mut req_str = serde_json::to_string(&envelope)?;
        req_str.push('\n');

        writer.write_all(req_str.as_bytes()).await?;
        writer.flush().await?;

        let mut response_line = String::new();
        let bytes_read = reader.read_line(&mut response_line).await?;

        if bytes_read == 0 {
            return Err(anyhow!("Daemon closed connection unexpectedly without response"));
        }

        let resp: IpcResponse = serde_json::from_str(&response_line)
            .with_context(|| format!("Invalid response JSON from daemon: {}", response_line.trim()))?;

        match resp {
            IpcResponse::Error { error } => Err(anyhow!("Daemon error: {}", error)),
            other => Ok(other),
        }
    }

    pub async fn ping(&self) -> Result<(String, bool, u32)> {
        match self.send_request(&IpcRequest::Ping).await? {
            IpcResponse::Pong { version, is_root, pid } => Ok((version, is_root, pid)),
            other => Err(anyhow!("Unexpected response to Ping: {:?}", other)),
        }
    }

    pub async fn get_status(&self) -> Result<DaemonStatusInfo> {
        match self.send_request(&IpcRequest::GetStatus).await? {
            IpcResponse::Status(info) => Ok(info),
            other => Err(anyhow!("Unexpected response to GetStatus: {:?}", other)),
        }
    }

    pub async fn start(
        &self,
        strategy_id: &str,
        socks_port: Option<u16>,
        apply_system_proxy: bool,
    ) -> Result<String> {
        let req = IpcRequest::Start {
            strategy_id: strategy_id.to_string(),
            socks_port,
            apply_system_proxy,
        };
        match self.send_request(&req).await? {
            IpcResponse::Ok { message } => Ok(message),
            other => Err(anyhow!("Unexpected response to Start: {:?}", other)),
        }
    }

    pub async fn stop(&self) -> Result<String> {
        match self.send_request(&IpcRequest::Stop).await? {
            IpcResponse::Ok { message } => Ok(message),
            other => Err(anyhow!("Unexpected response to Stop: {:?}", other)),
        }
    }

    pub async fn probe_direct(&self) -> Result<ProbeSummary> {
        match self.send_request(&IpcRequest::ProbeDirect).await? {
            IpcResponse::ProbeResult(summary) => Ok(summary),
            other => Err(anyhow!("Unexpected response to ProbeDirect: {:?}", other)),
        }
    }

    pub async fn test_strategy(&self, strategy_id: &str) -> Result<ProbeSummary> {
        let req = IpcRequest::TestStrategy {
            strategy_id: strategy_id.to_string(),
        };
        match self.send_request(&req).await? {
            IpcResponse::ProbeResult(summary) => Ok(summary),
            other => Err(anyhow!("Unexpected response to TestStrategy: {:?}", other)),
        }
    }

    pub async fn auto_tune(&self) -> Result<(Option<Strategy>, Option<u64>)> {
        match self.send_request(&IpcRequest::AutoTune).await? {
            IpcResponse::AutoTuneResult { best_strategy, latency_ms } => Ok((best_strategy, latency_ms)),
            other => Err(anyhow!("Unexpected response to AutoTune: {:?}", other)),
        }
    }

    pub async fn configure_dns(&self, servers: Vec<String>) -> Result<String> {
        match self.send_request(&IpcRequest::ConfigureDns { servers }).await? {
            IpcResponse::Ok { message } => Ok(message),
            other => Err(anyhow!("Unexpected response to ConfigureDns: {:?}", other)),
        }
    }

    pub async fn reset_dns(&self) -> Result<String> {
        match self.send_request(&IpcRequest::ResetDns).await? {
            IpcResponse::Ok { message } => Ok(message),
            other => Err(anyhow!("Unexpected response to ResetDns: {:?}", other)),
        }
    }

    pub async fn shutdown_daemon(&self) -> Result<String> {
        match self.send_request(&IpcRequest::ShutdownDaemon).await? {
            IpcResponse::Ok { message } => Ok(message),
            other => Err(anyhow!("Unexpected response to ShutdownDaemon: {:?}", other)),
        }
    }

    pub async fn wireguard_list(&self) -> Result<Vec<crate::engine::wireguard::WireGuardTunnelInfo>> {
        match self.send_request(&IpcRequest::WireGuardList).await? {
            IpcResponse::WireGuardList(tunnels) => Ok(tunnels),
            other => Err(anyhow!("Unexpected response to WireGuardList: {:?}", other)),
        }
    }

    pub async fn wireguard_status(&self, tunnel: &str) -> Result<crate::engine::wireguard::WireGuardState> {
        let req = IpcRequest::WireGuardStatus { tunnel: tunnel.to_string() };
        match self.send_request(&req).await? {
            IpcResponse::WireGuardStatus { state, .. } => Ok(state),
            other => Err(anyhow!("Unexpected response to WireGuardStatus: {:?}", other)),
        }
    }

    pub async fn wireguard_connect(&self, tunnel: &str) -> Result<String> {
        let req = IpcRequest::WireGuardConnect { tunnel: tunnel.to_string() };
        match self.send_request(&req).await? {
            IpcResponse::Ok { message } => Ok(message),
            other => Err(anyhow!("Unexpected response to WireGuardConnect: {:?}", other)),
        }
    }

    pub async fn wireguard_disconnect(&self, tunnel: &str) -> Result<String> {
        let req = IpcRequest::WireGuardDisconnect { tunnel: tunnel.to_string() };
        match self.send_request(&req).await? {
            IpcResponse::Ok { message } => Ok(message),
            other => Err(anyhow!("Unexpected response to WireGuardDisconnect: {:?}", other)),
        }
    }

    pub async fn wireguard_toggle(&self, tunnel: &str) -> Result<crate::engine::wireguard::WireGuardState> {
        let req = IpcRequest::WireGuardToggle { tunnel: tunnel.to_string() };
        match self.send_request(&req).await? {
            IpcResponse::WireGuardStatus { state, .. } => Ok(state),
            other => Err(anyhow!("Unexpected response to WireGuardToggle: {:?}", other)),
        }
    }

    pub async fn add_route(&self, ip: &str, router: &str, iface: &str) -> Result<String> {
        let req = IpcRequest::AddRoute {
            ip: ip.to_string(),
            router: router.to_string(),
            iface: iface.to_string(),
        };
        match self.send_request(&req).await? {
            IpcResponse::Ok { message } => Ok(message),
            other => Err(anyhow!("Unexpected response to AddRoute: {:?}", other)),
        }
    }

    pub async fn delete_route(&self, ip: &str, router: &str, iface: &str) -> Result<String> {
        let req = IpcRequest::DeleteRoute {
            ip: ip.to_string(),
            router: router.to_string(),
            iface: iface.to_string(),
        };
        match self.send_request(&req).await? {
            IpcResponse::Ok { message } => Ok(message),
            other => Err(anyhow!("Unexpected response to DeleteRoute: {:?}", other)),
        }
    }

    pub async fn get_recent_logs(&self, max_lines: Option<usize>) -> Result<Vec<String>> {
        let req = IpcRequest::GetRecentLogs { max_lines };
        match self.send_request(&req).await? {
            IpcResponse::RecentLogs(lines) => Ok(lines),
            other => Err(anyhow!("Unexpected response to GetRecentLogs: {:?}", other)),
        }
    }
}
