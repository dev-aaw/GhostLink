pub mod engine;

pub use engine::{
    autostart::AutoStartManager,
    binary_manager::BinaryManager,
    ipc::{DaemonClient, DaemonStatusInfo, IpcRequest, IpcResponse},
    notifications::notify,
    payloads,
    probes::ProbeRunner,
    service::ServiceManager,
    smart_router::{SmartRouteEntry, SmartRouter},
    strategies::{StrategyManager, StrategyConfigManager},
    types::{EngineConfig, EngineState, Platform, ProbeResult, ProbeRule, ProbeSummary, ProbeTier, Strategy},
    wireguard::{WireGuardManager, WireGuardState, WireGuardTunnelInfo},
    system_proxy::SystemProxyManager,
    logging::{self, init_logger, log_msg, get_recent_log_entries},
    silent_command,
    UnblockEngine,
};
