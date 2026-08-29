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
    strategies::StrategyManager,
    types::{EngineConfig, EngineState, Platform, ProbeResult, ProbeRule, ProbeSummary, ProbeTier, Strategy},
    wireguard::{WireGuardManager, WireGuardState, WireGuardTunnelInfo},
    silent_command,
    UnblockEngine,
};
