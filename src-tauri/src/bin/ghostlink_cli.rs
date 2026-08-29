use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use ghostlink_engine::{
    DaemonClient, EngineConfig, ProbeRunner, ServiceManager, Strategy, UnblockEngine,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::signal;

#[derive(Parser)]
#[command(name = "ghostlink_cli")]
#[command(
    about = "GhostLink Core Engine CLI - High-performance DPI bypass & censorship resilience",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List all available strategies for current operating system
    List,
    /// Download and prepare required binaries, fake payloads and domain lists
    Prepare,
    /// Test current internet connection without engine to check blocked services
    ProbeDirect,
    /// Test a specific strategy against probe endpoints
    Test {
        /// Strategy index (1-based) or Strategy ID (e.g. mac-split-midsld or 1)
        #[arg(short, long, default_value = "1")]
        strategy: String,
    },
    /// Automatically test all strategies and find the best working one for your ISP
    Autotune,
    /// Start the bypass engine with a strategy (delegates to LaunchDaemon if active)
    Start {
        /// Strategy index or ID to run (default: 1)
        #[arg(short, long, default_value = "1")]
        strategy: String,
        /// Do not apply system-wide proxy automatically (macOS only)
        #[arg(long, default_value_t = false)]
        no_proxy: bool,
    },
    /// Stop the running bypass engine
    Stop,
    /// Display current status of GhostLink engine and privileged daemon
    Status,
    /// Manage & Synchronize with WireGuard tunnels (e.g. wg0-daily)
    Wg {
        #[command(subcommand)]
        action: WgCommands,
    },
    /// Manage & Simulate Smart Fallback domain routes via WireGuard
    Route {
        #[command(subcommand)]
        action: RouteCommands,
    },
    /// Manage GhostLink macOS Privileged Helper Service (LaunchDaemon)
    Service {
        #[command(subcommand)]
        action: ServiceCommands,
    },
}

#[derive(Subcommand)]
enum RouteCommands {
    /// Add/Simulate a domain fallback route to WireGuard wg0-daily
    Add {
        /// Domain name (e.g. test-fallback-example.com or blocked-site.com)
        domain: String,
        /// Optional custom IP override (default: auto-resolve or mock test IP)
        #[arg(short, long)]
        ip: Option<String>,
    },
    /// List all learned Smart Fallback routes
    List,
    /// Remove a learned domain route
    Remove {
        domain: String,
    },
    /// Clear all learned Smart Fallback routes
    Clear,
}

#[derive(Subcommand)]
enum WgCommands {
    /// List all registered WireGuard NetworkExtension tunnels
    List,
    /// Get connection status of a WireGuard tunnel (default: wg0-daily)
    Status {
        #[arg(default_value = "wg0-daily")]
        tunnel: String,
    },
    /// Connect a WireGuard tunnel
    Connect {
        #[arg(default_value = "wg0-daily")]
        tunnel: String,
    },
    /// Disconnect a WireGuard tunnel
    Disconnect {
        #[arg(default_value = "wg0-daily")]
        tunnel: String,
    },
    /// Toggle WireGuard tunnel connection (connect if disconnected, disconnect if connected)
    Toggle {
        #[arg(default_value = "wg0-daily")]
        tunnel: String,
    },
}

#[derive(Subcommand)]
enum ServiceCommands {
    /// Install GhostLink LaunchDaemon for passwordless privileged execution
    Install,
    /// Uninstall GhostLink LaunchDaemon
    Uninstall,
    /// Check privileged LaunchDaemon status and socket connection
    Status,
    /// Start engine inside privileged daemon
    Start {
        #[arg(short, long, default_value = "1")]
        strategy: String,
    },
    /// Stop engine inside privileged daemon
    Stop,
    /// Configure system DNS servers via privileged helper
    Dns {
        /// Space-separated DNS IPs (e.g. 1.1.1.1 8.8.8.8)
        #[arg(required = true, num_args = 1..)]
        servers: Vec<String>,
    },
    /// Reset system DNS to DHCP default via privileged helper
    ResetDns,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = EngineConfig::default();
    let client = DaemonClient::default();

    println!("{}", "=========================================================".cyan());
    println!("{}", " 👻 GHOSTLINK - DPI Bypass Core Engine (Tauri v2 Base)".bold().cyan());
    println!("{}", "=========================================================".cyan());

    match cli.command {
        Commands::List => {
            let engine = UnblockEngine::new(config);
            let strategies = engine.list_strategies();
            println!("\n📋 Available Strategies for {:?}:\n", ghostlink_engine::Platform::current());
            for (idx, s) in strategies.iter().enumerate() {
                println!("  {}. {} ({})", (idx + 1).to_string().bold().green(), s.name.bold(), s.id.yellow());
                println!("     └─ {}", s.description.dimmed());
            }
            println!();
        }

        Commands::Prepare => {
            let engine = UnblockEngine::new(config);
            println!("\n📦 Preparing binaries, payloads and hostlists...");
            engine.prepare().await?;
            println!("{}", "\n✨ All binaries and payload files prepared successfully!".green().bold());
        }

        Commands::ProbeDirect => {
            println!("\n🔍 Probing endpoints directly (baseline test without DPI bypass)...");
            let runner = ProbeRunner::new();
            let summary = runner.run_suite("direct", None).await;

            print_probe_summary(&summary);
        }

        Commands::Test { strategy } => {
            let mut engine = UnblockEngine::new(config);
            let target_strat = resolve_strategy(&engine, &strategy)?;

            println!("\n🧪 Testing strategy: {} [{}]", target_strat.name.bold().green(), target_strat.id.yellow());
            let summary = engine.test_strategy(&target_strat).await?;

            print_probe_summary(&summary);
        }

        Commands::Autotune => {
            let mut engine = UnblockEngine::new(config);
            println!("\n🔄 Starting GhostLink Auto-tune Strategy Benchmark...\n");

            let best_strategy = engine.auto_tune(|curr, total, strat, maybe_summary| {
                match maybe_summary {
                    None => {
                        println!("👉 [{}/{}] Probing strategy: {}...", curr, total, strat.name.yellow());
                    }
                    Some(summary) => {
                        if summary.success {
                            println!("   {} Passed! Latency: {}ms", "✔".green().bold(), summary.total_latency_ms);
                        } else {
                            println!("   {} Failed (blocked or timeout)", "✖".red());
                        }
                    }
                }
            }).await?;

            println!("\n---------------------------------------------------------");
            match best_strategy {
                Some(strat) => {
                    println!("🏆 {} Recommended Working Strategy: {}", "SUCCESS:".bold().green(), strat.name.bold().green());
                    println!("💡 You can start it using: cargo run --bin ghostlink_cli -- start -s {}", strat.id);
                }
                None => {
                    println!("❌ {} No working strategy found among all candidates for current ISP.", "FAILED:".bold().red());
                }
            }
            println!("---------------------------------------------------------\n");
        }

        Commands::Status => {
            println!("\n📊 Checking GhostLink Engine & Daemon Status...\n");
            if client.is_daemon_alive().await {
                match client.get_status().await {
                    Ok(info) => {
                        println!("  • Privileged Daemon: {}", "RUNNING (Connected)".green().bold());
                        println!("  • Daemon PID: {}", info.daemon_pid);
                        println!("  • Running as Root: {}", if info.is_root { "YES (Privileged)".green() } else { "NO".yellow() });
                        println!("  • Uptime: {} seconds", info.uptime_secs);
                        println!("  • Engine State: {}", if info.is_running { "ACTIVE (Bypassing DPI)".green().bold() } else { "STOPPED (Idle)".yellow() });
                        if let Some(ref s_name) = info.active_strategy_name {
                            println!("  • Active Strategy: {}", s_name.cyan().bold());
                        }
                        if let Some(port) = info.socks_port {
                            println!("  • SOCKS Port: {}", port.to_string().yellow());
                        }
                    }
                    Err(e) => {
                        println!("  • Privileged Daemon: {} ({})", "ERROR".red().bold(), e);
                    }
                }
            } else {
                println!("  • Privileged Daemon: {}", "NOT RUNNING (Standalone CLI Mode)".yellow());
                println!("  💡 You can install it once via: ghostlink_cli service install");
            }
            println!();
        }

        Commands::Start { strategy, no_proxy } => {
            let engine = UnblockEngine::new(config);
            let target_strat = resolve_strategy(&engine, &strategy)?;

            // If daemon is running, seamlessly delegate to daemon
            if client.is_daemon_alive().await {
                println!("\n🚀 Privileged Daemon detected. Delegating startup to service...");
                match client.start(&target_strat.id, None, !no_proxy).await {
                    Ok(msg) => {
                        println!("\n{}", "🎉 GhostLink Engine is active via Privileged Daemon!".bold().green());
                        println!("   • Message: {}", msg.green());
                        println!("   • Strategy: {}", target_strat.name.cyan());
                        println!("   • Check status anytime: cargo run --bin ghostlink_cli -- status\n");
                    }
                    Err(e) => {
                        eprintln!("\n❌ Failed to start via daemon: {}", e);
                    }
                }
                return Ok(());
            }

            // Standalone mode if daemon not running
            let mut cfg = engine.config().clone();
            if no_proxy {
                cfg.apply_system_proxy = false;
            }
            let mut standalone_engine = UnblockEngine::new(cfg);

            standalone_engine.start(&target_strat).await?;
            println!("\n{}", "🎉 GhostLink Engine is active and running (Standalone)!".bold().green());
            println!("   • Strategy: {}", target_strat.name.cyan());
            println!("   • SOCKS Port: {}", standalone_engine.config().socks_port.to_string().yellow());
            println!("   • Press Ctrl+C to stop and restore system network settings...\n");

            let running = Arc::new(AtomicBool::new(true));
            let r = running.clone();

            tokio::spawn(async move {
                signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
                r.store(false, Ordering::SeqCst);
            });

            while running.load(Ordering::SeqCst) {
                tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
            }

            println!("\n🛑 Stopping engine gracefully...");
            standalone_engine.stop().await?;
            println!("{}", "✨ GhostLink stopped and network settings restored.".green());
        }

        Commands::Stop => {
            if client.is_daemon_alive().await {
                println!("\n🛑 Sending STOP command to Privileged Daemon...");
                match client.stop().await {
                    Ok(msg) => {
                        println!("✨ {}", msg.green());
                    }
                    Err(e) => {
                        eprintln!("❌ Failed to stop daemon engine: {}", e);
                    }
                }
            } else {
                let mut engine = UnblockEngine::new(config);
                engine.stop().await?;
                println!("{}", "\n✨ GhostLink stopped and system network settings verified.".green());
            }
        }

        Commands::Wg { action } => {
            match action {
                WgCommands::List => {
                    println!("\n📋 Registered WireGuard Tunnels (macOS NetworkExtension):\n");
                    let tunnels = if client.is_daemon_alive().await {
                        client.wireguard_list().await?
                    } else {
                        ghostlink_engine::WireGuardManager::list_tunnels()
                    };

                    if tunnels.is_empty() {
                        println!("  ⚠️ No WireGuard tunnels found.");
                    } else {
                        for (idx, t) in tunnels.iter().enumerate() {
                            let state_colored = match t.state {
                                ghostlink_engine::WireGuardState::Connected => "CONNECTED".green().bold(),
                                ghostlink_engine::WireGuardState::Connecting => "CONNECTING...".yellow(),
                                ghostlink_engine::WireGuardState::Disconnecting => "DISCONNECTING...".yellow(),
                                ghostlink_engine::WireGuardState::Disconnected => "DISCONNECTED".dimmed(),
                                ghostlink_engine::WireGuardState::Unknown(ref s) => s.normal(),
                            };
                            println!("  {}. {} -> [{}]", idx + 1, t.name.cyan().bold(), state_colored);
                        }
                    }
                    println!();
                }

                WgCommands::Status { tunnel } => {
                    let state = if client.is_daemon_alive().await {
                        client.wireguard_status(&tunnel).await?
                    } else {
                        ghostlink_engine::WireGuardManager::status(&tunnel)
                    };

                    let state_colored = match state {
                        ghostlink_engine::WireGuardState::Connected => "CONNECTED".green().bold(),
                        ghostlink_engine::WireGuardState::Connecting => "CONNECTING...".yellow(),
                        ghostlink_engine::WireGuardState::Disconnecting => "DISCONNECTING...".yellow(),
                        ghostlink_engine::WireGuardState::Disconnected => "DISCONNECTED".red().bold(),
                        ghostlink_engine::WireGuardState::Unknown(ref s) => s.normal(),
                    };
                    println!("\n🛡️ WireGuard Tunnel [{}]: {}\n", tunnel.cyan().bold(), state_colored);
                }

                WgCommands::Connect { tunnel } => {
                    println!("\n🚀 Connecting WireGuard Tunnel [{}]...", tunnel.cyan().bold());
                    let msg = if client.is_daemon_alive().await {
                        client.wireguard_connect(&tunnel).await?
                    } else {
                        ghostlink_engine::WireGuardManager::connect(&tunnel)?;
                        format!("WireGuard tunnel '{}' connected", tunnel)
                    };
                    println!("✨ {}\n", msg.green());
                }

                WgCommands::Disconnect { tunnel } => {
                    println!("\n🛑 Disconnecting WireGuard Tunnel [{}]...", tunnel.cyan().bold());
                    let msg = if client.is_daemon_alive().await {
                        client.wireguard_disconnect(&tunnel).await?
                    } else {
                        ghostlink_engine::WireGuardManager::disconnect(&tunnel)?;
                        format!("WireGuard tunnel '{}' disconnected", tunnel)
                    };
                    println!("✨ {}\n", msg.green());
                }

                WgCommands::Toggle { tunnel } => {
                    println!("\n🔄 Toggling WireGuard Tunnel [{}]...", tunnel.cyan().bold());
                    let new_state = if client.is_daemon_alive().await {
                        client.wireguard_toggle(&tunnel).await?
                    } else {
                        ghostlink_engine::WireGuardManager::toggle(&tunnel)?
                    };
                    let state_colored = match new_state {
                        ghostlink_engine::WireGuardState::Connected => "CONNECTED".green().bold(),
                        ghostlink_engine::WireGuardState::Disconnected => "DISCONNECTED".red().bold(),
                        _ => "UNKNOWN".normal(),
                    };
                    println!("✨ Tunnel [{}] is now: {}\n", tunnel.cyan().bold(), state_colored);
                }
            }
        }

        Commands::Route { action } => {
            match action {
                RouteCommands::Add { domain, ip } => {
                    println!("\n🧠 [{}] Simulating / Adding Smart Fallback route for: {}", "SMART ROUTER".cyan().bold(), domain.yellow().bold());
                    let custom_ips = ip.map(|i| vec![i]);
                    match ghostlink_engine::SmartRouter::add_fallback_domain(&domain, "MANUAL_CLI_SIMULATION", custom_ips) {
                        Ok(ips) => {
                            println!("✅ Successfully registered domain [{}] to Smart Fallback!", domain.green().bold());
                            println!("   • Target IPs: {:?}", ips);
                            if let Some((iface, router)) = ghostlink_engine::SmartRouter::get_active_wg_info("wg0-daily") {
                                println!("   • WireGuard Interface: {}", iface.cyan().bold());
                                println!("   • WireGuard Gateway: {}", router.cyan());
                            }
                            println!("   • Stored in: ~/.ghostlink/smart_routing.json\n");
                        }
                        Err(e) => {
                            eprintln!("❌ Failed to add route: {}\n", e);
                        }
                    }
                }
                RouteCommands::List => {
                    let routes = ghostlink_engine::SmartRouter::load_routes();
                    println!("\n🧠 [{}] Learned Fallback Routes ({} domain(s)):\n", "SMART ROUTING DATABASE".cyan().bold(), routes.len());
                    if routes.is_empty() {
                        println!("   (No learned fallback routes yet. Use 'ghostlink_cli route add <domain>' to simulate/add)\n");
                    } else {
                        println!("{:<30} {:<30} {:<20}", "DOMAIN".bold(), "IPS".bold(), "REASON".bold());
                        println!("{:-<85}", "");
                        for entry in routes.values() {
                            println!("{:<30} {:<30} {:<20}", entry.domain.green(), format!("{:?}", entry.ips), entry.reason);
                        }
                        println!();
                    }
                }
                RouteCommands::Remove { domain } => {
                    match ghostlink_engine::SmartRouter::remove_domain(&domain) {
                        Ok(true) => println!("\n🗑️ Successfully removed domain [{}] and its WireGuard routes.\n", domain.green()),
                        Ok(false) => println!("\n⚠️ Domain [{}] was not found in smart routing database.\n", domain.yellow()),
                        Err(e) => eprintln!("❌ Failed to remove route: {}\n", e),
                    }
                }
                RouteCommands::Clear => {
                    match ghostlink_engine::SmartRouter::clear_routes() {
                        Ok(count) => println!("\n🧹 Cleared all {} learned Smart Fallback routes.\n", count),
                        Err(e) => eprintln!("❌ Failed to clear routes: {}\n", e),
                    }
                }
            }
        }

        Commands::Service { action } => {
            let sm = ServiceManager::new();
            match action {
                ServiceCommands::Install => {
                    println!("\n📦 Building and installing GhostLink Privileged Helper...");
                    
                    // Locate current target binary for ghostlink_daemon
                    let current_exe = std::env::current_exe()?;
                    let bin_dir = current_exe.parent().unwrap();
                    let daemon_bin = bin_dir.join("ghostlink_daemon");

                    let target_bin = if daemon_bin.exists() {
                        daemon_bin
                    } else {
                        // Fallback to debug/release target
                        let base_target = current_exe.parent().unwrap().parent().unwrap();
                        let debug_bin = base_target.join("debug").join("ghostlink_daemon");
                        if debug_bin.exists() {
                            debug_bin
                        } else {
                            base_target.join("release").join("ghostlink_daemon")
                        }
                    };

                    if !target_bin.exists() {
                        println!("⚙️ Compiling ghostlink_daemon binary first...");
                        let build_st = std::process::Command::new("cargo")
                            .args(["build", "--bin", "ghostlink_daemon"])
                            .status()?;
                        if !build_st.success() {
                            anyhow::bail!("Failed to compile ghostlink_daemon binary");
                        }
                    }

                    sm.install(&target_bin).await?;
                }

                ServiceCommands::Uninstall => {
                    sm.uninstall().await?;
                }

                ServiceCommands::Status => {
                    println!("\n🔍 LaunchDaemon Plist Installed: {}", if sm.is_plist_installed() { "YES".green() } else { "NO".yellow() });
                    println!("🔍 Launchctl Service Loaded: {}", if sm.is_launchctl_loaded() { "YES".green() } else { "NO".yellow() });
                    println!("📡 IPC Socket Path: {}", sm.client().socket_path().to_string_lossy().cyan());
                    
                    if sm.is_daemon_running().await {
                        let (_ver, is_root, pid) = sm.client().ping().await?;
                        println!("🟢 Privileged Daemon: {} (PID: {}, root: {})", "RUNNING".green().bold(), pid, if is_root { "YES".green() } else { "NO".red() });
                        let st = sm.client().get_status().await?;
                        println!("⚡ Engine State: {}", if st.is_running { "ACTIVE (Bypassing DPI)".green().bold() } else { "IDLE".yellow() });
                        if let Some(ref name) = st.active_strategy_name {
                            println!("🎯 Active Strategy: {}", name.cyan());
                        }
                    } else {
                        println!("🔴 Privileged Daemon: {}", "NOT RESPONDING".red().bold());
                    }
                    println!();
                }

                ServiceCommands::Start { strategy } => {
                    let engine = UnblockEngine::new(config);
                    let target_strat = resolve_strategy(&engine, &strategy)?;
                    println!("\n🚀 Sending START [{}] to Privileged Daemon...", target_strat.name.green());
                    let msg = sm.client().start(&target_strat.id, None, true).await?;
                    println!("✨ {}", msg.green());
                }

                ServiceCommands::Stop => {
                    println!("\n🛑 Sending STOP to Privileged Daemon...");
                    let msg = sm.client().stop().await?;
                    println!("✨ {}", msg.green());
                }

                ServiceCommands::Dns { servers } => {
                    println!("\n🌐 Configuring DNS servers: {:?}...", servers);
                    let msg = sm.client().configure_dns(servers).await?;
                    println!("✨ {}", msg.green());
                }

                ServiceCommands::ResetDns => {
                    println!("\n🌐 Resetting DNS to DHCP default...");
                    let msg = sm.client().reset_dns().await?;
                    println!("✨ {}", msg.green());
                }
            }
        }
    }

    Ok(())
}

fn resolve_strategy(engine: &UnblockEngine, query: &str) -> Result<Strategy> {
    let list = engine.list_strategies();
    if let Ok(idx) = query.parse::<usize>() {
        if idx >= 1 && idx <= list.len() {
            return Ok(list[idx - 1].clone());
        }
    }
    for s in &list {
        if s.id.eq_ignore_ascii_case(query) || s.name.to_lowercase().contains(&query.to_lowercase()) {
            return Ok(s.clone());
        }
    }
    anyhow::bail!("Strategy '{}' not found. Run 'ghostlink_cli list' to see available strategies.", query);
}

fn print_probe_summary(summary: &ghostlink_engine::ProbeSummary) {
    println!("\n📋 Probe Test Results:");
    for res in &summary.results {
        let icon = if res.success { "✔".green().bold() } else { "✖".red().bold() };
        let status_str = res.status_code.map(|s| s.to_string()).unwrap_or_else(|| "ERR".to_string());
        println!("  {} [{}] {} ({}ms)", icon, status_str.cyan(), res.label.bold(), res.latency_ms);
        if let Some(ref err) = res.error {
            println!("     └─ Error: {}", err.dimmed().red());
        }
    }

    println!("\nStatus: {}", if summary.success { "ALL PROBES PASSED (Working!)".green().bold() } else { "SOME PROBES FAILED".red().bold() });
    println!("Total Latency: {}ms\n", summary.total_latency_ms);
}
