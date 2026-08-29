use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use ghostlink_engine::{EngineConfig, ProbeRunner, Strategy, UnblockEngine};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::signal;

#[derive(Parser)]
#[command(name = "ghostlink_cli")]
#[command(about = "GhostLink Core Engine CLI - Test and verify DPI bypass strategies on macOS & Windows", long_about = None)]
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
    /// Test a specific strategy against YouTube and Discord endpoints
    Test {
        /// Strategy index (1-based) or Strategy ID (e.g. mac-split-midsld or 1)
        #[arg(short, long, default_value = "1")]
        strategy: String,
    },
    /// Automatically test all strategies and find the best working one for your ISP
    Autotune,
    /// Start the bypass engine with a strategy and keep running in background
    Start {
        /// Strategy index or ID to run (default: 1)
        #[arg(short, long, default_value = "1")]
        strategy: String,
        /// Do not apply system-wide proxy automatically (macOS only)
        #[arg(long, default_value_t = false)]
        no_proxy: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = EngineConfig::default();

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

        Commands::Start { strategy, no_proxy } => {
            let mut cfg = config;
            if no_proxy {
                cfg.apply_system_proxy = false;
            }
            let mut engine = UnblockEngine::new(cfg);
            let target_strat = resolve_strategy(&engine, &strategy)?;

            engine.start(&target_strat).await?;
            println!("\n{}", "🎉 GhostLink Engine is active and running!".bold().green());
            println!("   • Strategy: {}", target_strat.name.cyan());
            println!("   • SOCKS Port: {}", engine.config().socks_port.to_string().yellow());
            println!("   • Press Ctrl+C to stop and restore system network settings...\n");

            // Wait for Ctrl+C gracefully
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
            engine.stop().await?;
            println!("{}", "✨ GhostLink stopped and network settings restored.".green());
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
