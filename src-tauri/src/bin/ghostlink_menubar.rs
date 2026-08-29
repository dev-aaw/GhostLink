#![allow(deprecated)]
use cocoa::appkit::{
    NSApp, NSApplication, NSApplicationActivationPolicyAccessory, NSMenuItem,
    NSStatusBar, NSStatusItem,
};
use cocoa::base::{id, nil, NO, YES};
use cocoa::foundation::{NSAutoreleasePool, NSString};
use objc::declare::ClassDecl;
use objc::runtime::{Class, Object, Sel};
use objc::{class, msg_send, sel, sel_impl};

use ghostlink_engine::{
    notify, AutoStartManager, DaemonClient, EngineConfig, SmartRouter, UnblockEngine,
    WireGuardManager, WireGuardState,
};

static MENU_HANDLER_CLASS: &str = "GhostLinkMenuHandler";

struct AppContext {
    client: DaemonClient,
    runtime: tokio::runtime::Runtime,
    standalone_engine: Option<UnblockEngine>,
    active_strategy: String,
    // UI Item references
    item_gl: id,
    item_wg_daily: id,
    item_wg_full: id,
    item_smart_desc: id,
    item_midsld: id,
    item_tls_sni: id,
    item_pos1: id,
    item_status_desc: id,
    item_autostart: id,
}

unsafe impl Send for AppContext {}
unsafe impl Sync for AppContext {}

static APP_CTX: std::sync::Mutex<Option<AppContext>> = std::sync::Mutex::new(None);

fn with_app_ctx<R, F: FnOnce(&mut AppContext) -> R>(f: F) -> R {
    let mut guard = APP_CTX.lock().expect("Failed to lock APP_CTX");
    let ctx = guard.as_mut().expect("APP_CTX not initialized");
    f(ctx)
}

/// Query real-time status of GhostLink, WireGuard (daily & full), Smart Fallback, and AutoStart.
fn update_menu_ui() {
    with_app_ctx(|ctx| {
        // 1. Query GhostLink Engine Status
        let (is_gl_running, current_strat) = ctx.runtime.block_on(async {
            if ctx.client.is_daemon_alive().await {
                if let Ok(st) = ctx.client.get_status().await {
                    return (st.is_running, st.active_strategy_name.unwrap_or_else(|| ctx.active_strategy.clone()));
                }
            }
            if let Some(ref eng) = ctx.standalone_engine {
                if eng.is_running() {
                    return (true, ctx.active_strategy.clone());
                }
            }
            (false, ctx.active_strategy.clone())
        });

    // 2. Query WireGuard Tunnels Status (Mutual Exclusion)
    let is_daily_connected = WireGuardManager::status("wg0-daily") == WireGuardState::Connected;
    let is_full_connected = WireGuardManager::status("wg0-mac") == WireGuardState::Connected;

    // 3. Query Learned Fallback Routes
    let route_count = SmartRouter::load_routes().len();

    // 4. Query AutoStart Status
    let is_autostart_enabled = AutoStartManager::is_enabled();

    unsafe {
        // Update GhostLink Item
        let gl_title = if is_gl_running {
            NSString::alloc(nil).init_str("👻 GhostLink: Active (DPI Bypass ON)")
        } else {
            NSString::alloc(nil).init_str("👻 GhostLink: Inactive (Click to Start)")
        };
        let _: () = msg_send![ctx.item_gl, setTitle: gl_title];
        let _: () = msg_send![ctx.item_gl, setState: if is_gl_running { 1isize } else { 0isize }];

        // Update Split VPN (wg0-daily) Item
        let daily_title = if is_daily_connected {
            NSString::alloc(nil).init_str("🛡️ Split VPN (wg0-daily): Connected")
        } else {
            NSString::alloc(nil).init_str("🛡️ Split VPN (wg0-daily): Disconnected")
        };
        let _: () = msg_send![ctx.item_wg_daily, setTitle: daily_title];
        let _: () = msg_send![ctx.item_wg_daily, setState: if is_daily_connected { 1isize } else { 0isize }];

        // Update Full VPN (wg0-mac) Item
        let full_title = if is_full_connected {
            NSString::alloc(nil).init_str("🌍 Full VPN (wg0-mac): Connected")
        } else {
            NSString::alloc(nil).init_str("🌍 Full VPN (wg0-mac): Disconnected")
        };
        let _: () = msg_send![ctx.item_wg_full, setTitle: full_title];
        let _: () = msg_send![ctx.item_wg_full, setState: if is_full_connected { 1isize } else { 0isize }];

        // Update Smart Fallback Description Item
        let smart_desc = format!("🧠 Smart Fallback: {} domain(s) on WireGuard", route_count);
        let smart_ns = NSString::alloc(nil).init_str(&smart_desc);
        let _: () = msg_send![ctx.item_smart_desc, setTitle: smart_ns];

        // Update Strategy Items Checkmarks
        let is_midsld = ctx.active_strategy == "mac-split-midsld";
        let is_tls_sni = ctx.active_strategy == "mac-split-tls-sni";
        let is_pos1 = ctx.active_strategy == "mac-split-pos-1";

        let _: () = msg_send![ctx.item_midsld, setState: if is_midsld { 1isize } else { 0isize }];
        let _: () = msg_send![ctx.item_tls_sni, setState: if is_tls_sni { 1isize } else { 0isize }];
        let _: () = msg_send![ctx.item_pos1, setState: if is_pos1 { 1isize } else { 0isize }];

        // Update Status Description Item
        let status_desc = if is_gl_running {
            format!("⚡ Active: {} (SOCKS 10808)", current_strat)
        } else {
            "⚪ Engine Idle".to_string()
        };
        let desc_ns = NSString::alloc(nil).init_str(&status_desc);
        let _: () = msg_send![ctx.item_status_desc, setTitle: desc_ns];

        // Update AutoStart Item
        let _: () = msg_send![ctx.item_autostart, setState: if is_autostart_enabled { 1isize } else { 0isize }];
        }
    });
}

#[no_mangle]
pub extern "C" fn menu_will_open(_this: &Object, _cmd: Sel, _menu: id) {
    update_menu_ui();
}

#[no_mangle]
pub extern "C" fn toggle_ghostlink(_this: &Object, _cmd: Sel, _sender: id) {
    println!("🔘 [Menu] GhostLink Toggle clicked");

    let will_be_active = with_app_ctx(|ctx| {
        let mut active = false;
        ctx.runtime.block_on(async {
            if ctx.client.is_daemon_alive().await {
                if let Ok(st) = ctx.client.get_status().await {
                    if st.is_running {
                        println!("🛑 Stopping engine via daemon...");
                        let _ = ctx.client.stop().await;
                        active = false;
                    } else {
                        println!("🚀 Starting engine via daemon with [{}]...", ctx.active_strategy);
                        let _ = ctx.client.start(&ctx.active_strategy, None, true).await;
                        active = true;
                    }
                }
            } else {
                // Standalone engine mode fallback
                if let Some(ref mut eng) = ctx.standalone_engine {
                    if eng.is_running() {
                        println!("🛑 Stopping engine (Standalone)...");
                        let _ = eng.stop().await;
                        active = false;
                    } else {
                        println!("🚀 Starting engine with [{}] (Standalone)...", ctx.active_strategy);
                        let strategies = eng.list_strategies();
                        if let Some(s) = strategies.iter().find(|s| s.id == ctx.active_strategy).cloned() {
                            match eng.start(&s).await {
                                Ok(()) => active = true,
                                Err(e) => {
                                    eprintln!("❌ Engine start error: {}", e);
                                    active = false;
                                }
                            }
                        }
                    }
                } else {
                    let mut eng = UnblockEngine::new(EngineConfig::default());
                    println!("🚀 Initializing & Starting engine with [{}] (Standalone)...", ctx.active_strategy);
                    let strategies = eng.list_strategies();
                    if let Some(s) = strategies.iter().find(|s| s.id == ctx.active_strategy).cloned() {
                        match eng.start(&s).await {
                            Ok(()) => active = true,
                            Err(e) => {
                                eprintln!("❌ Engine start error: {}", e);
                                active = false;
                            }
                        }
                    }
                    ctx.standalone_engine = Some(eng);
                }
            }
        });
        active
    });

    if will_be_active {
        notify("GhostLink", "GhostLink Active - DPI Bypass Enabled");
    } else {
        notify("GhostLink", "GhostLink Stopped");
    }

    update_menu_ui();
}

#[no_mangle]
pub extern "C" fn toggle_wireguard_daily(_this: &Object, _cmd: Sel, _sender: id) {
    println!("🔘 [Menu] Split VPN (wg0-daily) Toggle clicked");
    match WireGuardManager::toggle_exclusive("wg0-daily") {
        Ok(WireGuardState::Connected) => {
            println!("🛡️ Split VPN (wg0-daily) Connected");
            notify("WireGuard", "Split VPN (wg0-daily) Connected");
        }
        Ok(WireGuardState::Disconnected) => {
            println!("🛡️ Split VPN (wg0-daily) Disconnected");
            notify("WireGuard", "Split VPN (wg0-daily) Disconnected");
        }
        Ok(state) => println!("🛡️ WireGuard state: {:?}", state),
        Err(e) => eprintln!("❌ WireGuard error: {}", e),
    }
    update_menu_ui();
}

#[no_mangle]
pub extern "C" fn toggle_wireguard_mac(_this: &Object, _cmd: Sel, _sender: id) {
    println!("🔘 [Menu] Full VPN (wg0-mac) Toggle clicked");
    match WireGuardManager::toggle_exclusive("wg0-mac") {
        Ok(WireGuardState::Connected) => {
            println!("🌍 Full VPN (wg0-mac) Connected - All traffic routed via VPN");
            notify("WireGuard", "Full VPN (wg0-mac) Connected");
        }
        Ok(WireGuardState::Disconnected) => {
            println!("🌍 Full VPN (wg0-mac) Disconnected");
            notify("WireGuard", "Full VPN (wg0-mac) Disconnected");
        }
        Ok(state) => println!("🌍 Full VPN state: {:?}", state),
        Err(e) => eprintln!("❌ Full VPN error: {}", e),
    }
    update_menu_ui();
}

#[no_mangle]
pub extern "C" fn toggle_autostart(_this: &Object, _cmd: Sel, _sender: id) {
    println!("🔘 [Menu] AutoStart Toggle clicked");
    let current_exe = std::env::current_exe().unwrap_or_default();
    match AutoStartManager::toggle(&current_exe) {
        Ok(true) => {
            println!("🚀 Start at Login enabled");
            notify("GhostLink", "Start at Login Enabled");
        }
        Ok(false) => {
            println!("🚀 Start at Login disabled");
            notify("GhostLink", "Start at Login Disabled");
        }
        Err(e) => eprintln!("❌ Failed to toggle autostart: {}", e),
    }
    update_menu_ui();
}

fn switch_strategy(target_id: &str) {
    with_app_ctx(|ctx| {
        ctx.active_strategy = target_id.to_string();
        println!("⚡ Switching strategy to: {}", target_id);

        ctx.runtime.block_on(async {
            if ctx.client.is_daemon_alive().await {
                let _ = ctx.client.start(target_id, None, true).await;
            } else if let Some(ref mut eng) = ctx.standalone_engine {
                if eng.is_running() {
                    let strategies = eng.list_strategies();
                    if let Some(s) = strategies.iter().find(|s| s.id == target_id).cloned() {
                        let _ = eng.start(&s).await;
                    }
                }
            }
        });
    });

    notify("GhostLink Strategy", &format!("Strategy switched to: {}", target_id));
    update_menu_ui();
}

#[no_mangle]
pub extern "C" fn set_strategy_midsld(_this: &Object, _cmd: Sel, _sender: id) {
    switch_strategy("mac-split-midsld");
}

#[no_mangle]
pub extern "C" fn set_strategy_tls_sni(_this: &Object, _cmd: Sel, _sender: id) {
    switch_strategy("mac-split-tls-sni");
}

#[no_mangle]
pub extern "C" fn set_strategy_pos1(_this: &Object, _cmd: Sel, _sender: id) {
    switch_strategy("mac-split-pos-1");
}

#[no_mangle]
pub extern "C" fn run_autotune(_this: &Object, _cmd: Sel, _sender: id) {
    println!("🔄 [Menu] Running Auto-Tune benchmark in background...");
    notify("GhostLink Auto-Tune", "Benchmarking strategies on live connections...");

    with_app_ctx(|ctx| {
        ctx.runtime.block_on(async {
            if ctx.client.is_daemon_alive().await {
                if let Ok((Some(best), _)) = ctx.client.auto_tune().await {
                    ctx.active_strategy = best.id.clone();
                    let _ = ctx.client.start(&best.id, None, true).await;
                    println!("🏆 Auto-tune locked in best strategy: {}", best.name);
                    notify("GhostLink Auto-Tune", &format!("Best strategy selected: {}", best.name));
                }
            } else {
                let mut eng = UnblockEngine::new(EngineConfig::default());
                if let Ok(Some(best)) = eng.auto_tune(|curr, total, strat, _| {
                    println!("   [{}/{}] Testing strategy: {}", curr, total, strat.name);
                }).await {
                    ctx.active_strategy = best.id.clone();
                    let _ = eng.start(&best).await;
                    ctx.standalone_engine = Some(eng);
                    println!("🏆 Auto-tune locked in best strategy: {}", best.name);
                    notify("GhostLink Auto-Tune", &format!("Best strategy selected: {}", best.name));
                }
            }
        });
    });
    update_menu_ui();
}

#[no_mangle]
pub extern "C" fn run_probe(_this: &Object, _cmd: Sel, _sender: id) {
    println!("📊 [Menu] Running connection probe diagnostic...");
    with_app_ctx(|ctx| {
        ctx.runtime.block_on(async {
            if ctx.client.is_daemon_alive().await {
                if let Ok(summary) = ctx.client.probe_direct().await {
                    let status_msg = format!("Diagnostic: {} ({}ms)", if summary.success { "PASSED" } else { "FAILED" }, summary.total_latency_ms);
                    println!("📋 {}", status_msg);
                    notify("GhostLink Diagnostic", &status_msg);
                }
            } else {
                let runner = ghostlink_engine::ProbeRunner::new();
                let summary = runner.run_suite("direct", None).await;
                let status_msg = format!("Diagnostic: {} ({}ms)", if summary.success { "PASSED" } else { "FAILED" }, summary.total_latency_ms);
                println!("📋 {}", status_msg);
                notify("GhostLink Diagnostic", &status_msg);
            }
        });
    });
}

#[no_mangle]
pub extern "C" fn quit_app(_this: &Object, _cmd: Sel, _sender: id) {
    println!("🚪 [Menu] Quitting GhostLink...");
    with_app_ctx(|ctx| {
        ctx.runtime.block_on(async {
            if ctx.client.is_daemon_alive().await {
                let _ = ctx.client.stop().await;
            }
            if let Some(ref mut eng) = ctx.standalone_engine {
                let _ = eng.stop().await;
            }
        });
    });

    unsafe {
        let app = NSApp();
        let _: () = msg_send![app, terminate: nil];
    }
}

fn register_menu_handler() -> id {
    let mut decl = ClassDecl::new(MENU_HANDLER_CLASS, class!(NSObject)).unwrap();
    unsafe {
        decl.add_method(sel!(menuWillOpen:), menu_will_open as extern "C" fn(&Object, Sel, id));
        decl.add_method(sel!(menuNeedsUpdate:), menu_will_open as extern "C" fn(&Object, Sel, id));
        decl.add_method(sel!(toggleGhostLink:), toggle_ghostlink as extern "C" fn(&Object, Sel, id));
        decl.add_method(sel!(toggleWireGuardDaily:), toggle_wireguard_daily as extern "C" fn(&Object, Sel, id));
        decl.add_method(sel!(toggleWireGuardMac:), toggle_wireguard_mac as extern "C" fn(&Object, Sel, id));
        decl.add_method(sel!(toggleAutoStart:), toggle_autostart as extern "C" fn(&Object, Sel, id));
        decl.add_method(sel!(setStrategyMidsld:), set_strategy_midsld as extern "C" fn(&Object, Sel, id));
        decl.add_method(sel!(setStrategyTlsSni:), set_strategy_tls_sni as extern "C" fn(&Object, Sel, id));
        decl.add_method(sel!(setStrategyPos1:), set_strategy_pos1 as extern "C" fn(&Object, Sel, id));
        decl.add_method(sel!(runAutoTune:), run_autotune as extern "C" fn(&Object, Sel, id));
        decl.add_method(sel!(runProbe:), run_probe as extern "C" fn(&Object, Sel, id));
        decl.add_method(sel!(quitApp:), quit_app as extern "C" fn(&Object, Sel, id));
    }
    decl.register();

    let cls = Class::get(MENU_HANDLER_CLASS).unwrap();
    unsafe {
        let obj: id = msg_send![cls, alloc];
        let obj: id = msg_send![obj, init];
        obj
    }
}

fn main() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    unsafe {
        let pool = NSAutoreleasePool::new(nil);
        let app = NSApp();
        app.setActivationPolicy_(NSApplicationActivationPolicyAccessory);

        let handler = register_menu_handler();
        let _: id = msg_send![handler, retain];

        // Status Item in Menu Bar with dynamic width (NSVariableStatusItemLength = -1.0)
        let status_bar = NSStatusBar::systemStatusBar(nil);
        let status_item = status_bar.statusItemWithLength_(-1.0);
        let _: id = msg_send![status_item, retain];
        let _: () = msg_send![status_item, setVisible: YES];
        let _: () = msg_send![status_item, setHighlightMode: YES];

        let title_str = NSString::alloc(nil).init_str("👻 GhostLink");
        let button: id = msg_send![status_item, button];
        if button != nil {
            let _: () = msg_send![button, setTitle: title_str];
            let _: () = msg_send![button, setHidden: NO];
        }

        // Build Menu
        let menu: id = msg_send![class!(NSMenu), new];
        let _: id = msg_send![menu, retain];
        let _: () = msg_send![menu, setDelegate: handler];

        // 1. GhostLink Toggle
        let item_gl = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
            NSString::alloc(nil).init_str("👻 GhostLink: Inactive (Click to Start)"),
            sel!(toggleGhostLink:),
            NSString::alloc(nil).init_str(""),
        );
        let _: () = msg_send![item_gl, setTarget: handler];
        let _: () = msg_send![item_gl, retain];
        let _: () = msg_send![menu, addItem: item_gl];

        let _: () = msg_send![menu, addItem: NSMenuItem::separatorItem(nil)];

        // 2. WireGuard Tunnels (Mutually Exclusive)
        let item_wg_daily = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
            NSString::alloc(nil).init_str("🛡️ Split VPN (wg0-daily): Disconnected"),
            sel!(toggleWireGuardDaily:),
            NSString::alloc(nil).init_str(""),
        );
        let _: () = msg_send![item_wg_daily, setTarget: handler];
        let _: () = msg_send![item_wg_daily, retain];
        let _: () = msg_send![menu, addItem: item_wg_daily];

        let item_wg_full = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
            NSString::alloc(nil).init_str("🌍 Full VPN (wg0-mac): Disconnected"),
            sel!(toggleWireGuardMac:),
            NSString::alloc(nil).init_str(""),
        );
        let _: () = msg_send![item_wg_full, setTarget: handler];
        let _: () = msg_send![item_wg_full, retain];
        let _: () = msg_send![menu, addItem: item_wg_full];

        // 3. Smart Fallback Info Item
        let item_smart_desc = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
            NSString::alloc(nil).init_str("🧠 Smart Fallback: 0 domain(s) on WireGuard"),
            sel_impl!("noop:"),
            NSString::alloc(nil).init_str(""),
        );
        let _: () = msg_send![item_smart_desc, setEnabled: NO];
        let _: () = msg_send![item_smart_desc, retain];
        let _: () = msg_send![menu, addItem: item_smart_desc];

        let _: () = msg_send![menu, addItem: NSMenuItem::separatorItem(nil)];

        // 4. Status Description Item
        let item_status_desc = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
            NSString::alloc(nil).init_str("⚪ Engine Idle"),
            sel_impl!("noop:"),
            NSString::alloc(nil).init_str(""),
        );
        let _: () = msg_send![item_status_desc, setEnabled: NO];
        let _: () = msg_send![item_status_desc, retain];
        let _: () = msg_send![menu, addItem: item_status_desc];

        let _: () = msg_send![menu, addItem: NSMenuItem::separatorItem(nil)];

        // 5. Strategy Options
        let item_midsld = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
            NSString::alloc(nil).init_str("⚡ macOS TLS Split + Mid-SLD (Recommended)"),
            sel!(setStrategyMidsld:),
            NSString::alloc(nil).init_str(""),
        );
        let _: () = msg_send![item_midsld, setTarget: handler];
        let _: () = msg_send![item_midsld, retain];
        let _: () = msg_send![menu, addItem: item_midsld];

        let item_tls_sni = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
            NSString::alloc(nil).init_str("⚡ macOS TLS SNI Split"),
            sel!(setStrategyTlsSni:),
            NSString::alloc(nil).init_str(""),
        );
        let _: () = msg_send![item_tls_sni, setTarget: handler];
        let _: () = msg_send![item_tls_sni, retain];
        let _: () = msg_send![menu, addItem: item_tls_sni];

        let item_pos1 = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
            NSString::alloc(nil).init_str("⚡ macOS Split Pos 1"),
            sel!(setStrategyPos1:),
            NSString::alloc(nil).init_str(""),
        );
        let _: () = msg_send![item_pos1, setTarget: handler];
        let _: () = msg_send![item_pos1, retain];
        let _: () = msg_send![menu, addItem: item_pos1];

        let _: () = msg_send![menu, addItem: NSMenuItem::separatorItem(nil)];

        // 6. Tools & Settings
        let item_tune = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
            NSString::alloc(nil).init_str("🔄 Run Auto-Tune Benchmark"),
            sel!(runAutoTune:),
            NSString::alloc(nil).init_str(""),
        );
        let _: () = msg_send![item_tune, setTarget: handler];
        let _: () = msg_send![menu, addItem: item_tune];

        let item_probe = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
            NSString::alloc(nil).init_str("📊 Test Connection (YouTube/Discord/WikiLeaks)"),
            sel!(runProbe:),
            NSString::alloc(nil).init_str(""),
        );
        let _: () = msg_send![item_probe, setTarget: handler];
        let _: () = msg_send![menu, addItem: item_probe];

        let item_autostart = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
            NSString::alloc(nil).init_str("🚀 Start at Login"),
            sel!(toggleAutoStart:),
            NSString::alloc(nil).init_str(""),
        );
        let _: () = msg_send![item_autostart, setTarget: handler];
        let _: () = msg_send![item_autostart, retain];
        let _: () = msg_send![menu, addItem: item_autostart];

        let _: () = msg_send![menu, addItem: NSMenuItem::separatorItem(nil)];

        // 7. Quit
        let item_quit = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
            NSString::alloc(nil).init_str("🚪 Quit GhostLink"),
            sel!(quitApp:),
            NSString::alloc(nil).init_str("q"),
        );
        let _: () = msg_send![item_quit, setTarget: handler];
        let _: () = msg_send![menu, addItem: item_quit];

        status_item.setMenu_(menu);

        let ctx = AppContext {
            client: DaemonClient::default(),
            runtime: rt,
            standalone_engine: None,
            active_strategy: "mac-split-midsld".to_string(),
            item_gl,
            item_wg_daily,
            item_wg_full,
            item_smart_desc,
            item_midsld,
            item_tls_sni,
            item_pos1,
            item_status_desc,
            item_autostart,
        };

        *APP_CTX.lock().unwrap() = Some(ctx);

        update_menu_ui();

        let _: () = msg_send![app, finishLaunching];
        println!("👻 GhostLink Native Menu Bar App running with Full VPN and Smart Router.");
        app.run();

        let _: () = msg_send![pool, drain];
    }

    Ok(())
}
