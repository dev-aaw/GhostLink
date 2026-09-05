#![allow(deprecated)]

#[cfg(target_os = "macos")]
mod macos_app {
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
        // Recover from a poisoned lock: a panic inside one menu handler must not
        // permanently brick every subsequent menu interaction while the process
        // (and its status-bar item) linger on, apparently alive but inert.
        let mut guard = APP_CTX.lock().unwrap_or_else(|e| e.into_inner());
        let ctx = guard.as_mut().expect("APP_CTX not initialized");
        f(ctx)
    }

    /// Extract a human-readable message from a caught panic payload (the
    /// standard `panic!("...")` / `.expect("...")` shapes; anything else is
    /// reported generically rather than guessed at).
    fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
        if let Some(s) = payload.downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "non-string panic payload".to_string()
        }
    }

    /// Run `f`, catching any panic so it can never reach the Objective-C
    /// runtime across the calling `extern "C" fn`'s FFI boundary.
    ///
    /// Without this, a panic inside one of these menu-handler callbacks
    /// unwinds straight into "panic in a function that cannot unwind" — Rust
    /// detects the unwind is about to cross into `extern "C"` code (which by
    /// default cannot safely propagate it, since Objective-C's own frames in
    /// between don't know how to run Rust's landing pads) and calls `abort()`
    /// to avoid undefined behaviour. This happens regardless of the crate's
    /// `[profile] panic` setting (release's `panic = "abort"` is irrelevant;
    /// dev's default `unwind` still hits this same FFI-boundary rule) — the
    /// whole menu bar process is gone instantly, with the LaunchAgent's
    /// `KeepAlive` set to `false` (autostart.rs), so nothing restarts it. Every
    /// subsequent click on the (now-vanished) status item does nothing.
    /// `with_app_ctx`'s poison-recovery (`into_inner()`) can only matter for a
    /// *second* call that happens after the first panicked, which requires the
    /// process to still be alive to receive it — this is that missing half.
    ///
    /// `label` identifies the handler in the log so a crash report/log tail
    /// says which one. Catching here also gives the handler a normal, no-op
    /// return instead of no return at all.
    ///
    /// AssertUnwindSafe: every caller's closure only ever touches (a)
    /// `APP_CTX`, whose `Mutex` already tolerates and recovers from poisoning
    /// in `with_app_ctx` above — a panic mid-mutation of `AppContext`'s fields
    /// just means the next call sees whatever partial state was left, not a
    /// corrupted invariant that needs unwind-safety to protect; and (b) raw
    /// Objective-C `id` pointers to Cocoa objects whose lifetime and retain/
    /// release invariants are owned by the Objective-C runtime, not Rust's
    /// borrow checker — a panic between two `msg_send!` calls leaves at worst
    /// a stale/half-updated menu item, corrected by the next successful
    /// `update_menu_ui()`, never a memory-safety issue.
    fn catch_handler_panic(label: &str, f: impl FnOnce() + std::panic::UnwindSafe) {
        if let Err(payload) = std::panic::catch_unwind(f) {
            let msg = panic_message(payload.as_ref());
            eprintln!("⚠️ [{label}] panic caught at FFI boundary: {msg}");
            ghostlink_engine::log_msg("ERROR", &format!("panic in menu handler '{label}': {msg}"));
        }
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

            // 2. Query WireGuard Tunnels Status (Mutual Exclusion).
            // `status(name)` asks scutil by name and is independent of how
            // `scutil --nc list` labels the tunnel type; list-parsing (tried
            // briefly in v2.1.17) silently dropped .mobileconfig-provisioned or
            // "[VPN]"-typed tunnels and showed them as Disconnected while up.
            // This runs only on menuWillOpen:, so two short forks are fine.
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

                // Update Smart Fallback Description
                let smart_text = format!("🧠 Smart Fallback: {} domain(s) on WireGuard", route_count);
                let smart_str = NSString::alloc(nil).init_str(&smart_text);
                let _: () = msg_send![ctx.item_smart_desc, setTitle: smart_str];

                // Update Active Strategy Radio State
                let is_midsld = current_strat.contains("midsld") || current_strat.contains("mac-split-midsld");
                let is_sni = current_strat.contains("sni") || current_strat.contains("mac-split-tls-sni");
                let is_pos1 = current_strat.contains("pos1") || current_strat.contains("mac-split-pos-1");

                let _: () = msg_send![ctx.item_midsld, setState: if is_midsld { 1isize } else { 0isize }];
                let _: () = msg_send![ctx.item_tls_sni, setState: if is_sni { 1isize } else { 0isize }];
                let _: () = msg_send![ctx.item_pos1, setState: if is_pos1 { 1isize } else { 0isize }];

                // Update Status Line Text
                let status_line = if is_gl_running {
                    format!("Status: Active (Strategy: {})", current_strat)
                } else {
                    "Status: Inactive".to_string()
                };
                let status_str = NSString::alloc(nil).init_str(&status_line);
                let _: () = msg_send![ctx.item_status_desc, setTitle: status_str];

                // Update AutoStart State
                let _: () = msg_send![ctx.item_autostart, setState: if is_autostart_enabled { 1isize } else { 0isize }];
            }
        });
    }

    // Objective-C Callback Implementations
    extern "C" fn menu_will_open(_this: &Object, _cmd: Sel, _menu: id) {
        catch_handler_panic("menu_will_open", std::panic::AssertUnwindSafe(|| {
            update_menu_ui();
        }));
    }

    extern "C" fn toggle_ghostlink(_this: &Object, _cmd: Sel, _item: id) {
        catch_handler_panic("toggle_ghostlink", std::panic::AssertUnwindSafe(|| {
        with_app_ctx(|ctx| {
            let (is_daemon, is_running) = ctx.runtime.block_on(async {
                if ctx.client.is_daemon_alive().await {
                    if let Ok(st) = ctx.client.get_status().await {
                        return (true, st.is_running);
                    }
                }
                (false, ctx.standalone_engine.as_ref().map(|e| e.is_running()).unwrap_or(false))
            });

            if is_running {
                // STOP
                if is_daemon {
                    let _ = ctx.runtime.block_on(ctx.client.stop());
                } else if let Some(ref mut eng) = ctx.standalone_engine {
                    let _ = ctx.runtime.block_on(eng.stop());
                }
                notify("GhostLink DPI Bypass", "GhostLink disconnected (normal routing restored)");
            } else {
                // START
                let strat_id = ctx.active_strategy.clone();
                if is_daemon {
                    let _ = ctx.runtime.block_on(ctx.client.start(&strat_id, Some(1080), true));
                } else {
                    if ctx.standalone_engine.is_none() {
                        ctx.standalone_engine = Some(UnblockEngine::new(EngineConfig::default()));
                    }
                    if let Some(ref mut eng) = ctx.standalone_engine {
                        let strat_opt = eng.list_strategies().into_iter().find(|s| s.id == strat_id);
                        if let Some(s) = strat_opt {
                            let _ = ctx.runtime.block_on(eng.start(&s));
                        }
                    }
                }
                notify("GhostLink DPI Bypass", "GhostLink connected (YouTube & Discord unblocked)");
            }

            update_menu_ui();
        });
        }));
    }

    extern "C" fn toggle_wg_daily(_this: &Object, _cmd: Sel, _item: id) {
        catch_handler_panic("toggle_wg_daily", std::panic::AssertUnwindSafe(|| {
            let _ = WireGuardManager::toggle_exclusive("wg0-daily");
            update_menu_ui();
        }));
    }

    extern "C" fn toggle_wg_mac(_this: &Object, _cmd: Sel, _item: id) {
        catch_handler_panic("toggle_wg_mac", std::panic::AssertUnwindSafe(|| {
            let _ = WireGuardManager::toggle_exclusive("wg0-mac");
            update_menu_ui();
        }));
    }

    extern "C" fn select_strategy_midsld(_this: &Object, _cmd: Sel, _item: id) {
        catch_handler_panic("select_strategy_midsld", std::panic::AssertUnwindSafe(|| {
            switch_strategy("mac-split-midsld");
        }));
    }

    extern "C" fn select_strategy_tls_sni(_this: &Object, _cmd: Sel, _item: id) {
        catch_handler_panic("select_strategy_tls_sni", std::panic::AssertUnwindSafe(|| {
            switch_strategy("mac-split-tls-sni");
        }));
    }

    extern "C" fn select_strategy_pos1(_this: &Object, _cmd: Sel, _item: id) {
        catch_handler_panic("select_strategy_pos1", std::panic::AssertUnwindSafe(|| {
            switch_strategy("mac-split-pos-1");
        }));
    }

    fn switch_strategy(strategy_id: &str) {
        with_app_ctx(|ctx| {
            ctx.active_strategy = strategy_id.to_string();

            let (is_daemon, is_running) = ctx.runtime.block_on(async {
                if ctx.client.is_daemon_alive().await {
                    if let Ok(st) = ctx.client.get_status().await {
                        return (true, st.is_running);
                    }
                }
                (false, ctx.standalone_engine.as_ref().map(|e| e.is_running()).unwrap_or(false))
            });

            if is_running {
                if is_daemon {
                    let _ = ctx.runtime.block_on(ctx.client.start(strategy_id, Some(1080), true));
                } else if let Some(ref mut eng) = ctx.standalone_engine {
                    let strat_opt = eng.list_strategies().into_iter().find(|s| s.id == strategy_id);
                    if let Some(s) = strat_opt {
                        let _ = ctx.runtime.block_on(eng.start(&s));
                    }
                }
                notify("GhostLink Strategy Switched", &format!("Active: {}", strategy_id));
            }

            update_menu_ui();
        });
    }

    extern "C" fn run_autotune(_this: &Object, _cmd: Sel, _item: id) {
        catch_handler_panic("run_autotune", std::panic::AssertUnwindSafe(|| {
        notify("GhostLink Auto-Tune", "Starting ISP strategy benchmark in background...");
        // The spawned thread below never crosses back into Objective-C: it's a
        // plain Rust std::thread, not an ObjC callback, so a panic inside it
        // cannot trigger the FFI-boundary abort this fix is about — it would
        // just end that one background thread. Left unwrapped; out of this
        // fix's scope, noted separately as a lower-severity residual.
        std::thread::spawn(|| {
            with_app_ctx(|ctx| {
                let res = ctx.runtime.block_on(async {
                    if ctx.client.is_daemon_alive().await {
                        ctx.client.auto_tune().await.map(|(opt, _)| opt)
                    } else {
                        let mut eng = UnblockEngine::new(EngineConfig::default());
                        eng.auto_tune(|_, _, _, _| {}).await
                    }
                });

                match res {
                    Ok(Some(strat)) => {
                        notify("GhostLink Auto-Tune Complete", &format!("Best strategy found: {}", strat.name));
                        switch_strategy(&strat.id);
                    }
                    Ok(None) => {
                        notify("GhostLink Auto-Tune", "No working strategy found for current ISP.");
                    }
                    Err(e) => {
                        notify("GhostLink Auto-Tune Error", &format!("Benchmark failed: {}", e));
                    }
                }
            });
        });
        }));
    }

    extern "C" fn run_probe(_this: &Object, _cmd: Sel, _item: id) {
        catch_handler_panic("run_probe", std::panic::AssertUnwindSafe(|| {
        // Same note as run_autotune: the spawned thread doesn't cross the FFI
        // boundary, so it's intentionally left unwrapped here.
        std::thread::spawn(|| {
            with_app_ctx(|ctx| {
                let summary = ctx.runtime.block_on(async {
                    if ctx.client.is_daemon_alive().await {
                        ctx.client.probe_direct().await
                    } else {
                        let runner = ghostlink_engine::ProbeRunner::new();
                        Ok(runner.run_suite("direct", None).await)
                    }
                });

                match summary {
                    Ok(s) => {
                        let passed = s.results.iter().filter(|r| r.success).count();
                        let total = s.results.len();
                        notify(
                            "GhostLink Connection Health",
                            &format!("{}/{} endpoints reachable (Latency: {}ms)", passed, total, s.total_latency_ms),
                        );
                    }
                    Err(e) => {
                        notify("GhostLink Test Failed", &format!("Error: {}", e));
                    }
                }
            });
        });
        }));
    }

    extern "C" fn toggle_autostart(_this: &Object, _cmd: Sel, _item: id) {
        catch_handler_panic("toggle_autostart", std::panic::AssertUnwindSafe(|| {
            let exe = std::env::current_exe().unwrap_or_default();
            let _ = AutoStartManager::toggle(&exe);
            update_menu_ui();
        }));
    }

    extern "C" fn quit_app(_this: &Object, _cmd: Sel, _item: id) {
        // Catch first so a panic during the graceful stop attempt still lets
        // us fall through to exit(0) below — the user asked to quit; a hiccup
        // stopping the engine shouldn't prevent that (see the comment on
        // catch_handler_panic for why this can't just be left to abort()).
        catch_handler_panic("quit_app", std::panic::AssertUnwindSafe(|| {
            with_app_ctx(|ctx| {
                let is_daemon = ctx.runtime.block_on(ctx.client.is_daemon_alive());
                if is_daemon {
                    let _ = ctx.runtime.block_on(ctx.client.stop());
                } else if let Some(ref mut eng) = ctx.standalone_engine {
                    let _ = ctx.runtime.block_on(eng.stop());
                }
            });
        }));
        std::process::exit(0);
    }

    fn register_menu_handler() -> id {
        let superclass = class!(NSObject);
        let mut decl = ClassDecl::new(MENU_HANDLER_CLASS, superclass).unwrap();

        unsafe {
            decl.add_method(sel!(menuWillOpen:), menu_will_open as extern "C" fn(&Object, Sel, id));
            decl.add_method(sel!(toggleGhostLink:), toggle_ghostlink as extern "C" fn(&Object, Sel, id));
            decl.add_method(sel!(toggleWireGuardDaily:), toggle_wg_daily as extern "C" fn(&Object, Sel, id));
            decl.add_method(sel!(toggleWireGuardMac:), toggle_wg_mac as extern "C" fn(&Object, Sel, id));
            decl.add_method(sel!(setStrategyMidsld:), select_strategy_midsld as extern "C" fn(&Object, Sel, id));
            decl.add_method(sel!(setStrategyTlsSni:), select_strategy_tls_sni as extern "C" fn(&Object, Sel, id));
            decl.add_method(sel!(setStrategyPos1:), select_strategy_pos1 as extern "C" fn(&Object, Sel, id));
            decl.add_method(sel!(runAutoTune:), run_autotune as extern "C" fn(&Object, Sel, id));
            decl.add_method(sel!(runProbe:), run_probe as extern "C" fn(&Object, Sel, id));
            decl.add_method(sel!(toggleAutoStart:), toggle_autostart as extern "C" fn(&Object, Sel, id));
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

    pub fn run() -> anyhow::Result<()> {
        // So catch_handler_panic's log_msg() calls below actually persist
        // somewhere (~/.ghostlink/logs/menubar.log) instead of silently
        // no-op'ing; the menu bar always runs as the console user, so HOME is
        // set here (unlike the root daemon — see the base_dir fix history).
        ghostlink_engine::init_logger("menubar");

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
                NSString::alloc(nil).init_str("Status: Inactive"),
                sel_impl!("noop:"),
                NSString::alloc(nil).init_str(""),
            );
            let _: () = msg_send![item_status_desc, setEnabled: NO];
            let _: () = msg_send![item_status_desc, retain];
            let _: () = msg_send![menu, addItem: item_status_desc];

            let _: () = msg_send![menu, addItem: NSMenuItem::separatorItem(nil)];

            // 5. DPI Strategy Selection (Radio Group)
            let item_strat_header = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
                NSString::alloc(nil).init_str("--- macOS DPI Strategies ---"),
                sel_impl!("noop:"),
                NSString::alloc(nil).init_str(""),
            );
            let _: () = msg_send![item_strat_header, setEnabled: NO];
            let _: () = msg_send![menu, addItem: item_strat_header];

            let item_midsld = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
                NSString::alloc(nil).init_str("⚡ Mid-SLD + Disorder (Recommended)"),
                sel!(setStrategyMidsld:),
                NSString::alloc(nil).init_str(""),
            );
            let _: () = msg_send![item_midsld, setTarget: handler];
            let _: () = msg_send![item_midsld, retain];
            let _: () = msg_send![menu, addItem: item_midsld];

            let item_tls_sni = NSMenuItem::alloc(nil).initWithTitle_action_keyEquivalent_(
                NSString::alloc(nil).init_str("⚡ TLS SNI Split"),
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

            *APP_CTX.lock().unwrap_or_else(|e| e.into_inner()) = Some(ctx);

            update_menu_ui();

            let _: () = msg_send![app, finishLaunching];
            println!("👻 GhostLink Native Menu Bar App running with Full VPN and Smart Router.");
            app.run();

            let _: () = msg_send![pool, drain];
        }

        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn main() -> anyhow::Result<()> {
    macos_app::run()
}

#[cfg(not(target_os = "macos"))]
fn main() -> anyhow::Result<()> {
    eprintln!("ghostlink_menubar is native to macOS. On Windows, use ghostlink_cli or the GhostLink Windows GUI.");
    Ok(())
}
