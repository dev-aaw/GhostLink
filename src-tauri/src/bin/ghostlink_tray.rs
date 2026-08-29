#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(target_os = "windows")]
mod windows_tray {
    use anyhow::Result;
    use ghostlink_engine::{
        notify, AutoStartManager, DaemonClient, EngineConfig, ProbeRunner, Strategy,
        UnblockEngine, WireGuardManager, WireGuardState,
    };
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use windows_sys::Win32::Foundation::*;
    use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows_sys::Win32::UI::Shell::*;
    use windows_sys::Win32::UI::WindowsAndMessaging::*;

    const WM_TRAYICON: u32 = WM_USER + 101;
    const TIMER_ID: usize = 1001;

    // Menu Command IDs
    const ID_GHOSTLINK_TOGGLE: usize = 1001;
    const ID_WIREGUARD_TOGGLE: usize = 1002;
    const ID_AUTOTUNE: usize = 1003;
    const ID_TEST_CONNECTION: usize = 1004;
    const ID_AUTOSTART_TOGGLE: usize = 1005;
    const ID_QUIT: usize = 1099;
    const ID_STRATEGY_BASE: usize = 2000;

    fn to_wide_null(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
    }

    struct TrayState {
        is_gl_running: bool,
        active_strategy_id: String,
        active_strategy_name: String,
        wireguard_tunnel_name: String,
        wireguard_connected: bool,
        autostart_enabled: bool,
        strategies: Vec<Strategy>,
    }

    static GLOBAL_STATE: Mutex<Option<Arc<Mutex<TrayState>>>> = Mutex::new(None);
    static GLOBAL_RUNTIME: Mutex<Option<tokio::runtime::Runtime>> = Mutex::new(None);
    static GLOBAL_CLIENT: Mutex<Option<DaemonClient>> = Mutex::new(None);
    static IS_RUNNING: AtomicBool = AtomicBool::new(true);

    fn detect_primary_wg_tunnel() -> String {
        let tunnels = WireGuardManager::list_tunnels();
        if let Some(first) = tunnels.first() {
            first.name.clone()
        } else {
            "wg0".to_string()
        }
    }

    pub fn run_tray() -> Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        let client = DaemonClient::default();
        let engine = UnblockEngine::new(EngineConfig::default());
        let strategies = engine.list_strategies();

        let default_strat_id = strategies.first().map(|s| s.id.clone()).unwrap_or_else(|| "win-general".to_string());
        let default_strat_name = strategies.first().map(|s| s.name.clone()).unwrap_or_else(|| "Windows General".to_string());
        let detected_wg = detect_primary_wg_tunnel();

        let state = Arc::new(Mutex::new(TrayState {
            is_gl_running: false,
            active_strategy_id: default_strat_id,
            active_strategy_name: default_strat_name,
            wireguard_tunnel_name: detected_wg,
            wireguard_connected: false,
            autostart_enabled: AutoStartManager::is_enabled(),
            strategies,
        }));

        *GLOBAL_STATE.lock().unwrap() = Some(state.clone());
        *GLOBAL_CLIENT.lock().unwrap() = Some(client);
        *GLOBAL_RUNTIME.lock().unwrap() = Some(rt);

        unsafe {
            let hinstance = GetModuleHandleW(std::ptr::null());
            let class_name = to_wide_null("GhostLinkTrayClass");

            let wnd_class = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                style: 0,
                lpfnWndProc: Some(wnd_proc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: hinstance,
                hIcon: LoadIconW(std::ptr::null_mut(), IDI_APPLICATION),
                hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
                hbrBackground: std::ptr::null_mut(),
                lpszMenuName: std::ptr::null(),
                lpszClassName: class_name.as_ptr(),
                hIconSm: LoadIconW(std::ptr::null_mut(), IDI_APPLICATION),
            };

            RegisterClassExW(&wnd_class);

            let hwnd = CreateWindowExW(
                0,
                class_name.as_ptr(),
                to_wide_null("GhostLink System Tray").as_ptr(),
                WS_OVERLAPPEDWINDOW,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                CW_USEDEFAULT,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                hinstance,
                std::ptr::null(),
            );

            if hwnd.is_null() {
                return Err(anyhow::anyhow!("Failed to create message window"));
            }

            // Create Tray Icon
            let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
            nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = hwnd;
            nid.uID = 1;
            nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
            nid.uCallbackMessage = WM_TRAYICON;
            nid.hIcon = LoadIconW(std::ptr::null_mut(), IDI_APPLICATION);

            let tip = to_wide_null("GhostLink: Starting...");
            for (i, &ch) in tip.iter().take(127).enumerate() {
                nid.szTip[i] = ch;
            }

            Shell_NotifyIconW(NIM_ADD, &nid);

            // Start 1.5s refresh timer
            SetTimer(hwnd, TIMER_ID, 1500, None);

            // Initial sync
            refresh_state_from_daemon(hwnd as usize);

            // Message Loop
            let mut msg: MSG = std::mem::zeroed();
            while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            // Cleanup Tray Icon
            Shell_NotifyIconW(NIM_DELETE, &nid);
        }

        Ok(())
    }

    fn refresh_state_from_daemon(hwnd_val: usize) {
        let state_arc = match GLOBAL_STATE.lock().unwrap().clone() {
            Some(s) => s,
            None => return,
        };

        std::thread::spawn(move || {
            let (is_running, strategy_name, strategy_id) = {
                let rt_guard = GLOBAL_RUNTIME.lock().unwrap();
                let client_guard = GLOBAL_CLIENT.lock().unwrap();
                if let (Some(rt), Some(client)) = (rt_guard.as_ref(), client_guard.as_ref()) {
                    rt.block_on(async {
                        if client.is_daemon_alive().await {
                            if let Ok(status) = client.get_status().await {
                                return (status.is_running, status.active_strategy_name, status.active_strategy_id);
                            }
                        }
                        (false, None, None)
                    })
                } else {
                    (false, None, None)
                }
            };

            let wg_name = {
                let st = state_arc.lock().unwrap();
                st.wireguard_tunnel_name.clone()
            };
            let is_wg_active = WireGuardManager::status(&wg_name) == WireGuardState::Connected;
            let is_autostart = AutoStartManager::is_enabled();

            let mut st = state_arc.lock().unwrap();
            st.is_gl_running = is_running;
            if let Some(name) = strategy_name {
                st.active_strategy_name = name;
            }
            if let Some(id) = strategy_id {
                st.active_strategy_id = id;
            }
            st.wireguard_connected = is_wg_active;
            st.autostart_enabled = is_autostart;

            // Update Tooltip
            let tip_text = format!(
                "GhostLink: {}\nStrategy: {}\nWireGuard: {}",
                if st.is_gl_running { "ACTIVE 🟢" } else { "IDLE ⚪" },
                st.active_strategy_name,
                if st.wireguard_connected { "CONNECTED 🔵" } else { "OFF" }
            );

            unsafe {
                let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
                nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
                nid.hWnd = hwnd_val as HWND;
                nid.uID = 1;
                nid.uFlags = NIF_TIP;

                let tip = to_wide_null(&tip_text);
                for (i, &ch) in tip.iter().take(127).enumerate() {
                    nid.szTip[i] = ch;
                }
                Shell_NotifyIconW(NIM_MODIFY, &nid);
            }
        });
    }

    unsafe fn show_context_menu(hwnd: HWND) {
        let state_arc = match GLOBAL_STATE.lock().unwrap().clone() {
            Some(s) => s,
            None => return,
        };
        let st = state_arc.lock().unwrap();

        let hmenu = CreatePopupMenu();
        if hmenu.is_null() {
            return;
        }

        // 1. GhostLink Engine Toggle
        let gl_label = if st.is_gl_running {
            format!("👻 GhostLink: Active [{}] (Click to Stop)", st.active_strategy_name)
        } else {
            "👻 GhostLink: Inactive (Click to Start)".to_string()
        };
        let mut gl_flags = MF_STRING;
        if st.is_gl_running {
            gl_flags |= MF_CHECKED;
        }
        AppendMenuW(hmenu, gl_flags, ID_GHOSTLINK_TOGGLE, to_wide_null(&gl_label).as_ptr());

        // 2. WireGuard Toggle
        let wg_label = format!(
            "🌍 Full VPN (WireGuard): {} [{}]",
            st.wireguard_tunnel_name,
            if st.wireguard_connected { "Connected" } else { "Disconnected" }
        );
        let mut wg_flags = MF_STRING;
        if st.wireguard_connected {
            wg_flags |= MF_CHECKED;
        }
        AppendMenuW(hmenu, wg_flags, ID_WIREGUARD_TOGGLE, to_wide_null(&wg_label).as_ptr());

        AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());

        // 3. Strategy Submenu
        let hstrat_menu = CreatePopupMenu();
        for (idx, strat) in st.strategies.iter().enumerate() {
            let mut s_flags = MF_STRING;
            if strat.id == st.active_strategy_id {
                s_flags |= MF_CHECKED;
            }
            let label = format!("{} ({})", strat.name, strat.id);
            AppendMenuW(hstrat_menu, s_flags, ID_STRATEGY_BASE + idx, to_wide_null(&label).as_ptr());
        }
        let strat_header = format!("⚡ Strategy: {}", st.active_strategy_name);
        AppendMenuW(hmenu, MF_POPUP, hstrat_menu as usize, to_wide_null(&strat_header).as_ptr());

        AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());

        // 4. Run Auto-Tune
        AppendMenuW(hmenu, MF_STRING, ID_AUTOTUNE, to_wide_null("🔄 Run Auto-Tune Benchmark").as_ptr());

        // 5. Test Connection (Probe)
        AppendMenuW(hmenu, MF_STRING, ID_TEST_CONNECTION, to_wide_null("📊 Test Connection (YouTube / Discord / WikiLeaks)").as_ptr());

        // 6. Start at Login
        let mut auto_flags = MF_STRING;
        if st.autostart_enabled {
            auto_flags |= MF_CHECKED;
        }
        AppendMenuW(hmenu, auto_flags, ID_AUTOSTART_TOGGLE, to_wide_null("🚀 Start at Login").as_ptr());

        AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());

        // 7. Quit
        AppendMenuW(hmenu, MF_STRING, ID_QUIT, to_wide_null("🚪 Quit GhostLink").as_ptr());

        let mut pt: POINT = std::mem::zeroed();
        GetCursorPos(&mut pt);

        SetForegroundWindow(hwnd);
        TrackPopupMenuEx(hmenu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN, pt.x, pt.y, hwnd, std::ptr::null());
        DestroyMenu(hmenu);
    }

    unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        match msg {
            WM_TRAYICON => {
                let event = lparam as u32;
                if event == WM_RBUTTONUP || event == WM_LBUTTONUP {
                    show_context_menu(hwnd);
                }
                0
            }
            WM_TIMER => {
                if wparam == TIMER_ID {
                    refresh_state_from_daemon(hwnd as usize);
                }
                0
            }
            WM_COMMAND => {
                let id = (wparam & 0xFFFF) as usize;
                handle_menu_command(hwnd, id);
                0
            }
            WM_DESTROY => {
                IS_RUNNING.store(false, Ordering::SeqCst);
                KillTimer(hwnd, TIMER_ID);
                PostQuitMessage(0);
                0
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    fn handle_menu_command(hwnd: HWND, id: usize) {
        let state_arc = match GLOBAL_STATE.lock().unwrap().clone() {
            Some(s) => s,
            None => return,
        };

        let hwnd_val = hwnd as usize;

        match id {
            ID_GHOSTLINK_TOGGLE => {
                std::thread::spawn(move || {
                    let rt_guard = GLOBAL_RUNTIME.lock().unwrap();
                    let client_guard = GLOBAL_CLIENT.lock().unwrap();
                    if let (Some(rt), Some(client)) = (rt_guard.as_ref(), client_guard.as_ref()) {
                        rt.block_on(async {
                            let is_running = {
                                let st = state_arc.lock().unwrap();
                                st.is_gl_running
                            };
                            if is_running {
                                let _ = client.stop().await;
                                notify("GhostLink", "GhostLink DPI Bypass stopped");
                            } else {
                                let strat_id = {
                                    let st = state_arc.lock().unwrap();
                                    st.active_strategy_id.clone()
                                };
                                let _ = client.start(&strat_id, None, true).await;
                                notify("GhostLink", "GhostLink DPI Bypass is now ACTIVE");
                            }
                        });
                    }
                    refresh_state_from_daemon(hwnd_val);
                });
            }
            ID_WIREGUARD_TOGGLE => {
                std::thread::spawn(move || {
                    let tunnel = {
                        let st = state_arc.lock().unwrap();
                        st.wireguard_tunnel_name.clone()
                    };
                    let new_state = WireGuardManager::toggle(&tunnel);
                    match new_state {
                        Ok(WireGuardState::Connected) => {
                            notify("GhostLink VPN", &format!("WireGuard [{}] Connected", tunnel));
                        }
                        Ok(WireGuardState::Disconnected) => {
                            notify("GhostLink VPN", &format!("WireGuard [{}] Disconnected", tunnel));
                        }
                        _ => {}
                    }
                    refresh_state_from_daemon(hwnd_val);
                });
            }
            ID_AUTOTUNE => {
                std::thread::spawn(move || {
                    notify("GhostLink Auto-Tune", "Benchmarking strategies for current ISP in progress...");
                    let rt_guard = GLOBAL_RUNTIME.lock().unwrap();
                    if let Some(rt) = rt_guard.as_ref() {
                        rt.block_on(async {
                            let mut engine = UnblockEngine::new(EngineConfig::default());
                            match engine.auto_tune(|_, _, _, _| {}).await {
                                Ok(Some(best)) => {
                                    notify(
                                        "GhostLink Auto-Tune Complete",
                                        &format!("🏆 Best Strategy Found: {}\nSwitching automatically...", best.name),
                                    );
                                    let client_guard = GLOBAL_CLIENT.lock().unwrap();
                                    if let Some(client) = client_guard.as_ref() {
                                        let _ = client.start(&best.id, None, true).await;
                                    }
                                }
                                Ok(None) => {
                                    notify("GhostLink Auto-Tune", "No working strategy found among candidates.");
                                }
                                Err(e) => {
                                    notify("GhostLink Auto-Tune", &format!("Auto-tune error: {}", e));
                                }
                            }
                        });
                    }
                    refresh_state_from_daemon(hwnd_val);
                });
            }
            ID_TEST_CONNECTION => {
                std::thread::spawn(move || {
                    notify("GhostLink", "Testing connection endpoints (YouTube / Discord / WikiLeaks)...");
                    let rt_guard = GLOBAL_RUNTIME.lock().unwrap();
                    if let Some(rt) = rt_guard.as_ref() {
                        rt.block_on(async {
                            let runner = ProbeRunner::new();
                            let summary = runner.run_suite("probe", None).await;
                            if summary.success {
                                notify(
                                    "GhostLink Connection Test",
                                    &format!("✅ ALL PROBES PASSED!\nTotal Latency: {}ms", summary.total_latency_ms),
                                );
                            } else {
                                notify(
                                    "GhostLink Connection Test",
                                    "⚠️ Some endpoints could not be reached.",
                                );
                            }
                        });
                    }
                });
            }
            ID_AUTOSTART_TOGGLE => {
                if let Ok(exe_path) = std::env::current_exe() {
                    let _ = AutoStartManager::toggle(&exe_path);
                    let enabled = AutoStartManager::is_enabled();
                    notify(
                        "GhostLink",
                        if enabled { "Start at Login: ENABLED" } else { "Start at Login: DISABLED" },
                    );
                    refresh_state_from_daemon(hwnd_val);
                }
            }
            ID_QUIT => {
                unsafe {
                    DestroyWindow(hwnd);
                }
            }
            id if id >= ID_STRATEGY_BASE => {
                let idx = id - ID_STRATEGY_BASE;
                std::thread::spawn(move || {
                    let target_strat = {
                        let st = state_arc.lock().unwrap();
                        st.strategies.get(idx).cloned()
                    };

                    if let Some(strat) = target_strat {
                        let rt_guard = GLOBAL_RUNTIME.lock().unwrap();
                        let client_guard = GLOBAL_CLIENT.lock().unwrap();
                        if let (Some(rt), Some(client)) = (rt_guard.as_ref(), client_guard.as_ref()) {
                            rt.block_on(async {
                                let _ = client.start(&strat.id, None, true).await;
                                notify("GhostLink", &format!("Strategy switched to: {}", strat.name));
                            });
                        }
                    }
                    refresh_state_from_daemon(hwnd_val);
                });
            }
            _ => {}
        }
    }
}

fn main() -> anyhow::Result<()> {
    #[cfg(target_os = "windows")]
    {
        windows_tray::run_tray()
    }
    #[cfg(not(target_os = "windows"))]
    {
        eprintln!("ghostlink_tray is designed for Windows.");
        Ok(())
    }
}
