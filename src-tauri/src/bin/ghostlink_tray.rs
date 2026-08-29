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
    use windows_sys::Win32::Graphics::Gdi::*;
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress, LoadLibraryW};
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
            "wg0-pc".to_string()
        }
    }

    /// Enable native Dark Mode for Win32 menus and windows on Windows 10/11
    unsafe fn enable_dark_mode(hwnd: HWND) {
        // 1. SetPreferredAppMode (ordinal 135) in uxtheme.dll (ForceDark = 2 / AllowDark = 1)
        let uxtheme_dll = LoadLibraryW(to_wide_null("uxtheme.dll").as_ptr());
        if !uxtheme_dll.is_null() {
            type FnSetPreferredAppMode = unsafe extern "system" fn(i32) -> i32;
            type FnFlushMenuThemes = unsafe extern "system" fn();

            if let Some(proc) = GetProcAddress(uxtheme_dll, 135 as *const u8) {
                let set_mode: FnSetPreferredAppMode = std::mem::transmute(proc);
                set_mode(2); // ForceDark
            }
            if let Some(proc) = GetProcAddress(uxtheme_dll, 136 as *const u8) {
                let flush: FnFlushMenuThemes = std::mem::transmute(proc);
                flush();
            }
            if let Some(proc) = GetProcAddress(uxtheme_dll, b"SetWindowTheme\0".as_ptr()) {
                type FnSetWindowTheme = unsafe extern "system" fn(HWND, *const u16, *const u16) -> i32;
                let set_theme: FnSetWindowTheme = std::mem::transmute(proc);
                let theme_name = to_wide_null("DarkMode_Explorer");
                set_theme(hwnd, theme_name.as_ptr(), std::ptr::null());
            }
        }

        // 2. DwmSetWindowAttribute for Immersive Dark Mode
        let dwmapi_dll = LoadLibraryW(to_wide_null("dwmapi.dll").as_ptr());
        if !dwmapi_dll.is_null() {
            type FnDwmSetWindowAttribute = unsafe extern "system" fn(HWND, u32, *const std::ffi::c_void, u32) -> i32;
            if let Some(proc) = GetProcAddress(dwmapi_dll, b"DwmSetWindowAttribute\0".as_ptr()) {
                let dwm_set_attr: FnDwmSetWindowAttribute = std::mem::transmute(proc);
                let dark: i32 = 1;
                let _ = dwm_set_attr(hwnd, 20, &dark as *const _ as *const _, std::mem::size_of::<i32>() as u32);
                let _ = dwm_set_attr(hwnd, 19, &dark as *const _ as *const _, std::mem::size_of::<i32>() as u32);
            }
        }
    }

    /// Generate a stylized, neon-cyan glowing 👻 GhostLink icon for the System Tray
    unsafe fn create_ghostlink_icon() -> HICON {
        let width: u32 = 32;
        let height: u32 = 32;
        let mut color_pixels = vec![0u32; (width * height) as usize];
        let mut mask_pixels = vec![0xFFu8; ((width + 31) / 32 * 4 * height) as usize];

        for y in 0..height {
            for x in 0..width {
                let fx = x as f32;
                let fy = y as f32;

                // Ghost Head: rounded dome
                let in_head = (fx - 15.5) * (fx - 15.5) + (fy - 12.0) * (fy - 12.0) <= 9.0 * 9.0 && fy <= 12.0;
                // Ghost Body: torso
                let in_body = fx >= 6.5 && fx <= 24.5 && fy > 12.0 && fy <= 22.0;
                // Ghost Skirt: wavy bottom
                let wave = ((fx * 0.75).sin() * 2.2).round();
                let in_skirt = fx >= 6.5 && fx <= 24.5 && fy > 22.0 && fy <= (24.0 + wave);

                if in_head || in_body || in_skirt {
                    // Cute Eyes (dark blue with bright white sparkle)
                    let in_left_eye = (fx - 11.5) * (fx - 11.5) / 1.6 + (fy - 13.5) * (fy - 13.5) / 4.0 <= 1.0;
                    let in_right_eye = (fx - 19.5) * (fx - 19.5) / 1.6 + (fy - 13.5) * (fy - 13.5) / 4.0 <= 1.0;
                    let in_left_twinkle = (x == 11 || x == 12) && (y == 12);
                    let in_right_twinkle = (x == 19 || x == 20) && (y == 12);

                    // Cute soft pink blush
                    let in_left_blush = (x == 8 || x == 9) && (y == 16 || y == 17);
                    let in_right_blush = (x == 22 || x == 23) && (y == 16 || y == 17);

                    let pixel = if in_left_twinkle || in_right_twinkle {
                        0xFFFFFFFF // White star twinkle
                    } else if in_left_eye || in_right_eye {
                        0xFF0B1426 // Deep dark indigo
                    } else if in_left_blush || in_right_blush {
                        0xFFFF7BA9 // Soft kawaii pink blush
                    } else {
                        // Radiant celestial cyan-to-white gradient
                        let ratio = ((fy - 3.0) / 24.0).clamp(0.0, 1.0);
                        let r = (245.0 * (1.0 - ratio) + 0.0 * ratio) as u32;
                        let g = (255.0 * (1.0 - ratio) + 215.0 * ratio) as u32;
                        let b = (255.0 * (1.0 - ratio) + 255.0 * ratio) as u32;
                        0xFF000000 | (r << 16) | (g << 8) | b
                    };

                    let idx = (y * width + x) as usize;
                    color_pixels[idx] = pixel;

                    // Unmask pixel in 1-bit transparency mask
                    let row_bytes = ((width + 31) / 32 * 4) as usize;
                    let byte_idx = (y as usize) * row_bytes + (x as usize / 8);
                    let bit_idx = 7 - (x % 8);
                    mask_pixels[byte_idx] &= !(1 << bit_idx);
                }
            }
        }

        let hbm_color = CreateBitmap(width as i32, height as i32, 1, 32, color_pixels.as_ptr() as _);
        let hbm_mask = CreateBitmap(width as i32, height as i32, 1, 1, mask_pixels.as_ptr() as _);

        let mut icon_info: ICONINFO = std::mem::zeroed();
        icon_info.fIcon = 1;
        icon_info.hbmColor = hbm_color;
        icon_info.hbmMask = hbm_mask;

        let hicon = CreateIconIndirect(&icon_info);
        DeleteObject(hbm_color as _);
        DeleteObject(hbm_mask as _);

        if hicon.is_null() {
            LoadIconW(std::ptr::null_mut(), IDI_APPLICATION)
        } else {
            hicon
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

            let ghost_icon = create_ghostlink_icon();

            let wnd_class = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                style: 0,
                lpfnWndProc: Some(wnd_proc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: hinstance,
                hIcon: ghost_icon,
                hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
                hbrBackground: std::ptr::null_mut(),
                lpszMenuName: std::ptr::null(),
                lpszClassName: class_name.as_ptr(),
                hIconSm: ghost_icon,
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

            // Apply Immersive Dark Mode to window and menus
            enable_dark_mode(hwnd);

            // Create Tray Icon with customized Ghost icon
            let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
            nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
            nid.hWnd = hwnd;
            nid.uID = 1;
            nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
            nid.uCallbackMessage = WM_TRAYICON;
            nid.hIcon = ghost_icon;

            let tip = to_wide_null("GhostLink DPI Bypass");
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

        // 1. GhostLink Engine Toggle (Active shows ✓, Inactive shows clean text)
        let gl_label = if st.is_gl_running {
            format!("✓  GhostLink: Active [{}]", st.active_strategy_name)
        } else {
            "GhostLink: Inactive (Click to Start)".to_string()
        };
        let mut gl_flags = MF_STRING;
        if st.is_gl_running {
            gl_flags |= MF_CHECKED;
        }
        AppendMenuW(hmenu, gl_flags, ID_GHOSTLINK_TOGGLE, to_wide_null(&gl_label).as_ptr());
        if st.is_gl_running {
            CheckMenuItem(hmenu, ID_GHOSTLINK_TOGGLE as u32, MF_BYCOMMAND | MF_CHECKED);
        }

        // 2. WireGuard Toggle (Active shows ✓, Inactive shows clean text)
        let wg_label = if st.wireguard_connected {
            format!("✓  Full VPN (WireGuard): {} [Connected]", st.wireguard_tunnel_name)
        } else {
            format!("Full VPN (WireGuard): {} [Disconnected]", st.wireguard_tunnel_name)
        };
        let mut wg_flags = MF_STRING;
        if st.wireguard_connected {
            wg_flags |= MF_CHECKED;
        }
        AppendMenuW(hmenu, wg_flags, ID_WIREGUARD_TOGGLE, to_wide_null(&wg_label).as_ptr());
        if st.wireguard_connected {
            CheckMenuItem(hmenu, ID_WIREGUARD_TOGGLE as u32, MF_BYCOMMAND | MF_CHECKED);
        }

        AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());

        // 3. Strategy Submenu (Active strategy shows ✓, others clean text)
        let hstrat_menu = CreatePopupMenu();
        for (idx, strat) in st.strategies.iter().enumerate() {
            let is_active = strat.id == st.active_strategy_id;
            let label = if is_active {
                format!("✓  {} ({})", strat.name, strat.id)
            } else {
                format!("{} ({})", strat.name, strat.id)
            };
            let mut s_flags = MF_STRING;
            if is_active {
                s_flags |= MF_CHECKED;
            }
            let item_id = ID_STRATEGY_BASE + idx;
            AppendMenuW(hstrat_menu, s_flags, item_id, to_wide_null(&label).as_ptr());
            if is_active {
                CheckMenuItem(hstrat_menu, item_id as u32, MF_BYCOMMAND | MF_CHECKED);
            }
        }
        let strat_header = format!("⚡ Strategy: {}", st.active_strategy_name);
        AppendMenuW(hmenu, MF_POPUP, hstrat_menu as usize, to_wide_null(&strat_header).as_ptr());

        AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());

        // 4. Run Auto-Tune
        AppendMenuW(hmenu, MF_STRING, ID_AUTOTUNE, to_wide_null("🔄 Run Auto-Tune Benchmark").as_ptr());

        // 5. Test Connection (Probe)
        AppendMenuW(hmenu, MF_STRING, ID_TEST_CONNECTION, to_wide_null("📊 Test Connection (YouTube / Discord / WikiLeaks)").as_ptr());

        // 6. Start at Login
        let auto_label = if st.autostart_enabled {
            "✓  Start at Login".to_string()
        } else {
            "Start at Login".to_string()
        };
        let mut auto_flags = MF_STRING;
        if st.autostart_enabled {
            auto_flags |= MF_CHECKED;
        }
        AppendMenuW(hmenu, auto_flags, ID_AUTOSTART_TOGGLE, to_wide_null(&auto_label).as_ptr());
        if st.autostart_enabled {
            CheckMenuItem(hmenu, ID_AUTOSTART_TOGGLE as u32, MF_BYCOMMAND | MF_CHECKED);
        }

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
                            // Query live status from daemon to be 100% synchronized
                            let is_currently_running = if client.is_daemon_alive().await {
                                match client.get_status().await {
                                    Ok(status) => status.is_running,
                                    Err(_) => state_arc.lock().unwrap().is_gl_running,
                                }
                            } else {
                                state_arc.lock().unwrap().is_gl_running
                            };

                            if is_currently_running {
                                // Turn OFF / Stop engine
                                match client.stop().await {
                                    Ok(_) => {
                                        {
                                            let mut st = state_arc.lock().unwrap();
                                            st.is_gl_running = false;
                                        }
                                        notify("GhostLink", "GhostLink DPI Bypass stopped");
                                    }
                                    Err(e) => {
                                        notify("GhostLink Error", &format!("Failed to stop engine: {}", e));
                                    }
                                }
                            } else {
                                // Turn ON / Start engine
                                let strat_id = {
                                    let st = state_arc.lock().unwrap();
                                    st.active_strategy_id.clone()
                                };
                                match client.start(&strat_id, None, true).await {
                                    Ok(_) => {
                                        {
                                            let mut st = state_arc.lock().unwrap();
                                            st.is_gl_running = true;
                                        }
                                        notify("GhostLink", "GhostLink DPI Bypass is now ACTIVE");
                                    }
                                    Err(e) => {
                                        notify("GhostLink Error", &format!("Failed to start engine: {}", e));
                                    }
                                }
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

                    let rt_guard = GLOBAL_RUNTIME.lock().unwrap();
                    let client_guard = GLOBAL_CLIENT.lock().unwrap();
                    if let (Some(rt), Some(client)) = (rt_guard.as_ref(), client_guard.as_ref()) {
                        rt.block_on(async {
                            let res = if client.is_daemon_alive().await {
                                client.wireguard_toggle(&tunnel).await
                            } else {
                                WireGuardManager::toggle(&tunnel)
                            };

                            match res {
                                Ok(WireGuardState::Connected) => {
                                    {
                                        let mut st = state_arc.lock().unwrap();
                                        st.wireguard_connected = true;
                                    }
                                    notify("GhostLink VPN", &format!("WireGuard [{}] Connected", tunnel));
                                }
                                Ok(WireGuardState::Disconnected) => {
                                    {
                                        let mut st = state_arc.lock().unwrap();
                                        st.wireguard_connected = false;
                                    }
                                    notify("GhostLink VPN", &format!("WireGuard [{}] Disconnected", tunnel));
                                }
                                Ok(WireGuardState::Connecting) => {
                                    notify("GhostLink VPN", &format!("WireGuard [{}] Connecting...", tunnel));
                                }
                                Ok(WireGuardState::Disconnecting) => {
                                    notify("GhostLink VPN", &format!("WireGuard [{}] Disconnecting...", tunnel));
                                }
                                Ok(WireGuardState::Unknown(msg)) => {
                                    notify("GhostLink VPN", &format!("WireGuard state: {}", msg));
                                }
                                Err(e) => {
                                    notify("GhostLink VPN Error", &format!("Failed to toggle WireGuard: {}", e));
                                }
                            }
                        });
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
