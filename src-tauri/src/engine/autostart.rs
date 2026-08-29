use anyhow::Result;
use std::path::Path;
use crate::engine::silent_command;

pub struct AutoStartManager;

impl AutoStartManager {
    #[cfg(target_os = "macos")]
    pub fn plist_path() -> std::path::PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        std::path::PathBuf::from(home)
            .join("Library")
            .join("LaunchAgents")
            .join("com.ghostlink.menubar.plist")
    }

    pub fn is_enabled() -> bool {
        #[cfg(target_os = "macos")]
        {
            Self::plist_path().exists()
        }
        #[cfg(target_os = "windows")]
        {
            let output = silent_command("reg.exe")
                .args(["query", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "GhostLink"])
                .output();
            if let Ok(out) = output {
                return out.status.success();
            }
            false
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            false
        }
    }

    pub fn enable(app_executable_path: &Path) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let plist_path = Self::plist_path();
            if let Some(parent) = plist_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let plist_content = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ghostlink.menubar</string>
    <key>ProgramArguments</key>
    <array>
        <string>{}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>ProcessType</key>
    <string>Interactive</string>
</dict>
</plist>"#,
                app_executable_path.to_string_lossy()
            );

            std::fs::write(&plist_path, plist_content)?;
            let _ = silent_command("launchctl")
                .args(["load", "-w", &plist_path.to_string_lossy()])
                .status();

            Ok(())
        }
        #[cfg(target_os = "windows")]
        {
            let exe_str = format!("\"{}\"", app_executable_path.to_string_lossy());
            let _ = silent_command("reg.exe")
                .args(["add", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "GhostLink", "/t", "REG_SZ", "/d", &exe_str, "/f"])
                .status();
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            Ok(())
        }
    }

    pub fn disable() -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            let plist_path = Self::plist_path();
            if plist_path.exists() {
                let _ = silent_command("launchctl")
                    .args(["unload", "-w", &plist_path.to_string_lossy()])
                    .status();
                let _ = std::fs::remove_file(&plist_path);
            }
            Ok(())
        }
        #[cfg(target_os = "windows")]
        {
            let _ = silent_command("reg.exe")
                .args(["delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "/v", "GhostLink", "/f"])
                .status();
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            Ok(())
        }
    }

    pub fn toggle(app_executable_path: &Path) -> Result<bool> {
        if Self::is_enabled() {
            Self::disable()?;
            Ok(false)
        } else {
            Self::enable(app_executable_path)?;
            Ok(true)
        }
    }
}
