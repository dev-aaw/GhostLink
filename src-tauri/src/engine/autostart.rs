use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct AutoStartManager;

impl AutoStartManager {
    pub fn plist_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home)
            .join("Library")
            .join("LaunchAgents")
            .join("com.ghostlink.menubar.plist")
    }

    pub fn is_enabled() -> bool {
        Self::plist_path().exists()
    }

    pub fn enable(app_executable_path: &Path) -> Result<()> {
        let plist_path = Self::plist_path();
        if let Some(parent) = plist_path.parent() {
            fs::create_dir_all(parent)?;
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

        fs::write(&plist_path, plist_content)?;
        let _ = Command::new("launchctl")
            .args(["load", "-w", &plist_path.to_string_lossy()])
            .status();

        Ok(())
    }

    pub fn disable() -> Result<()> {
        let plist_path = Self::plist_path();
        if plist_path.exists() {
            let _ = Command::new("launchctl")
                .args(["unload", "-w", &plist_path.to_string_lossy()])
                .status();
            let _ = fs::remove_file(&plist_path);
        }
        Ok(())
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
