use std::io::Write;
use std::process::Stdio;
use crate::engine::silent_command;

/// Sends a native desktop notification on macOS and Windows.
/// Security: Uses stdin piping to avoid shell argument injection.
pub fn notify(title: &str, message: &str) {
    #[cfg(target_os = "macos")]
    {
        // Escape backslashes first, then double quotes for AppleScript string literals
        let safe_title = title.replace('\\', "\\\\").replace('"', "\\\"");
        let safe_message = message.replace('\\', "\\\\").replace('"', "\\\"");

        let script = format!(
            "display notification \"{}\" with title \"{}\"",
            safe_message, safe_title
        );

        // Pipe script via stdin rather than -e to avoid shell argument parsing issues
        if let Ok(mut child) = silent_command("osascript")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(script.as_bytes());
            }
            let _ = child.wait();
        }
    }

    #[cfg(target_os = "windows")]
    {
        let safe_title = title.replace('`', "``").replace('$', "`$").replace('"', "`\"");
        let safe_message = message.replace('`', "``").replace('$', "`$").replace('"', "`\"");

        let ps_script = format!(
            r#"[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$nodes = $template.GetElementsByTagName("text")
$nodes.Item(0).AppendChild($template.CreateTextNode("{}")) > $null
$nodes.Item(1).AppendChild($template.CreateTextNode("{}")) > $null
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("GhostLink")
$notification = [Windows.UI.Notifications.ToastNotification]::new($template)
$notifier.Show($notification)
"#,
            safe_title, safe_message
        );

        if let Ok(mut child) = silent_command("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(ps_script.as_bytes());
            }
            let _ = child.wait();
        }
    }
}
