use std::io::Write;
use std::process::{Command, Stdio};

/// Sends a native macOS desktop notification.
/// Security: Uses stdin piping to osascript instead of -e argument interpolation,
/// preventing AppleScript injection attacks from crafted domain names or messages.
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
        if let Ok(mut child) = Command::new("osascript")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            if let Some(ref mut stdin) = child.stdin {
                let _ = stdin.write_all(script.as_bytes());
            }
            // Don't wait — fire and forget
            let _ = child.wait();
        }
    }
}
