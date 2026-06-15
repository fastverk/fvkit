//! Best-effort desktop notifications, usable from any component (the
//! daemon, the updater, the tray). On macOS this posts a Notification
//! Center banner via `osascript`; elsewhere it's a no-op for now.
//!
//! macOS caveat: `osascript display notification` is attributed to the
//! scripting host, not "fastverk". A bundle-identity notification
//! (UNUserNotificationCenter) is a follow-up once the app is signed.

/// Post a notification (best-effort — never fails the caller).
pub fn send(title: &str, body: &str) {
    #[cfg(target_os = "macos")]
    {
        let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let _ = std::process::Command::new("osascript")
            .arg("-e")
            .arg(format!(
                "display notification \"{}\" with title \"{}\"",
                esc(body),
                esc(title)
            ))
            .status();
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (title, body);
    }
}
