//! Best-effort desktop notifications, usable from any component (the
//! daemon, the updater, the tray).
//!
//! On macOS, banners are posted through `mac-notification-sys` bound to the
//! fastverk bundle id, so they read "fastverk" (now that the app is a
//! signed Developer ID bundle registered with Launch Services) instead of
//! the osascript scripting host. Falls back to `osascript` if that path is
//! unavailable (e.g. the bundle isn't registered), and is a no-op off macOS.

#[cfg(target_os = "macos")]
const BUNDLE_ID: &str = "com.fastverk.app";

/// Post a notification (best-effort — never fails the caller).
pub fn send(title: &str, body: &str) {
    #[cfg(target_os = "macos")]
    {
        if post_via_bundle(title, body).is_err() {
            post_via_osascript(title, body);
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (title, body);
    }
}

#[cfg(target_os = "macos")]
fn post_via_bundle(title: &str, body: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Once;
    // set_application can only be called once per process; remember whether
    // the bundle registered so later calls fall back cleanly.
    static INIT: Once = Once::new();
    static REGISTERED: AtomicBool = AtomicBool::new(false);
    INIT.call_once(|| {
        REGISTERED.store(
            mac_notification_sys::set_application(BUNDLE_ID).is_ok(),
            Ordering::Relaxed,
        );
    });
    if !REGISTERED.load(Ordering::Relaxed) {
        return Err("bundle not registered".into());
    }
    mac_notification_sys::Notification::new()
        .title(title)
        .message(body)
        .send()?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn post_via_osascript(title: &str, body: &str) {
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

#[cfg(all(test, target_os = "macos"))]
mod tests {
    /// Manual: `cargo test -p fvkit posts_a_banner -- --ignored --nocapture`
    /// — posts a real banner (should read "fastverk" once the bundle is
    /// registered with Launch Services).
    #[test]
    #[ignore]
    fn posts_a_banner() {
        let ok = super::post_via_bundle("fastverk", "notify test — bundle path");
        println!("post_via_bundle: {ok:?}");
    }
}
