//! Per-OS backends behind a single boundary.
//!
//! macOS is implemented first (APFS volumes, Keychain, `osascript`
//! elevation, LaunchAgent). Linux (btrfs/loopback + Secret Service +
//! systemd) and Windows (VHDX + Credential Manager + service) are P6 and
//! compile as stubs so the shared crate builds on every host.

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "windows")]
pub mod windows;
