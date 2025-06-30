//! Platform-specific test module

#[cfg(target_os = "macos")]
pub mod macos_tests;

#[cfg(target_os = "linux")]
pub mod linux_tests;