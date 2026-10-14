#[cfg(all(feature = "dev-2fa-stub", not(debug_assertions)))]
compile_error!("dev-2fa-stub is debug-only; do not build release binaries with deterministic 2FA");

pub mod args;
pub mod clipboard;
pub mod commands;
pub mod interface;
pub mod net;
pub mod password;
#[cfg(target_os = "linux")]
pub mod password_input;
pub mod session;
pub mod session_conn;
pub mod storage;
pub mod twofa;

#[cfg(test)]
mod tests;
