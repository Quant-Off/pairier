#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
compile_error!("kms-sys supports only linux, macos and windows targets");

mod error;
#[cfg(unix)]
pub mod harden;
pub mod mem;
#[cfg(unix)]
pub mod peer;

pub use error::Error;
