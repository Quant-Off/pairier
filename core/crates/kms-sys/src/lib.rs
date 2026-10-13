#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("kms-sys supports only linux and macos targets");

mod error;
pub mod harden;
pub mod mem;
pub mod peer;

pub use error::Error;
