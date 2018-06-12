extern crate libc;

use std::sync::{Once, ONCE_INIT};

pub mod db;
pub mod engine;
mod error;
mod ffi;
pub mod scan_settings;
pub mod version;

pub use error::ClamError;

/// Initializes clamav
///
/// This must be called once per process. This is safe to call multiple times.
pub fn initialize() -> Result<(), ClamError> {
    // the cl_init implementation isn't thread-safe, which is painful for tests
    static ONCE: Once = ONCE_INIT;
    static mut RESULT: ffi::cl_error = ffi::cl_error::CL_SUCCESS;
    unsafe {
        ONCE.call_once(|| {
            RESULT = ffi::cl_init(ffi::CL_INIT_DEFAULT);
            // this function always returns OK
            if RESULT == ffi::cl_error::CL_SUCCESS {
                ffi::cl_initialize_crypto();
                libc::atexit(cleanup);
            }
        });

        extern "C" fn cleanup() {
            unsafe {
                ffi::cl_cleanup_crypto();
            }
        }

        match RESULT {
            ffi::cl_error::CL_SUCCESS => Ok(()),
            _ => Err(ClamError::new(RESULT)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_success() {
        assert!(initialize().is_ok(), "initialize should succeed");
    }
}
