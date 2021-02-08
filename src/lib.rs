use std::sync::Once;

pub mod db;
pub mod engine;
mod error;
pub mod scan_settings;
pub mod version;
pub mod fmap;
#[cfg(windows)]
pub mod windows_fd;

pub use error::ClamError;

use clamav_sys::{
    cl_error_t,
    cl_init,
    cl_initialize_crypto,
};

/// Initializes clamav
///
/// This must be called once per process. This is safe to call multiple times.
pub fn initialize() -> Result<(), ClamError> {
    // the cl_init implementation isn't thread-safe, which is painful for tests
    static ONCE: Once = Once::new();
    static mut RESULT: cl_error_t = cl_error_t::CL_SUCCESS;
    unsafe {
        ONCE.call_once(|| {
            RESULT = cl_init(clamav_sys::CL_INIT_DEFAULT);
            // this function always returns OK
            if RESULT == cl_error_t::CL_SUCCESS {
                cl_initialize_crypto();
                libc::atexit(cleanup);
            }
        });

        extern "C" fn cleanup() {
            unsafe {
                clamav_sys::cl_cleanup_crypto();
            }
        }

        match RESULT {
            cl_error_t::CL_SUCCESS => Ok(()),
            _ => Err(ClamError::new(RESULT)),
        }
    }
}

pub fn version() -> String {
    let ver = unsafe {clamav_sys::cl_retver()};
    if ver == std::ptr::null() {
        "".to_string()
    }
    else {
        unsafe {
            std::ffi::CStr::from_ptr(ver).to_string_lossy().to_string()
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
