extern crate libc;

use std::ffi::CStr;
use std::str;

mod engine;
mod error;
mod ffi;
mod scan_settings;

pub use engine::*;
pub use error::*;
pub use scan_settings::*;

/// Initializes clamav
///
/// This must be called once per process
pub fn initialize() -> Result<(), ClamError> {
    unsafe {
        let result = ffi::cl_init(ffi::CL_INIT_DEFAULT);
        match result {
            ffi::cl_error::CL_SUCCESS => Ok(()),
            _ => Err(ClamError::new(result)),
        }
    }
}

/// Gets the default database directory for clamav
pub fn default_database_directory() -> String {
    unsafe {
        let ptr = ffi::cl_retdbdir();
        let bytes = CStr::from_ptr(ptr).to_bytes();
        str::from_utf8(bytes)
            .ok()
            .expect("Invalid UTF8 string")
            .to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_success() {
        assert!(initialize().is_ok(), "initialize should succeed");
    }

    #[test]
    fn default_database_directory_success() {
        initialize().expect("initialize should succeed");
        assert!(
            default_database_directory().len() > 0,
            "should have a default db dir"
        );
    }
}
