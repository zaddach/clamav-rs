extern crate libc;

use std::ffi::CStr;
use std::fmt;
use std::str;

mod ffi;

/// An error indicating a clam failure.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClamError {
    code: i32,
}

impl ClamError {
    pub fn new(native_err: ffi::cl_error) -> Self {
        ClamError {
            code: native_err as i32,
        }
    }

    fn string_error(&self) -> String {
        unsafe {
            let ptr = ffi::cl_strerror(self.code);
            let bytes = CStr::from_ptr(ptr).to_bytes();
            str::from_utf8(bytes)
                .ok()
                .expect("Invalid UTF8 string")
                .to_string()
        }
    }
}

impl fmt::Display for ClamError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "cl_error {}: {}", self.code, self.string_error())
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_success() {
        assert!(initialize().is_ok(), "initialize should succeed");
    }

    #[test]
    fn error_as_string_success() {
        let err = ClamError::new(ffi::cl_error::CL_EFORMAT);
        let err_string = err.to_string();
        assert!(
            err_string.contains("CL_EFORMAT"),
            "error description should contain string error"
        );
    }
}
