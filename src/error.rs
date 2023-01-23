use std::ffi::CStr;
use std::fmt;
use std::str;
use std::error;

use clamav_sys::cl_error_t;

/// An error indicating a clam failure.
#[derive(Clone, PartialEq, Eq)]
pub struct ClamError {
    code: cl_error_t,
}

impl ClamError {
    pub fn new(native_err: cl_error_t) -> Self {
        ClamError {
            code: native_err,
        }
    }

    pub fn string_error(&self) -> String {
        unsafe {
            let ptr = clamav_sys::cl_strerror(self.code);
            let bytes = CStr::from_ptr(ptr).to_bytes();
            str::from_utf8(bytes)
                .ok()
                .expect("Invalid UTF8 string")
                .to_string()
        }
    }

    pub fn code(&self) -> i32 {
        self.code as i32
    }
}

impl fmt::Display for ClamError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "cl_error {}: {}", self.code as i32, self.string_error())
    }
}

impl fmt::Debug for ClamError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl error::Error for ClamError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_as_string_success() {
        let err = ClamError::new(cl_error_t::CL_EFORMAT);
        let err_string = err.to_string();
        assert!(
            err_string.contains("CL_EFORMAT"),
            "error description should contain string error"
        );
    }
}
