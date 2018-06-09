extern crate libc;

mod ffi;

/// An error indicating a clam failure.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ClamError {
    code: u32,
}

impl ClamError {
    pub fn new(native_err: ffi::cl_error) -> Self {
        ClamError {
            code: native_err as u32,
        }
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
}
