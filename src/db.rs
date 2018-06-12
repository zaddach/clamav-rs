use std::ffi::CStr;
use std::str;

use ffi;

/// Gets the default database directory for clamav
pub fn default_directory() -> String {
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
    fn default_directory_success() {
        ::initialize().expect("initialize should succeed");
        assert!(
            default_directory().len() > 0,
            "should have a default db dir"
        );
    }
}
