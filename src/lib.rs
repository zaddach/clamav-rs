extern crate libc;

use std::ffi::CStr;
use std::ffi::CString;
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

/// Stats of a loaded database
pub struct DatabaseStats {
    /// The total number of loaded signatures
    pub signature_count: u32,
}

/// Engine used for scanning files
pub struct Engine {
    handle: *mut ffi::cl_engine,
}

impl Engine {
    /// Initialises the engine
    pub fn new() -> Self {
        unsafe {
            let handle = ffi::cl_engine_new();
            Engine { handle }
        }
    }

    /// Compiles the loaded database definitions
    ///
    /// This function will compile the database definitions loaded
    /// in this engine using the [`load_database`] function.
    ///
    /// # Examples
    ///
    /// ```
    /// use clamav;
    ///
    /// clamav::initialize().expect("failed to initialize");
    /// let engine = clamav::Engine::new();
    /// engine.compile().expect("failed to compile");
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if compliation fails.
    /// The [`ClamError`] returned will contain the error code.
    ///
    /// [`ClamError`]: struct.ClamError.html
    pub fn compile(&self) -> Result<(), ClamError> {
        unsafe {
            let result = ffi::cl_engine_compile(self.handle);
            match result {
                ffi::cl_error::CL_SUCCESS => Ok(()),
                _ => Err(ClamError::new(result)),
            }
        }
    }

    /// Loads all of the definition databases (*.{cud, cvd}) in the specified directory.
    ///
    /// This function will load the definitions that can then be compiled with [`compile`].
    ///
    /// # Examples
    ///
    /// ```
    /// use clamav;
    ///
    /// clamav::initialize().expect("failed to initialize");
    /// let engine = clamav::Engine::new();
    /// engine.load_databases("test_data/database/").expect("failed to load");
    /// engine.compile().expect("failed to compile");
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if compliation fails.
    /// The [`ClamError`] returned will contain the error code.
    ///
    /// [`ClamError`]: struct.ClamError.html
    pub fn load_databases(
        &self,
        database_directory_path: &str,
    ) -> Result<DatabaseStats, ClamError> {
        // consider the rust-ish builder pattern as it allows options to be specified
        let raw_path = CString::new(database_directory_path).unwrap();
        unsafe {
            let mut signature_count: u32 = 0;
            let result = ffi::cl_load(
                raw_path.as_ptr(),
                self.handle,
                &mut signature_count,
                ffi::CL_DB_STDOPT,
            );
            match result {
                ffi::cl_error::CL_SUCCESS => Ok(DatabaseStats { signature_count }),
                _ => Err(ClamError::new(result)),
            }
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            ffi::cl_engine_free(self.handle);
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

    #[test]
    fn compile_empty_engine_success() {
        let engine = Engine::new();
        assert!(engine.compile().is_ok(), "compile should succeed");
    }

    #[test]
    fn load_databases_success() {
        let engine = Engine::new();
        let result = engine.load_databases("test_data/database/");
        assert!(result.is_ok(), "load should succeed");
        assert!(
            result.unwrap().signature_count > 0,
            "should load some signatures"
        );
    }

    #[test]
    fn load_databases_with_file_success() {
        let engine = Engine::new();
        let result = engine.load_databases("test_data/database/example.cud");
        assert!(result.is_ok(), "load should succeed");
        assert!(
            result.unwrap().signature_count > 0,
            "should load some signatures"
        );
    }

    #[test]
    fn load_databases_fake_path_fails() {
        let engine = Engine::new();
        assert!(
            engine.load_databases("/dev/null").is_err(),
            "should fail to load invalid databases"
        );
    }

    #[test]
    fn default_database_directory_success() {
        assert!(
            default_database_directory().len() > 0,
            "should have a default db dir"
        );
    }
}
