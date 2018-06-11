extern crate libc;

use std::ffi::CStr;
use std::ffi::CString;
use std::fmt;
use std::ptr;
use std::str;

mod ffi;
mod scan_settings;

pub type ScanSettings = scan_settings::ScanSettings;
pub type ScanSettingsBuilder = scan_settings::ScanSettingsBuilder;

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

pub enum ScanResult {
    /// Clean result, checked against *N* signatures
    Clean(u64),
    /// Whitelisted result, checked against *N* signatures
    Whitelisted(u64),
    /// Virus result, checked against *N* signatured with detected name
    Virus(u64, String),
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

    /// Scans a file with the previously loaded and compiled definitions.
    ///
    /// This function will scan the given file with the the database definitions
    /// loaded and compiled.
    ///
    /// # Examples
    ///
    /// ```
    /// use clamav::{ScanResult, ScanSettings};
    ///
    /// clamav::initialize().expect("failed to initialize");
    /// let engine = clamav::Engine::new();
    /// engine.load_databases("test_data/database/").expect("failed to load");
    /// engine.compile().expect("failed to compile");
    ///
    /// let settings: ScanSettings = Default::default();
    /// let hit = engine.scan_file("test_data/files/good_file", &settings).expect("expected scan to succeed");
    ///
    /// match hit {
    ///     ScanResult::Virus(count, name) => println!("Virus {}, checked {} sigs", count, name),
    ///     ScanResult::Clean(count) => println!("Clean checked {} sigs", count),
    ///     ScanResult::Whitelisted(count) => println!("Whitelisted file w/{} sigs", count)
    /// }
    /// ```
    ///
    /// ```
    /// use clamav::{ScanResult, ScanSettingsBuilder};
    ///
    /// clamav::initialize().expect("failed to initialize");
    /// let engine = clamav::Engine::new();
    /// engine.load_databases("test_data/database/").expect("failed to load");
    /// engine.compile().expect("failed to compile");
    ///
    /// let settings = ScanSettingsBuilder::new()
    ///     .enable_pdf()
    ///     .block_broken_executables()
    ///     .build();
    /// println!("Using settings {}", settings);
    /// let hit = engine.scan_file("test_data/files/good_file", &settings).expect("expected scan to succeed");
    ///
    /// match hit {
    ///     ScanResult::Virus(count, name) => println!("Virus {}, checked {} sigs", count, name),
    ///     ScanResult::Clean(count) => println!("Clean checked {} sigs", count),
    ///     ScanResult::Whitelisted(count) => println!("Whitelisted file w/{} sigs", count)
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if the scan fails.
    /// The [`ClamError`] returned will contain the error code.
    ///
    /// [`ClamError`]: struct.ClamError.html
    pub fn scan_file(
        &self,
        path: &str,
        settings: &scan_settings::ScanSettings,
    ) -> Result<ScanResult, ClamError> {
        let raw_path = CString::new(path).unwrap();
        unsafe {
            let mut virname: *const i8 = ptr::null();
            let mut scanned: u64 = 0;
            let result = ffi::cl_scanfile(
                raw_path.as_ptr(),
                &mut virname,
                &mut scanned,
                self.handle,
                settings.flags(),
            );
            match result {
                ffi::cl_error::CL_CLEAN => Ok(ScanResult::Clean(scanned)),
                ffi::cl_error::CL_BREAK => Ok(ScanResult::Whitelisted(scanned)),
                ffi::cl_error::CL_VIRUS => {
                    let bytes = CStr::from_ptr(virname).to_bytes();
                    let name = str::from_utf8(bytes).ok().unwrap_or_default().to_string();
                    Ok(ScanResult::Virus(scanned, name))
                }
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

    const TEST_DATABASES_PATH: &'static str = "test_data/database/";
    const EXAMPLE_DATABASE_PATH: &'static str = "test_data/database/example.cud";
    const GOOD_FILE_PATH: &'static str = "test_data/files/good_file";
    const NAUGHTY_FILE_PATH: &'static str = "test_data/files/naughty_file";

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
        let result = engine.load_databases(TEST_DATABASES_PATH);
        assert!(result.is_ok(), "load should succeed");
        assert!(
            result.unwrap().signature_count > 0,
            "should load some signatures"
        );
    }

    #[test]
    fn load_databases_with_file_success() {
        let engine = Engine::new();
        let result = engine.load_databases(EXAMPLE_DATABASE_PATH);
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

    #[test]
    fn scan_naughty_file_matches() {
        let engine = Engine::new();
        engine
            .load_databases(EXAMPLE_DATABASE_PATH)
            .expect("failed to load db");
        engine.compile().expect("failed to compile");
        let settings: scan_settings::ScanSettings = Default::default();
        let result = engine.scan_file(NAUGHTY_FILE_PATH, &settings);
        assert!(result.is_ok(), "scan should succeed");
        let hit = result.unwrap();
        match hit {
            ScanResult::Virus(_count, name) => {
                assert_eq!(name, "naughty_file.UNOFFICIAL");
            }
            _ => panic!("should have matched as a virus"),
        }
    }

    #[test]
    fn scan_good_file_success() {
        let engine = Engine::new();
        engine
            .load_databases(EXAMPLE_DATABASE_PATH)
            .expect("failed to load db");
        engine.compile().expect("failed to compile");
        let settings: scan_settings::ScanSettings = Default::default();
        let result = engine.scan_file(GOOD_FILE_PATH, &settings);
        assert!(result.is_ok(), "scan should succeed");
        let hit = result.unwrap();
        match hit {
            ScanResult::Clean(_count) => {}
            _ => panic!("should have matched as a virus"),
        }
    }
}
