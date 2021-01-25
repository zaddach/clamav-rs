use std::ffi::CStr;
use std::ffi::CString;
use std::ptr;
use std::str;
use std::os::raw::c_ulong;

use clamav_sys::{
    cl_error_t,
    cl_load,
    CL_DB_STDOPT,
};


use crate::error::ClamError;
use crate::scan_settings::ScanSettings;
use crate::fmap::Fmap;

/// Stats of a loaded database
pub struct DatabaseStats {
    /// The total number of loaded signatures
    pub signature_count: u32,
}

pub enum ScanResult {
    /// Clean result
    Clean,
    /// Whitelisted result
    Whitelisted,
    /// Virus result, with detected name
    Virus(String),
}

/// Engine used for scanning files
pub struct Engine {
    handle: *mut clamav_sys::cl_engine,
}

unsafe impl Send for Engine {}
unsafe impl Sync for Engine {}

fn map_scan_result(result: cl_error_t, virname: *const i8) -> Result<ScanResult, ClamError> {
    match result {
        cl_error_t::CL_CLEAN => Ok(ScanResult::Clean),
        cl_error_t::CL_BREAK => Ok(ScanResult::Whitelisted),
        cl_error_t::CL_VIRUS => {
            unsafe {
                let bytes = CStr::from_ptr(virname).to_bytes();
                let name = str::from_utf8(bytes).ok().unwrap_or_default().to_string();
                Ok(ScanResult::Virus(name))
            }
        }
        _ => Err(ClamError::new(result)),
    }
}

impl Engine {
    /// Initialises the engine
    pub fn new() -> Self {
        unsafe {
            let handle = clamav_sys::cl_engine_new();
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
    /// use clamav::{engine};
    ///
    /// clamav::initialize().expect("failed to initialize");
    /// let scanner = engine::Engine::new();
    /// scanner.compile().expect("failed to compile");
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
            let result = clamav_sys::cl_engine_compile(self.handle);
            match result {
                cl_error_t::CL_SUCCESS => Ok(()),
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
    /// use clamav::{engine};
    ///
    /// clamav::initialize().expect("failed to initialize");
    /// let scanner = engine::Engine::new();
    /// scanner.load_databases("test_data/database/").expect("failed to load");
    /// scanner.compile().expect("failed to compile");
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
            let result = cl_load(
                raw_path.as_ptr(),
                self.handle,
                &mut signature_count,
                CL_DB_STDOPT,
            );
            match result {
                cl_error_t::CL_SUCCESS => Ok(DatabaseStats { signature_count }),
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
    /// use clamav::{engine, engine::ScanResult, scan_settings::ScanSettings};
    ///
    /// clamav::initialize().expect("failed to initialize");
    /// let scanner = engine::Engine::new();
    /// scanner.load_databases("test_data/database/").expect("failed to load");
    /// scanner.compile().expect("failed to compile");
    ///
    /// let settings: ScanSettings = Default::default();
    /// let hit = scanner.scan_file("test_data/files/good_file", &settings).expect("expected scan to succeed");
    ///
    /// match hit {
    ///     ScanResult::Virus(name) => println!("Virus {}", name),
    ///     ScanResult::Clean => println!("Clean"),
    ///     ScanResult::Whitelisted => println!("Whitelisted file")
    /// }
    /// ```
    ///
    /// ```
    /// use clamav::{engine, engine::ScanResult, scan_settings::ScanSettingsBuilder};
    ///
    /// clamav::initialize().expect("failed to initialize");
    /// let scanner = engine::Engine::new();
    /// scanner.load_databases("test_data/database/").expect("failed to load");
    /// scanner.compile().expect("failed to compile");
    ///
    /// let settings = ScanSettingsBuilder::new()
    ///     .enable_pdf()
    ///     .block_broken_executables()
    ///     .build();
    /// println!("Using settings {}", settings);
    /// let hit = scanner.scan_file("test_data/files/good_file", &settings).expect("expected scan to succeed");
    ///
    /// match hit {
    ///     ScanResult::Virus(name) => println!("Virus {}", name),
    ///     ScanResult::Clean => println!("Clean"),
    ///     ScanResult::Whitelisted => println!("Whitelisted file")
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// This function will return an error if the scan fails.
    /// The [`ClamError`] returned will contain the error code.
    ///
    /// [`ClamError`]: struct.ClamError.html
    pub fn scan_file(&self, path: &str, settings: &mut ScanSettings) -> Result<ScanResult, ClamError> {
        let raw_path = CString::new(path).unwrap();
        unsafe {
            let mut virname: *const i8 = ptr::null();
            let result = clamav_sys::cl_scanfile(
                raw_path.as_ptr(),
                &mut virname,
                ptr::null_mut(),
                self.handle,
                &mut settings.settings,
            );
            map_scan_result(result, virname)
        }
    }

    /// Scans a descriptor with the previously loaded and compiled definitions.
    ///
    /// This function will scan the given descriptor with the the database definitions
    /// loaded and compiled.
    pub fn scan_descriptor(&self, descriptor: i32, settings: &mut ScanSettings, filename: Option< &str >) -> Result<ScanResult, ClamError> {
        unsafe {
            let mut virname: *const i8 = ptr::null();
            let filename_cstr = filename.map(|x| CString::new(x).expect("CString::new failed"));
            let mut scanned : c_ulong = 0;
            let result = clamav_sys::cl_scandesc(
                descriptor,
                filename_cstr.map_or(ptr::null(), |x| x.as_ptr()),
                &mut virname,
                &mut scanned,
                self.handle,
                &mut settings.settings,
            );
            map_scan_result(result, virname)
        }
    }

    #[cfg(unix)]
    pub fn scan_fileobj(&self, file: &std::fs::File, settings: &mut ScanSettings, filename: Option< &str >) -> Result<ScanResult, ClamError> {
        use std::os::unix::io::AsRawFd;
        self.scan_descriptor(file.as_raw_fd(), settings, filename)
    }

    #[cfg(windows)]
    pub fn scan_fileobj(&self, file: &std::fs::File, settings: &mut ScanSettings, filename: Option< &str >) -> Result<ScanResult, ClamError> {
        use std::os::windows::io::AsRawHandle;
        self.scan_descriptor(file.as_raw_handle() as i32, settings, filename)
    }

    /// @brief Scan custom data.
    /// @param map           Buffer to be scanned, in form of a cl_fmap_t.
    /// @param filename      Name of data origin. Does not need to be an actual
    ///                      file on disk. May be None if a name is not available.
    /// @param engine        The scanning engine.
    /// @param scanoptions   The scanning options.
    pub fn scan_map(&self, map : &dyn Fmap, filename: Option<&str>, settings: &mut ScanSettings) -> Result<ScanResult, ClamError> {
        let mut virname: *const i8 = ptr::null();
        let c_filename = filename.map(|n| CString::new(n).expect("CString::new failed"));
        let result = unsafe {
            clamav_sys::cl_scanmap_callback(
                map.get_map(),
                c_filename.map_or(ptr::null(), |n| n.as_ptr()),
                &mut virname,
                ptr::null_mut(),
                self.handle,
                &mut settings.settings,
                ptr::null_mut())
        };
        map_scan_result(result, virname)
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            clamav_sys::cl_engine_free(self.handle);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    const TEST_DATABASES_PATH: &'static str = "test_data/database/";
    const EXAMPLE_DATABASE_PATH: &'static str = "test_data/database/example.cud";
    const GOOD_FILE_PATH: &'static str = "test_data/files/good_file";
    const NAUGHTY_FILE_PATH: &'static str = "test_data/files/naughty_file";

    #[test]
    fn compile_empty_engine_success() {
        crate::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        assert!(scanner.compile().is_ok(), "compile should succeed");
    }

    #[test]
    fn load_databases_success() {
        crate::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        let result = scanner.load_databases(TEST_DATABASES_PATH);
        assert!(result.is_ok(), "load should succeed");
        assert!(
            result.unwrap().signature_count > 0,
            "should load some signatures"
        );
    }

    #[test]
    fn load_databases_with_file_success() {
        crate::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        let result = scanner.load_databases(EXAMPLE_DATABASE_PATH);
        assert!(result.is_ok(), "load should succeed");
        assert!(
            result.unwrap().signature_count > 0,
            "should load some signatures"
        );
    }

    #[test]
    fn load_databases_fake_path_fails() {
        crate::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        assert!(
            scanner.load_databases("/dev/null").is_err(),
            "should fail to load invalid databases"
        );
    }

    #[test]
    fn scan_naughty_file_matches() {
        crate::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        scanner
            .load_databases(EXAMPLE_DATABASE_PATH)
            .expect("failed to load db");
        scanner.compile().expect("failed to compile");
        let mut settings: ScanSettings = Default::default();
        let result = scanner.scan_file(NAUGHTY_FILE_PATH, &mut settings);
        assert!(result.is_ok(), "scan should succeed");
        let hit = result.unwrap();
        match hit {
            ScanResult::Virus(name) => {
                assert_eq!(name, "naughty_file.UNOFFICIAL");
            }
            _ => panic!("should have matched as a virus"),
        }
    }

    #[test]
    fn scan_good_file_success() {
        crate::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        scanner
            .load_databases(EXAMPLE_DATABASE_PATH)
            .expect("failed to load db");
        scanner.compile().expect("failed to compile");
        let mut settings: ScanSettings = Default::default();
        let result = scanner.scan_file(GOOD_FILE_PATH, &mut settings);
        assert!(result.is_ok(), "scan should succeed");
        let hit = result.unwrap();
        match hit {
            ScanResult::Clean => {}
            _ => panic!("should have matched as a virus"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn scan_naughty_fd_matches() {
        crate::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        scanner
            .load_databases(EXAMPLE_DATABASE_PATH)
            .expect("failed to load db");
        scanner.compile().expect("failed to compile");
        let settings: ScanSettings = Default::default();
        let file = File::open(NAUGHTY_FILE_PATH).unwrap();
        let result = scanner.scan_fileobj(&file, &settings);
        assert!(result.is_ok(), "scan should succeed");
        let hit = result.unwrap();
        match hit {
            ScanResult::Virus(name) => {
                assert_eq!(name, "naughty_file.UNOFFICIAL");
            }
            _ => panic!("should have matched as a virus"),
        }
    }

    #[test]
    fn scan_good_fd_success() {
        crate::initialize().expect("initialize should succeed");
        let scanner = Engine::new();
        scanner
            .load_databases(EXAMPLE_DATABASE_PATH)
            .expect("failed to load db");
        scanner.compile().expect("failed to compile");
        let mut settings: ScanSettings = Default::default();
        let file = File::open(GOOD_FILE_PATH).unwrap();
        let result = scanner.scan_fileobj(&file, &mut settings, Some(GOOD_FILE_PATH));
        assert!(result.is_ok(), "scan should succeed");
        let hit = result.unwrap();
        match hit {
            ScanResult::Clean => {}
            _ => panic!("should have matched as a virus"),
        }
    }
}
