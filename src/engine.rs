use std::ffi::CStr;
use std::ffi::CString;
use std::ptr;
use std::str;
use std::mem;
use std::time;
use std::os::raw::{c_ulong, c_int};

use clamav_sys::{
    cl_engine_field,
    cl_engine_get_num,
    cl_engine_get_str,
    cl_engine_set_num,
    cl_engine_set_str,
    cl_error_t,
    cl_load,
    time_t,
    CL_DB_STDOPT,
};


use crate::error::ClamError;
use crate::scan_settings::ScanSettings;
use crate::fmap::Fmap;
#[cfg(windows)]
use crate::windows_fd::WindowsFd;

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

#[derive(Debug, PartialEq)]
pub enum EngineValueType {
    U32,
    U64,
    String,
    Time,
}

pub struct ClamTime(time_t);

impl ClamTime {
    pub fn as_system_time(&self) -> time::SystemTime {
        if self.0 >= 0 {
            time::UNIX_EPOCH + time::Duration::from_secs(self.0 as u64)
        }
        else {
            time::UNIX_EPOCH - time::Duration::from_secs((self.0 * -1) as u64)
        }
    }
}



pub enum EngineValue {
    U32(u32),
    U64(u64),
    String(String),
    Time(ClamTime),
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
    pub fn scan_fileobj<T: std::os::unix::io::AsRawFd>(&self, file: &T, settings: &mut ScanSettings, filename: Option< &str >) -> Result<ScanResult, ClamError>
    {
        self.scan_descriptor(file.as_raw_fd(), settings, filename)
    }

    #[cfg(windows)]
    pub fn scan_fileobj<T: std::os::windows::io::AsRawHandle>(&self, file: &T, settings: &mut ScanSettings, filename: Option< &str >) -> Result<ScanResult, ClamError> {
        let fd = WindowsFd::new(file.as_raw_handle()).map_err(|_| ClamError::new(cl_error_t::CL_EARG))?; 
        self.scan_descriptor(fd.raw(), settings, filename)
    }

    /// @brief Scan custom data.
    /// @param map           Buffer to be scanned, in form of a cl_fmap_t.
    /// @param filename      Name of data origin. Does not need to be an actual
    ///                      file on disk. May be None if a name is not available.
    /// @param engine        The scanning engine.
    /// @param scanoptions   The scanning options.
    pub fn scan_map(&self, map : & Fmap, filename: Option<&str>, settings: &mut ScanSettings) -> Result<ScanResult, ClamError> {
        let mut virname: *const i8 = ptr::null();
        let c_filename = filename.map(|n| CString::new(n).expect("CString::new failed"));
        let result = unsafe {
            clamav_sys::cl_scanmap_callback(
                map.raw(),
                c_filename.map_or(ptr::null(), |n| n.as_ptr()),
                &mut virname,
                ptr::null_mut(),
                self.handle,
                &mut settings.settings,
                ptr::null_mut())
        };
        map_scan_result(result, virname)
    }

    fn get(&self, field: cl_engine_field) -> Result<EngineValue, ClamError> {
        unsafe {
            match get_field_type(field) {
                EngineValueType::U32 => {
                    let mut err: c_int = 0;
                    let value = cl_engine_get_num(self.handle, field, &mut err) as u32;
                    if err != 0 {
                        Err(ClamError::new(mem::transmute(err)))
                    }
                    else {
                        Ok(EngineValue::U32(value))
                    }
                },
                EngineValueType::U64 => {
                    let mut err: c_int = 0;
                    let value = cl_engine_get_num(self.handle, field, &mut err) as u64;
                    if err != 0 {
                        Err(ClamError::new(mem::transmute(err)))
                    }
                    else {
                        Ok(EngineValue::U64(value))
                    }
                },
                EngineValueType::String => {
                    let mut err = 0;
                    let value = cl_engine_get_str(self.handle, field, &mut err);
                    if err != 0 {
                        Err(ClamError::new(mem::transmute(err)))
                    }
                    else {
                        Ok(EngineValue::String(CStr::from_ptr(value).to_str().unwrap().to_string()))
                    }
                },
                EngineValueType::Time => {
                    let mut err = 0;
                    let value = cl_engine_get_num(self.handle, field, &mut err) as time_t;
                    if err != 0 {
                        Err(ClamError::new(mem::transmute(err)))
                    }
                    else {
                        Ok(EngineValue::Time(ClamTime(value)))
                    }
                },
            }
        }
    }

    fn set(&self, field: cl_engine_field, value: EngineValue) -> Result<(), ClamError> {
        let expected_type = get_field_type(field);
        let actual_type = match &value {
            EngineValue::U32(_) => EngineValueType::U32,
            EngineValue::U64(_) => EngineValueType::U64,
            EngineValue::String(_) => EngineValueType::String,
            EngineValue::Time(_) => EngineValueType::Time,
        };

        if expected_type != actual_type {
            return Err(ClamError::new(cl_error_t::CL_EARG));
        }

        unsafe {
            match value {
                EngineValue::U32(val) => {
                    let err = cl_engine_set_num(self.handle, field, val as i64);
                    if err != cl_error_t::CL_SUCCESS {
                        Err(ClamError::new(err))
                    }
                    else {
                        Ok(())
                    }
                },
                EngineValue::U64(val) => {
                    let err = cl_engine_set_num(self.handle, field, val as i64);
                    if err != cl_error_t::CL_SUCCESS {
                        Err(ClamError::new(err))
                    }
                    else {
                        Ok(())
                    }
                },
                EngineValue::String(val) => {
                    let val = CString::new(val).unwrap();
                    let err = cl_engine_set_str(self.handle, field, val.as_ptr());
                    if err != cl_error_t::CL_SUCCESS {
                        Err(ClamError::new(err))
                    }
                    else {
                        Ok(())
                    }
                },
                EngineValue::Time(ClamTime(val)) => {
                    let err = cl_engine_set_num(self.handle, field, val as i64);
                    if err != cl_error_t::CL_SUCCESS {
                        Err(ClamError::new(err))
                    }
                    else {
                        Ok(())
                    }
                },
            }
        }
    }

    pub fn database_version(&self) -> Result<u32, ClamError> {
        if let EngineValue::U32(value) = self.get(cl_engine_field::CL_ENGINE_DB_VERSION)? {
            Ok(value)
        }
        else {
            Err(ClamError::new(cl_error_t::CL_EARG))
        }
    }

    pub fn database_timestamp(&self) -> Result<time::SystemTime, ClamError> {
        if let EngineValue::Time(value) = self.get(cl_engine_field::CL_ENGINE_DB_TIME)? {
            Ok(value.as_system_time())
        }
        else {
            Err(ClamError::new(cl_error_t::CL_EARG))
        }
    }

}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            clamav_sys::cl_engine_free(self.handle);
        }
    }
}


fn get_field_type(field: cl_engine_field) -> EngineValueType {
    match field {
        cl_engine_field::CL_ENGINE_MAX_SCANSIZE => EngineValueType::U64,
        cl_engine_field::CL_ENGINE_MAX_FILESIZE => EngineValueType::U64,
        cl_engine_field::CL_ENGINE_MAX_RECURSION => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_MAX_FILES => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_MIN_CC_COUNT => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_MIN_SSN_COUNT => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_PUA_CATEGORIES => EngineValueType::String,
        cl_engine_field::CL_ENGINE_DB_OPTIONS => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_DB_VERSION => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_DB_TIME => EngineValueType::Time,
        cl_engine_field::CL_ENGINE_AC_ONLY => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_AC_MINDEPTH => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_AC_MAXDEPTH => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_TMPDIR => EngineValueType::String,
        cl_engine_field::CL_ENGINE_KEEPTMP => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_BYTECODE_SECURITY => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_BYTECODE_TIMEOUT => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_BYTECODE_MODE => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_MAX_EMBEDDEDPE => EngineValueType::U64,
        cl_engine_field::CL_ENGINE_MAX_HTMLNORMALIZE => EngineValueType::U64,
        cl_engine_field::CL_ENGINE_MAX_HTMLNOTAGS => EngineValueType::U64,
        cl_engine_field::CL_ENGINE_MAX_SCRIPTNORMALIZE => EngineValueType::U64,
        cl_engine_field::CL_ENGINE_MAX_ZIPTYPERCG => EngineValueType::U64,
        cl_engine_field::CL_ENGINE_FORCETODISK => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_DISABLE_CACHE => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_DISABLE_PE_STATS => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_STATS_TIMEOUT => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_MAX_PARTITIONS => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_MAX_ICONSPE => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_MAX_RECHWP3 => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_MAX_SCANTIME => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_PCRE_MATCH_LIMIT => EngineValueType::U64,
        cl_engine_field::CL_ENGINE_PCRE_RECMATCH_LIMIT => EngineValueType::U64,
        cl_engine_field::CL_ENGINE_PCRE_MAX_FILESIZE => EngineValueType::U64,
        cl_engine_field::CL_ENGINE_DISABLE_PE_CERTS => EngineValueType::U32,
        cl_engine_field::CL_ENGINE_PE_DUMPCERTS => EngineValueType::U32,
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
