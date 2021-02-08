fn main() {
    ::windows::build!(
        windows::win32::debug::{
            GetLastError,
        }
        windows::win32::file_system::{
            ReadFile,
        }
        windows::win32::system_services::{
            ERROR_HANDLE_EOF,
            OVERLAPPED,
        }
    );
}
