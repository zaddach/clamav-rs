fn main() {
    ::windows::build!(
        Windows::Win32::Storage::FileSystem::{
            ReadFile,
        },
        Windows::Win32::System::Diagnostics::Debug::{
           GetLastError,
        },
        Windows::Win32::System::Threading::{
            GetCurrentProcess,
        },
        Windows::Win32::System::WindowsProgramming::{
            DuplicateHandle,
        },
        Windows::Win32::System::WindowsProgramming::{
            DUPLICATE_SAME_ACCESS,
        },
        Windows::Win32::System::Diagnostics::Debug::{
            ERROR_HANDLE_EOF,
        },
        Windows::Win32::System::SystemServices::{
            INVALID_HANDLE_VALUE,
            OVERLAPPED,
            HANDLE,
        },
    );
}
