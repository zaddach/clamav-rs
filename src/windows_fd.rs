use std::io;
use std::mem;
use std::os::raw;

extern {
    // https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/open-osfhandle?view=msvc-160
    fn _open_osfhandle(osfhandle: isize, flags: raw::c_int) -> raw::c_int;

    // https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/close?view=msvc-160
    fn _close(fd: raw::c_int) -> raw::c_int;
}

pub const _O_RDONLY: raw::c_int = 0;

pub struct WindowsFd(i32);

impl WindowsFd {
    pub fn new(handle: std::os::windows::io::RawHandle) -> io::Result<WindowsFd> {
        unsafe {
            let fd = _open_osfhandle(mem::transmute(handle), _O_RDONLY);
            if fd == -1 {
                Err(io::Error::new(io::ErrorKind::InvalidInput, "Error converting Windows HANDLE to file descriptor"))
            }
            else {
                Ok(WindowsFd(fd))
            }
        }
    }

    pub fn raw(& self) -> i32 {
        self.0
    }
}



impl Drop for WindowsFd {
    fn drop(& mut self) {
        unsafe {
            let _ = _close(self.0);
        }
    }
}
