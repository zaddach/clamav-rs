#![allow(non_camel_case_types, dead_code)]

use libc::{c_char, c_int, c_uint, c_void};

pub const CL_INIT_DEFAULT: u32 = 0x0;

pub type cl_engine = c_void;

// :libclamav.so.7 as opposed to clamav as libclamav.so may not exist
#[link(name = ":libclamav.so.7")]
extern "C" {
    pub fn cl_init(initOptions: c_uint) -> cl_error;
    pub fn cl_strerror(clerror: c_int) -> *const c_char;

    // engine
    pub fn cl_engine_new() -> *mut cl_engine;
    pub fn cl_engine_free(engine: *mut cl_engine) -> cl_error;
    pub fn cl_engine_compile(engine: *mut cl_engine) -> cl_error;
}

#[repr(C)]
#[derive(PartialEq, Debug)]
pub enum cl_error {
    /* libclamav specific */
    /* CL_CLEAN = 0, */
    CL_SUCCESS = 0,
    CL_VIRUS,
    CL_ENULLARG,
    CL_EARG,
    CL_EMALFDB,
    CL_ECVD,
    CL_EVERIFY,
    CL_EUNPACK,

    /* I/O and memory errors */
    CL_EOPEN,
    CL_ECREAT,
    CL_EUNLINK,
    CL_ESTAT,
    CL_EREAD,
    CL_ESEEK,
    CL_EWRITE,
    CL_EDUP,
    CL_EACCES,
    CL_ETMPFILE,
    CL_ETMPDIR,
    CL_EMAP,
    CL_EMEM,
    CL_ETIMEOUT,

    /* internal (not reported outside libclamav) */
    CL_BREAK,
    CL_EMAXREC,
    CL_EMAXSIZE,
    CL_EMAXFILES,
    CL_EFORMAT,
    CL_EPARSE,
    CL_EBYTECODE,          /* may be reported in testmode */
    CL_EBYTECODE_TESTFAIL, /* may be reported in testmode */

    /* c4w error codes */
    CL_ELOCK,
    CL_EBUSY,
    CL_ESTATE,

    /* no error codes below this line please */
    CL_ELAST_ERROR,
}

impl cl_error {
    // CL_CLEAN has the same value as CL_SUCCESS, which Rust does not yet support
    pub const CL_CLEAN: cl_error = cl_error::CL_SUCCESS;
}
