//
// Copyright (C) 2020 Jonas Zaddach.
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
// MA 02110-1301, USA.

use std::ffi::{
    c_void,
};
use std::fmt;
use std::result;

use clamav_sys::{
    cl_fmap_t,
    cl_fmap_open_memory,
    cl_fmap_close,
};

#[derive(Debug, Clone)]
pub struct MapError;

impl fmt::Display for MapError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Failed to open mapping")
    }
}

impl MapError {
    pub fn new() -> MapError { MapError{} }
}

pub type Result<T> = result::Result<T, MapError>;

pub trait Fmap {
    fn get_map(&self) -> *mut cl_fmap_t;
}


#[allow(dead_code)]
pub struct MemoryFmap {
    map: *mut cl_fmap_t,
}

impl MemoryFmap {
    pub fn new(start: *const u8, len: u64) -> Result< MemoryFmap > {
        let map = unsafe { cl_fmap_open_memory(start as *const c_void, len) };
        if map.is_null() {
            Err(MapError::new())
        }
        else {
            Ok(MemoryFmap {map})
        }
    }
}

impl Drop for MemoryFmap {
    fn drop(&mut self) -> () {
        unsafe {cl_fmap_close(self.map)};
    }
}

impl Fmap for MemoryFmap {
    fn get_map(& self) -> *mut cl_fmap_t {self.map}
}
