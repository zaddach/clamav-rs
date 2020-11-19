# rust-clamav
[![crates.io](https://img.shields.io/crates/v/clamav.svg)](https://crates.io/crates/clamav)

rust-clamav is a safe library for interacting with [libclamav](https://www.clamav.net) from Rust.
The low-level C API is wrapped in idomatic and safe Rust code.

# Documentation

 - [crates.io documentation](https://docs.rs/clamav/)

[bindgen](https://github.com/rust-lang-nursery/rust-bindgen) is not used to generate `src/ffi.rs` as the libclamav interface is relatively straight forward. This may change in future.

# Requirements

rust-clamav can be tested locally or via Docker.

## Docker

```
docker build -t rust-clamav . 
docker run -it rust-clamav cargo test
```

## Locally

### Rust

We currently target the latest stable release of Rust (1.26), and Cargo (1.26).

[clippy](https://github.com/rust-lang-nursery/rust-clippy) is used for linting, install with: `cargo +nightly install clippy`

### Linux
`libclamav.so.7` should be available on the `PATH` at runtime (or `LD_LIBRARY_PATH` if it lives somewhere non-standard).

Debian/Ubuntu minimal example:

`$ sudo apt install libclamav7`

### Freshclam

Freshclam can optionally be installed to keep the defintions in `/var/lib/clamav` up to date:

`$ sudo apt install clamav-freshclam`
