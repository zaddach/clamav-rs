#!/bin/bash
set -euo pipefail

cargo +nightly clippy
cargo build
cargo test