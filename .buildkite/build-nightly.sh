#!/bin/bash
set -euo pipefail

cargo +nightly clippy
cargo +nightly build
cargo +nightly test