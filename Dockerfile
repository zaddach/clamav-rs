FROM icebergdefender/clamav-slim

RUN freshclam

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        gcc \
        libc6-dev \
        ; \
    \
    curl https://sh.rustup.rs -sSf | sh -s -- -y --no-modify-path

# Clippy requires nightly for now
RUN rustup install nightly && cargo +nightly install clippy

WORKDIR /usr/local/src/rust-clamav
COPY src src
COPY test_data test_data
COPY tests tests
COPY Cargo.lock Cargo.toml ./