FROM rust:1.87-bookworm AS builder

WORKDIR /build

# Install OpenSSL dev headers
RUN apt-get update && apt-get install -y libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock* ./
COPY crates/irc-proto/Cargo.toml crates/irc-proto/
COPY crates/irc-config/Cargo.toml crates/irc-config/
COPY crates/nefarious/Cargo.toml crates/nefarious/

# Create dummy source files so cargo can resolve deps
RUN mkdir -p crates/irc-proto/src && echo "pub fn _dummy() {}" > crates/irc-proto/src/lib.rs && \
    mkdir -p crates/irc-config/src && echo "pub fn _dummy() {}" > crates/irc-config/src/lib.rs && \
    mkdir -p crates/nefarious/src && echo "fn main() {}" > crates/nefarious/src/main.rs

# Build dependencies (cached unless Cargo.toml changes)
RUN cargo build --release 2>/dev/null || true

# Copy actual source
COPY crates/ crates/

# Force rebuild of our crates
RUN touch crates/*/src/*.rs

# Build for real
RUN cargo build --release

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1234 nefarious && useradd -u 1234 -g nefarious -m nefarious

COPY --from=builder /build/target/release/nefarious /usr/local/bin/nefarious

USER nefarious
WORKDIR /home/nefarious

ENTRYPOINT ["nefarious"]
CMD ["/home/nefarious/ircd.conf"]
