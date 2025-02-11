# Rust as the base image
FROM rust:1.75.0-slim as builder

# fix rust http openssl bug
RUN apt-get update \
    && apt-get install libssl-dev -y \ 
    && apt-get install pkg-config -y \ 
    && apt-get install protobuf-compiler -y

# Create a new empty shell project
RUN USER=root mkdir -p /server
WORKDIR /server

# Capture dependencies
COPY Cargo.toml Cargo.lock ./

# Build and cache the dependencies
RUN USER=root mkdir src && mkdir tests \
    && echo "fn main() {}" > src/main.rs \
    && echo "fn main() {}" > tests/test_api.rs \
    && echo "fn main() {}" > tests/test_ip_list.rs \
    && echo "fn main() {}" > tests/test_roles.rs

RUN cargo build --release

RUN rm src/main.rs

# Copy the source code
COPY src ./src
COPY proto ./proto
COPY sql ./sql
COPY build.rs ./

RUN cargo build --release

# The final base image
FROM debian:12.5-slim
WORKDIR /server

# Copy from the previous build
COPY --from=builder /server/target/release/server .
