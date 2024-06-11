# Rust as the base image
FROM rust:1.75.0-slim as builder

# fix rust http openssl bug
RUN apt-get update \
    && apt-get install libssl-dev \ 
    && apt-get install pkg-config -y \ 
    && apt-get install protobuf-compiler -y

# Create a new empty shell project
RUN USER=root mkdir -p /server
WORKDIR /server

# Copy all directories and files
COPY . .

# Build the project
RUN cargo build --release

# The final base image
FROM debian:12.5-slim
WORKDIR /server

# Copy from the previous build
COPY --from=builder /server/target/release/server .