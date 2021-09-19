FROM rust:latest as build

# Create a new, blank, bin project that just happens
# to share the same dependencies as our actual project.
# This is a base caching layer.
RUN USER=root cargo new --bin ackreport
WORKDIR ./ackreport
COPY ./Cargo.toml ./Cargo.toml
COPY ./Cargo.lock ./Cargo.lock
RUN cargo build --release

# Clean up cargo new template rs.
RUN rm src/*.rs

# Add source
ADD . ./

# Cleanup any application targets that might have been
# built or copied.
RUN rm ./target/release/deps/ackreport*

# Build
RUN cargo build --release

# Install binary into smaller container
FROM debian:buster-slim
# TODO: install openssl certs
COPY --from=build ./ackreport/target/release/ackreport /usr/bin/ackreport
CMD ["/usr/bin/ackreport"]
