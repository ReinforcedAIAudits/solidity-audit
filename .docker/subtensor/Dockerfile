FROM rust:1.72.0-alpine as builder

RUN apk add --no-cache make clang curl openssl-dev llvm libudev-zero-dev protobuf-dev git bash

# RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

RUN git clone https://github.com/opentensor/subtensor.git /subtensor

WORKDIR /subtensor

# RUN ./scripts/init.sh
RUN rustup target add x86_64-unknown-linux-musl 

RUN cargo build --workspace --profile=release --features "pow-faucet runtime-benchmarks fast-blocks" --manifest-path "/subtensor/Cargo.toml"

FROM scratch

WORKDIR /app

COPY --from=builder /subtensor/target/release/node-subtensor /app/target/release/node-subtensor
COPY --from=builder /subtensor/scripts/localnet.sh /app/scripts/localnet.sh

CMD ["BUILD_BINARY=0 ./scripts/localnet"]
