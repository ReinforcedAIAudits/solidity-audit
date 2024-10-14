FROM rust:1.72.0 as builder

RUN apt-get update && \
    apt-get install -y --assume-yes make build-essential git clang curl libssl-dev llvm libudev-dev protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

RUN git clone https://github.com/opentensor/subtensor.git /subtensor

WORKDIR /subtensor

RUN ./scripts/init.sh

RUN cargo build --workspace --profile=release --features "pow-faucet runtime-benchmarks fast-blocks" --manifest-path "/subtensor/Cargo.toml"

FROM alpine:3.17

WORKDIR /app

COPY --from=builder /subtensor/target/release/node-subtensor /app/target/release/node-subtensor
COPY --from=builder /subtensor/scripts/localnet.sh /app/scripts/localnet.sh

CMD ["sh", "-c", "BUILD_BINARY=0 ./scripts/localnet.sh"]
