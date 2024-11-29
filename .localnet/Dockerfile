FROM ubuntu:22.04 as builder

ARG BRANCH=v1.1.6

RUN apt-get update && \
    apt-get install -y --assume-yes make build-essential git clang curl libssl-dev llvm libudev-dev protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ENV PATH="/root/.cargo/bin:${PATH}"

RUN git clone --branch $BRANCH https://github.com/opentensor/subtensor.git /subtensor

WORKDIR /subtensor

RUN ./scripts/init.sh

RUN cargo build --workspace --profile=release \
    --features "pow-faucet runtime-benchmarks fast-blocks" \
    --manifest-path "/subtensor/Cargo.toml" -p node-subtensor

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --assume-yes procps

WORKDIR /app

COPY --from=builder /subtensor/target/release/node-subtensor /app/target/release/node-subtensor
COPY ./scripts/docker_localnet.sh /app/scripts/localnet.sh
ENV BUILD_BINARY=0
EXPOSE 9944
CMD ["./scripts/localnet.sh"]
