FROM rust:1.70

RUN apt-get update && \
    apt-get install -y --assume-yes make build-essential git clang curl libssl-dev llvm libudev-dev protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

RUN git clone https://github.com/opentensor/subtensor.git /subtensor

WORKDIR /subtensor

RUN ./scripts/init.sh

RUN cargo build -p node-subtensor --profile production --features pow-faucet

CMD ["sh", "-c", "BUILD_BINARY=0 ./scripts/localnet.sh"]
