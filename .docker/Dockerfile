# Используем официальный образ Rust
FROM rust:1.70

# Устанавливаем необходимые зависимости
RUN apt-get update && \
    apt-get install -y --assume-yes make build-essential git clang curl libssl-dev llvm libudev-dev protobuf-compiler && \
    rm -rf /var/lib/apt/lists/*

# Устанавливаем Rust и Cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Клонируем репозиторий subtensor
RUN git clone https://github.com/opentensor/subtensor.git /subtensor

# Устанавливаем рабочую директорию
WORKDIR /subtensor

# Настраиваем Rust
RUN ./scripts/init.sh

# Запускаем локальную сеть
CMD ["sh", "-c", "./scripts/localnet.sh", "&", "python", "utils/init_solochain.py"]
