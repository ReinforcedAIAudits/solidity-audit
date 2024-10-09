FROM python:3.11-slim

ARG MNEMONIC_COLDKEY
ARG MNEMONIC_HOTKEY
ARG WALLET_NAME
RUN apt-get update && apt-get install -y git
WORKDIR /app


COPY . /app

RUN pip install -e .
RUN pip install bittensor-cli

RUN scripts/restore_or_create_wallets.sh MNEMONIC_COLDKEY MNEMONIC_HOTKEY WALLET_NAME