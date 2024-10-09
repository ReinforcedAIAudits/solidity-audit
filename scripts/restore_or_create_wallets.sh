#!/bin/bash

MNEMONIC_COLDKEY=$1
MNEMONIC_HOTKEY=$2
NAME=${3:-foo}

if [[ -z "$MNEMONIC_COLDKEY" -a -z "$MNEMONIC_HOTKEY" ]]; then
    btcli w create --name "$NAME" --no-use-password --quiet --wallet.path ~/.bittensor/wallets
    btcli w create --name "$NAME" --no-use-password --quiet --wallet.path ~/.bittensor/wallets
else
    btcli w regen_coldkey --mnemonic "$MNEMONIC_COLDKEY" --name "$NAME" --no-use-password --quiet --wallet.path /root/.bittensor/wallets
    btcli w regen_hotkey --mnemonic "$MNEMONIC_HOTKEY" --name "$NAME" --no-use-password --quiet --wallet.path /root/.bittensor/wallets
fi
