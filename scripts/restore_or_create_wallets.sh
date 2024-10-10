#!/bin/bash

MNEMONIC_COLDKEY=$1
MNEMONIC_HOTKEY=$2
NAME=$3

if [[ -z "$MNEMONIC_COLDKEY" && -z "$MNEMONIC_HOTKEY" && -z "$NAME" ]]; then
    echo "some arg are null"
    echo "coldkey: $MNEMONIC_COLDKEY"
    echo "hotkey: $MNEMONIC_HOTKEY"
    echo "name: $NAME"
    btcli w create --name "$NAME" --no-use-password --quiet --wallet.path ~/.bittensor/wallets
    btcli w create --name "$NAME" --no-use-password --quiet --wallet.path ~/.bittensor/wallets
else
    btcli w regen_coldkey --mnemonic "$MNEMONIC_COLDKEY" --name "$NAME" --no-use-password --quiet --wallet.path ~/.bittensor/wallets
    btcli w regen_hotkey --mnemonic "$MNEMONIC_HOTKEY" --name "$NAME" --hotkey default --no-use-password --quiet --wallet.path ~/.bittensor/wallets
fi
