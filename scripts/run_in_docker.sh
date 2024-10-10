#!/bin/bash

./scripts/restore_or_create_wallets.sh "$MNEMONIC_COLDKEY" "$MNEMONIC_HOTKEY" "$WALLET_NAME"

if [ "$WORKER_TYPE" == "miner" ]; then 
    python neurons/miner.py --netuid "${NETWORK_UID}" --wallet.name "${WALLET_NAME}" --wallet.hotkey "${WALLET_HOTKEY}" --subtensor.network "${NETWORK_TYPE}" --logging.debug
elif [ "$WORKER_TYPE" == "validator" ]; then
    python neurons/validator.py --netuid "${NETWORK_UID}" --wallet.name "${WALLET_NAME}" --wallet.hotkey "${WALLET_HOTKEY}" --subtensor.network "${NETWORK_TYPE}" --logging.debug
else 
    echo "no such worker"
    exit 1
fi