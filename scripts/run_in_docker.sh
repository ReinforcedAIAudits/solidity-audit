#!/bin/bash

./scripts/restore_or_create_wallets.sh "$MNEMONIC_COLDKEY" "$MNEMONIC_HOTKEY" "$WALLET_NAME"

check_endpoint() {
    response=$(curl --write-out "%{http_code}" --silent --output /dev/null "$MODEL_SERVER/healthcheck")
    echo "$response"
}

while true; do
    status_code=$(check_endpoint)

    if [ "$status_code" -eq 200 ]; then
        echo "Model server is not running yet."
        break
    else
        echo "Retrying in 5 seconds..."
        sleep 5
    fi
done

if [ "$WORKER_TYPE" == "miner" ]; then 
    python neurons/miner.py --netuid "${NETWORK_UID}" --wallet.name "${WALLET_NAME}" --wallet.hotkey "${WALLET_HOTKEY}" --subtensor.network "${NETWORK_TYPE}" --subtensor.chain_endpoint "${CHAIN_ENDPOINT}" --axon.external_ip "${EXTERNAL_IP}" --logging.debug
elif [ "$WORKER_TYPE" == "validator" ]; then
    python neurons/validator.py --netuid "${NETWORK_UID}" --wallet.name "${WALLET_NAME}" --wallet.hotkey "${WALLET_HOTKEY}" --subtensor.network "${NETWORK_TYPE}" --subtensor.chain_endpoint "${CHAIN_ENDPOINT}" --logging.debug
else 
    echo "no such worker"
    exit 1
fi