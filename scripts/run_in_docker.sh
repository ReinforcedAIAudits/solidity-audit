#!/bin/bash

check_endpoint() {
    response=$(curl --write-out "%{http_code}" --silent --output /dev/null "$MODEL_SERVER/healthcheck")
    echo "$response"
}

if [ -z "${SKIP_HEALTHCHECK}" ]; then
    while true; do
        status_code=$(check_endpoint)

        if [ "$status_code" -eq 200 ]; then
            break
        else
            echo "Model server is not running yet."
            echo "Retrying in 5 seconds..."
            sleep 5
        fi
    done
else
    echo "Healthcheck skipped due to SKIP_HEALTHCHECK variable"
fi

if [ "$WORKER_TYPE" == "miner" ]; then 
    python neurons/miner.py
elif [ "$WORKER_TYPE" == "validator" ]; then
    python neurons/validator.py
else 
    echo "no such worker"
    exit 1
fi