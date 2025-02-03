# Quickstart on testnet

## Step 0: Key Generation

To work with bittensor-wallet, Python 3.11 is required.

The simplest way to install it is by using [pyenv](https://github.com/pyenv/pyenv) and [pyenv-virtualenv](https://github.com/pyenv/pyenv-virtualenv). Note about install dependencies of pyenv: [Suggested build environment](https://github.com/pyenv/pyenv/wiki#suggested-build-environment)

```shell
curl https://pyenv.run | bash
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo '[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
. ~/.bashrc
pyenv install 3.11
pyenv virtualenv 3.11 btcli
pyenv activate btcli
```

Install the CLI client:

```
pip install bittensor-cli
```

Generate a cold and hot keypairs:

```shell
btcli w create --wallet.name <WALLET_NAME> --wallet.hotkey default --no-use-password
```

Select the number of mnemonic words (21) and be sure to save the mnemonic phrase for key recovery.

You will get result like this:

```
IMPORTANT: Store this mnemonic in a secure (preferable offline place), as anyone who has possession of this mnemonic can use it to regenerate the key and access your tokens.

The mnemonic to the new coldkey is: amateur apology ...
You can use the mnemonic to recreate the key with `btcli` in case it gets lost.

IMPORTANT: Store this mnemonic in a secure (preferable offline place), as anyone who has possession of this mnemonic can use it to regenerate the key and access your tokens.

The mnemonic to the new hotkey is: right viable ...
You can use the mnemonic to recreate the key with `btcli` in case it gets lost.
```

Store your seed phrases in a secure location, as they will be needed later when launching the miner or validator.

## Step 0.1: Transfering tokens to your cold key

You need to obtain testnet tokens to be able to launch the miner or validator. Only the coldkey needs a balance (the hotkey can remain without tokens).

Testnet have no any faucet, so, if you don't have sufficient faucet tokens, ask the [Bittensor Discord community](https://discord.com/channels/799672011265015819/830068283314929684) for faucet tokens.

You can obtain wallet addresses as follows:

```shell
btcli w list
```

## Step 1: Connecting to the Subnet and Configuration

To operate, miners need a balance of 1 TAO, while validators require 11 TAO.

Register your wallet with the subnet:

```shell
btcli subnet register --netuid 222 --wallet.name <WALLET_NAME> --wallet.hotkey default --subtensor.network test
```

At this stage, setup for the miner's key is complete—it's ready for use.

## Step 2: Setting up the Stake (Required for validator)

First, nominate the hot key as a delegate:

```shell
btcli root nominate --wallet.name <WALLET_NAME> --wallet.hotkey default --subtensor.network test
```

Next, add a stake of at least 10 TAO to enable the validator to set weights in the subnet:

```shell
btcli stake add --amount 10 --wallet.name <WALLET_NAME> --wallet.hotkey default --subtensor.network test
```

That's it—the validator is now also ready for operation. Note that staking can also be applied to miners.

## Step 3: Running the miner

First, you need to choose a model server for your miner to work with. Three predefined options are available.

#### API Corcel.io

Pros:

- More affordable than OpenAI
- Fast performance

Cons:

- Currently, only the `llama-3-1-70b` model is available, which lags behind OpenAI in quality
- Context size is limited to 4096 tokens, which is sufficient for validators but may be inadequate for auditing large contracts (including user audits via the [website](https://audit.reinforced.app/))

### API OpenAI

Pros:

- High-quality model that passes all validator tests
- Fast performance

Cons:

- High cost


### API OpenRouter

Props:

- Many models to choose from with different pricing policies
- Fast performance

Cons:

- Not all models are well-suited for Solidity auditing


### Local LLM

Pros:

- Does not require a paid subscription (only a machine with a modern CPU or GPU is needed to run)

Cons:

- Low audit quality
- Slow performance on CPU

### Choosing a Model Server

The `docker-compose.yml` file provides two model servers: one for OpenAI and one for Corcel.io. The model server for a local LLM is contained in a separate repository [sa-model-server-example](https://github.com/ReinforcedAIAudits/sa-model-server-example).

The selected model server needs to be recorded in the `docker-compose.yml` file in the `MODEL_SERVER` environment variable (by default, the model server from Corcel.io is used).

Additionally, the chosen server must be launched separately:

```bash
docker compose up -d model_server_corcel
```

or

```bash
docker compose up -d model_server_openai
```

or

```bash
docker compose up -d model_server_open_router
```

### Running the miner service

```bash
docker compose up -d miner
```

To make this work you need to set environment variables:
- **MINER_COLDKEY_MNEMONIC** - seed phrase of miner cold key (from Step 0)
- **MINER_HOTKEY_MNEMONIC** - seed phrase of miner hot key (from Step 0)
- **NETWORK_UID** - Set to `222` (Solidity Audit network)
- **NETWORK_TYPE** - Set to `test`
- **CHAIN_ENDPOINT** - Set to `wss://test.finney.opentensor.ai:443/`
- **EXTERNAL_IP** - external ip of machine where miner would running

If you want to name your miner for [Auditor website](https://audit.reinforced.app/) you need to edit `docker-compose.yml` and set **COLDKEY_DESCRIPTION** to wished miner name.

## Step 4: Running the validator

Before launching the validator, you must ensure that your coldkey has a staking amount of at least 10 TAO.

### Running the validator service

```bash
docker compose up -d validator
```

To make this work you need to set environment variables:
- **VALIDATOR_COLDKEY_MNEMONIC** - seed phrase of validator cold key (From Step 0)
- **VALIDATOR_HOTKEY_MNEMONIC** - seed phrase of validator hot key (From step 0)
- **NETWORK_UID** - Set to 222 (Solidity Audit network)
- **NETWORK_TYPE** - Set to `test`
- **CHAIN_ENDPOINT** - Set to `wss://test.finney.opentensor.ai:443/`
- **VALIDATOR_TIME** - value from 0 to 59, indicates executable validator minute in hour
