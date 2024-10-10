<div align="center">

# **Solidity-Audit** <!-- omit in toc -->

## An Incentivized and Decentralized Subtensor Network <!-- omit in toc -->
</div>


- [Machine Requirements](#machine-requirements)
  - [Validator](#validator-requirements)
  - [Miner](#miner-requirements)
- [Installation](#installation)
  - [Install SolidityAudit](#install-solidityaudit)
  - [Install Subtensor](#install-local-subtensor)
- [Blackboxes](#blackboxes)
  - [Miner blackbox](#miner-blackbox)
- [Running a Miner](#running-a-miner)
- [Running a Validator](#running-a-validator)


## Introduction

Subtensor nodes play a vital role in the Bittensor network, governing various aspects such as incentivization, governance, and network health. Solidity-Audit aims to provide a decentralized platform for validating Solidity smart contracts and identifying potential vulnerabilities. With the increasing reliance on blockchain technology and smart contracts, ensuring their security has become critical to prevent financial loss and exploitation. This subnet will utilize distributed machine learning models to analyze and evaluate Solidity contracts for potential weaknesses or flaws, contributing to the overall security and trustworthiness of decentralized applications (dApps).


## Machine requirements

In terms of Operation System, you have to follow the requirements

- Ubuntu (>= 22.04)
- Others - please share with us to update our docs.

### Miner <a id="miner-requirements"></a>

For miner, a CPU machine with the same requirements as a local Subtensor is necessary. It is important to note that a GPU is not required for this implementation, as the primary functionality is handled by a [separate service](https://github.com/ReinforcedAIAudits/solidity-audit/blob/main/blackbox_example/miner_server.py) that operates independently of miner. For more detailed information, please visit the [Subtensor GitHub](https://github.com/opentensor/subtensor).

### Validator <a id="validator-requirements"></a>

For validator, a CPU machine with the same requirements as a local Subtensor is necessary. 

## Installation

### Install SolidityAudit

To install the subnet, you need to make some simple instructions:

```bash
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

This commands will create virtual python environment and install required dependencies.

### Install Local Subtensor

To install a local subtensor, begin by installing the required dependencies for running a Substrate node.

#### Install Subtensor dependencies

Update your system packages and install additional required libraries and tools:

```bash
sudo apt update
sudo apt install --assume-yes make build-essential git clang curl libssl-dev llvm libudev-dev protobuf-compiler
```

#### Install Rust and Cargo

Rust is the programming language used in Substrate development. Cargo is Rust package manager.

Install rust and cargo and update your shell's source to include Cargo's path:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

#### Clone the subtensor repository

This step fetches the subtensor codebase to your local machine.

```bash
git clone https://github.com/opentensor/subtensor.git
```


#### Setup Rust

This step ensures that you have the nightly toolchain and the WebAssembly (wasm) compilation target. Note that this step will run the subtensor chain on your terminal directly, hence we advise that you run this as a background process using PM2 or other software.

```bash
./subtensor/scripts/init.sh
```


#### Run subtensor

Build the binary with the faucet feature enabled and run the localnet script and turn off the attempt to build the binary (as we have already done this above):

```bash
cargo build -p node-subtensor --profile production --features pow-faucet
./scripts/localnet.sh
```

#### Initialize network

Execute this command to create wallets, register your subnetwork, set weights, and perform other essential tasks. This is a crucial step for the proper functioning of the node:

```bash
python utils/init_solochain.py
```

> **NOTE:**
> In this script, you can modify the names of the wallets being created, add passwords to them, and adjust the values for root and subnet weights.

## Blackboxes

To fully leverage the capabilities of the `SoldityAudit` subnetwork, it is essential to implement the logic for your blackboxes. 

The first blackbox is required for the miner, enabling it to send data for processing, and subsequently receive, structure, and return that data to the validator within a synapse. 

The second blackbox is necessary for the validator, whose responsibilities include generating tasks and verifying the structural correctness of the miner's responses.

However, for testing purposes, you can use the templates implemented in `blackbox_example/`.

> **NOTE:** Remember to create your `.env` file, which should include the addresses of your blackboxes in the variables `MINER_SERVER`. For testing purposes, you can use the command `cp .env-example .env`.

### Miner blackbox

To run the miner blackbox example , you simply need to execute the command:

```bash
python blackbox_example/miner_server.py
```

## Running a Miner

> **IMPORTANT:** Before running a miner, be sure you have a local subtensor up and running. Please see the [Subtensor guide](#install-local-subtensor) for more details.

To run a miner, navigate to the `solidity-audit` directory, run this command:

```
python neurons/miner.py \
 --netuid <SUBNET_UID> \
 --wallet.name <YOUR_MINER_WALLET_NAME>
 --wallet.hotkey <YOUR_HOTKEY_NAME> \
 --subtensor.network local \
 --subtensor.chain_endpoint ws://127.0.0.1:9946 \
 --logging.debug 

```

> IMPORTANT: Do not run more than one miner per machine. Running multiple miners will result in the loss of incentive and emissions on all miners.

## Running a Validator

> **IMPORTANT:** Before running a validator, be sure you have a local subtensor up and running. Please see the [Subtensor guide](#install-local-subtensor) for more details.

Similar to running a miner in the above section, navigate to the `solidity-audit` directory and run the following:

```
python neurons/validator.py \
  --netuid <NET_UID> \
  --wallet.name <YOUR_VALIDATOR_WALLET_NAME> \
  --wallet.hotkey <YOUR_HOTKEY_NAME> \
  --subtensor.network local \
  --subtensor.chain_endpoint ws://127.0.0.1:9946 \
  --logging.debug
```

> NOTE: if you run a validator in testnet do not forget to add the argument `--subtensor.network test` or `--subtensor.chain_endpoint ws://<LOCAL_SUBTENSOR_IP>:9946` (the local subtensor has to target the network testnet)

