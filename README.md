<div align="center">

![Logo](./docs/images/logo_black.png#gh-light-mode-only)
![Logo](./docs/images/logo_white.png#gh-dark-mode-only)

# **Solidity-Audit** <!-- omit in toc -->

## An Incentivized and Decentralized Subtensor Network <!-- omit in toc -->

</div>

- [Architecture](#architecture)
- [Joining the Network](#joining-the-network)
- [Creating your own miner](#creating-your-own-miner)
- [Audit Protocol](#audit-protocol)
- [Validator Operation Principle](#validator-operation-principle)
- [Improving your Validator](#improving-your-validator)
- [Development Roadmap](#development-roadmap)
- [Running Localnet](#running-localnet)
- [Machine Requirements](#machine-requirements)
- [Installation (local)](#install-local)
  - [Install SolidityAudit](#install-solidityaudit)
  - [Install Subtensor](#install-local-subtensor)
- [Installation (Docker)](#install-docker)
- [Model servers](#model-servers)
  - [OpenAI server](#openai-model-server)
- [Running a Miner](#running-a-miner)
- [Running a Validator](#running-a-validator)

## Introduction

Subtensor nodes play a vital role in the Bittensor network, governing various aspects such as incentivization, governance, and network health. Solidity-Audit aims to provide a decentralized platform for validating Solidity smart contracts and identifying potential vulnerabilities. With the increasing reliance on blockchain technology and smart contracts, ensuring their security has become critical to prevent financial loss and exploitation. This subnet will utilize distributed machine learning models to analyze and evaluate Solidity contracts for potential weaknesses or flaws, contributing to the overall security and trustworthiness of decentralized applications (dApps).

## Architecture

In this network, miners act as thin clients, while model processing is delegated to a separate microservice for ease of deployment and development. To start the miner, it requires an HTTP URL of the service with the model, without needing to modify the miner's code.

As a reference, an implementation of a microservice based on OpenAI is provided, which requires an API key to run. You can create your own microservice with a model, either using a local model or a public API, as long as you follow the protocol outlined below.

## Joining the Network

The simplest way to join the network is to use the reference implementation of the microservice that utilizes OpenAI's technology. This configuration is described in `.docker/docker-compose.common.yml`, which allows you to run all services at once by configuring the environment variables with wallets and network addresses.

Alternatively, you can run each service separately (this will be discussed in the relevant sections below).

## Creating Your Own Miner

Creating your own miner in the current architecture is not necessary, but you can develop your own microservice for the audit model. To do this, you need to provide model responses based on the specified protocol. Audit does not support streaming, and the response must be delivered as a single JSON object. For each vulnerability found, a separate JSON object with a description is formed.

## Audit Protocol

The description of the protocol in Pydantic format is available in the `ai_audits/protocol.py` file. This description can be imported and used as the response_format for the model (see `miner_servers/miner_server_open_ai.py`).

Example of an audit JSON object:

```javascript
{
  "from_line": 12,  // The starting line number of the vulnerability in the source code. The line numbers start from one.
  "to_line": 19,  // The ending line number of the vulnerability in the source code (inclusive).
  "vulnerability_class": "Reentrancy",  // The category of the vulnerability. E.g. Reentrancy, Bad randomness, Forced reception, Integer overflow, Race condition, Unchecked call, Unguarded function, et cetera.
  "test_case": "An attacker can create a malicious contract that calls the `withdrawBalance` function and then calls the `addToBalance` function in the fallback function. This will allow the attacker to withdraw more funds than they have deposited",  // A code or description example that exploits the vulnerability.
  "description": "The `withdrawBalance` function is vulnerable to reentrancy attacks because it does not update the `userBalance` mapping before sending the funds. This allows an attacker to call the `withdrawBalance` function multiple times before the `userBalance` mapping is updated",  // Human-readable vulnerability description, in markdown
  "prior_art": ["DAO hack"],  // Similar vulnerabilities encountered in wild before (Not really necessary, just to inform user)
  "fixed_lines": "function withdrawBalance(){\n    uint balance = userBalance[msg.sender];\n    userBalance[msg.sender] = 0;\n    msg.sender.transfer(balance);\n}"  // Fixed version of the original source.
}
```

## Validator Operation Principle

The validator operates based on a set of templates for both vulnerable and non-vulnerable contracts, located in the `contract_templates` directory. The validator generates a unique contract from the template and queries miners, evaluating their performance based on the number of matched vulnerability classes identified.

If a miner correctly identifies vulnerabilities in the generated contract, it receives a score accordingly. The system relies on the diversity and accuracy of the contract templates to assess the miners' ability to detect potential security issues.

## Improving your Validator

The simplest way to improve the validator is by adding additional contract templates to the `contract_templates directory`. A template consists of two files: `{contract_name}.sol.tpl` and `{contract_name}.json`. If one of these files is missing, an error will occur when the validator runs.

The `{contract_name}.sol.tpl` file contains the contract code to be checked (it can be either vulnerable or non-vulnerable). To create uniqueness, the template can include special variables.

### List of Variables

- `<|timestamp|>` – will be replaced with the current UNIX timestamp when generating the contract from the template.

- Additional variables can be defined in the future.

The `{contract_name}.json` file contains the reference miner response, formatted according to the protocol (see the "Audit Protocol" section).

### Current Validator Behavior

At the moment, the validator only checks the correspondence between the classes of identified vulnerabilities. In the future, the quality score for the miner's response will be improved by considering additional keys from the protocol.

## Development Roadmap

- Improvement of Validator Heuristics
  - Extend validation to check not only vulnerability classes but also the specific lines of code affected and the fix proposed by the model.
- Expanding Contract Templates
  - Add more contract templates to enhance the validator's effectiveness by providing a wider variety of vulnerable and non-vulnerable scenarios.
- Creation of Integration Tests
  - Develop integration tests to ensure the system functions correctly, covering miner interaction, contract validation, and local subtensor compatibility.

## Running Localnet

The repository includes a method to run a full localnet (a local Subtensor network along with the reference miner and validator). The docker-compose file for this setup can be found at `.docker/docker-compose.localnet.yml`.

Additionally, for testing purposes, there is a dummy microservice template for the miner model, which does not interact with a real AI model but returns a predefined response according to the protocol. This dummy microservice is located in `model_servers/miner_server_dummy.py`.

## Machine requirements

In terms of Operation System, you have to follow the requirements

- Ubuntu (>= 22.04)
- Others - please share with us to update our docs.

For miner and validator, a CPU machine with the same requirements as a local Subtensor is necessary. For more detailed information, please visit the [Subtensor GitHub](https://github.com/opentensor/subtensor).

It is important to note that a GPU is not required for this implementation, as the primary functionality is handled by a [separate service](miner_servers/miner_server_open_ai.py) that operates independently of miner.

## Installation (local) <a id="install-local"></a>

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

## Installation (docker) <a id="install-docker"></a>

TBD

## Model servers <a id="model-servers"></a>

To fully leverage the capabilities of the `SoldityAudit` subnetwork, it is essential to implement the logic for your model servers.

Model servers is required for the miner, enabling it to send data for processing, and subsequently receive, structure, and return that data to the validator within a synapse.

However, for testing purposes, you can use the template implemented in `model_servers/miner_server_dummy.py`.

> **NOTE:** Remember to create your `.env` file, which should include the addresses of your miner server in the variable `MINER_SERVER`. For testing purposes, you can use the command `cp .env-example .env`.

### OpenAI server <a id="openai-model-server"></a>

To run the miner powered by OpenAO , you simply need to execute the command:

```bash
python model_servers/miner_server_open_ai.py
```

Remember, that OpenAI miner server requires additional environment variable `OPENAI_API_KEY` with your API key, received from from OpenAI.

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
