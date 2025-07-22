<div align="center">

![Logo](./docs/images/logo_black.png#gh-light-mode-only)
![Logo](./docs/images/logo_white.png#gh-dark-mode-only)

# **Solidity-Audit** <!-- omit in toc -->

## An Incentivized and Decentralized Subtensor Network <!-- omit in toc -->

**Website: <https://reinforced.app>**

</div>

- [Architecture](#architecture)
- [Joining the Network](#joining-the-network)
- [Minimal requirements](#minimum-requirements)
- [Creating your own miner](#creating-your-own-miner)
- [Audit Protocol](#audit-protocol)
- [Secure Proof-of-Work Validation](#secure-proof-of-work-validation-via-unique-network-integration)
- [Validator Operation Principle](#validator-operation-principle)
- [Relayer](#relayer)
- [Installation (Docker)](#install-docker)
  - [Running a Miner](#running-a-miner-docker)
  - [Running a Validator](#running-a-validator-docker)
- [Installation (local)](#install-local)
  - [Install SolidityAudit](#install-solidityaudit)
  - [Running a Miner](#running-a-miner-local)
- [Model servers](#model-servers)


## Introduction

Subtensor nodes play a vital role in the Bittensor network, governing various aspects such as incentivization, governance, and network health. Solidity-Audit aims to provide a decentralized platform for validating Solidity smart contracts and identifying potential vulnerabilities. With the increasing reliance on blockchain technology and smart contracts, ensuring their security has become critical to prevent financial loss and exploitation. This subnet will utilize distributed machine learning models to analyze and evaluate Solidity contracts for potential weaknesses or flaws, contributing to the overall security and trustworthiness of decentralized applications (dApps).

## Architecture

In this network, miners act as thin clients, while model processing is delegated to a separate microservice for ease of deployment and development. To start the miner, it requires an HTTP URL of the service with the model, without needing to modify the miner's code.

As a reference, an implementation of a microservice based on local LLM is provided. You can create your own microservice with a model, either using a local model or a public API, as long as you follow the protocol outlined below.

## Joining the Network

The simplest way to join the network is to use the reference implementation of the microservice. This configuration is described in `.docker/docker-compose.yml`, which allows you to run all services at once by configuring the environment variables with wallets and network addresses.

Alternatively, you can run each service separately (this will be discussed in the relevant sections below).

## Minimum requirements

* Python 3.11 (We use Rust-built wheels that are available only for this version)
* 8GB RAM or 4GB VRAM (However, we strongly recommend more for working with more powerful LLMs)
* UNQ tokens for miners

## Creating Your Own Miner

Creating your own miner from scratch in the current architecture is not necessary, but you will want to develop your own microservice for the audit model to differentiate from other miners and create a better service. To do this, you need to provide model responses based on the specified protocol. Audit does not support streaming, and the response must be delivered as a single JSON object. For each vulnerability found, a separate JSON object with a description is formed.

## Audit Protocol

The description of the protocol in Pydantic format is available in the `ai_audits/protocol.py` file.

Example of an audit JSON object:

```json
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
## Secure Proof-of-Work Validation via [Unique Network](https://unique.network) Integration

To prevent miners from executing duplicate submission attacks, we have integration with Unique Network. Each miner is required to generate an NFT containing encrypted proof of their work. This proof can only be verified using the private key of the requesting validator.

Validators assign scores based on a comparison of the information stored in the NFT and the submitted miner response. They decrypt the NFT’s metadata using their private key. If the metadata does not match the submitted response or if the NFT is not associated with the miner’s public key, the validator will not assign a score.

This approach ensures that each proof is unique, prevents unauthorized reuse of work, and strengthens the overall integrity of the validation process.


## Validator Operation Principle

The validator receives a completely random contract from the LLM, enriches it with vulnerabilities, ensures that the contract remains valid (by performing a full compilation via `solc`), and knows the type of the vulnerability in advance. The contract is then sent to miners for evaluation, and the types of vulnerabilities identified by miners are compared with the expected ones (accounting for synonyms).

The generation of fully random templates via LLM is currently implemented using `Claude 3.7 Sonnet`.

## Relayer

In the proposed architecture for a Solidity smart contract auditing subnet, miners and validators interact indirectly via an intermediate node – the relayer. This abstraction layer enhances transparency, control, and system resilience by centralizing data collection for validator improvement and enabling flexible information flow management.

Key Advantages of This Approach:

- Metric Collection and Analysis – The relayer records data on contracts generated by validators, discovered vulnerabilities, and validator scores. This enables detailed analytics for improving validation quality and overall network performance.
- Validator Activity Monitoring – Tracking frequency, quality, and objectivity of validations helps detect anomalies and builds trust in the audit outcomes.
- Enhanced Consensus Observability – While Yuma Consensus ensures validation integrity, the relayer offers deeper insight into decision-making processes and the dynamics of network interactions.
- Data Filtering and Normalization – The relayer allows for protocol migrations without halting the network, giving miners extra time to update and ensuring seamless transitions.
- Buffering and Retransmission – In cases of temporary axon unavailability, the relayer can store and forward data, improving network reliability.
- Load Distribution – The relayer maintains up-to-date information about miner availability, helping prevent axon overload and acting as a protection layer from external access attempts outside the metagraph.


## Installation (docker) <a id="install-docker"></a>

The project is adapted for installation in Docker, so this option may be preferable for deployment.

### Running a Miner <a id="running-a-miner-docker"></a>

```bash
docker compose up -d miner
```

To make this work you need to set environment variables:
* **MNEMONIC_HOTKEY** - seed phrase of miner hot key
* **NETWORK_TYPE** - network type (`testnet` for testnet, `mainnet` for mainnet)
* **CHAIN_ENDPOINT** - network endpoint (`wss://test.finney.opentensor.ai:443/` for testnet, `wss://entrypoint-finney.opentensor.ai:443/` for mainnet)
* **EXTERNAL_IP** - external ip of machine where miner would running
* **MODEL_SERVER** - url for miner model_server to perform audit (`'http://miner_server:5000'`)

### Running a Validator <a id="running-a-validator-docker"></a>

The simplest (and best) way to run a validator on SN92 is using Docker. The validator code will update automatically, so you’ll always stay up to date and maintain a good vtrust.

> **Important note:** services must include `restart: unless-stopped` because the container may shut down occasionally (this is also required for auto-updating).

To run the validator, you’ll also need an API key from [OpenRouter](https://openrouter.ai/).

```yaml
services:
  validator-server:
    image: reinforcedai/solidity-audit
    container_name: validator-server
    environment:
      OPEN_ROUTER_API_KEY: 'sk-or-v1-xxxx (Your real OpenRouter key)'
      NETWORK_TYPE: 'mainnet'
      SA_SERVICE: 'validator_model_server'
    restart: unless-stopped
    networks:
      - solidity-audit

  validator-uid-x:
    image: reinforcedai/solidity-audit
    container_name: validator-uid-x
    environment:
      MNEMONIC_HOTKEY: '//Alice (your real hotkey)'
      CHAIN_ENDPOINT: 'wss://entrypoint-finney.opentensor.ai:443/'
      MODEL_SERVER: 'http://validator-server:5000'
      NETWORK_TYPE: 'mainnet'
      SA_SERVICE: 'validator'
    restart: unless-stopped
    networks:
      - solidity-audit

networks:
  solidity-audit:
```

```bash
docker compose up -d validator-uid-x validator-server
```

To make this work you need to set environment variables:
* **MNEMONIC_HOTKEY** - seed phrase of validator hot key
* **NETWORK_TYPE** - network type (`testnet` for testnet, `mainnet` for mainnet)
* **CHAIN_ENDPOINT** - network endpoint (``wss://test.finney.opentensor.ai:443/` for testnet, `wss://entrypoint-finney.opentensor.ai:443/` for mainnet)
* **MODEL_SERVER** - url for validator model_server to generate contracts (`'http://validator_server:5000'`)

## Installation (local) <a id="install-local"></a>

### Install SolidityAudit

To install the subnet, you need to make some simple instructions:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

This commands will create virtual python environment and install required dependencies.

### Running a Miner <a id="running-a-miner-local"></a>

#### Model server

To run the default miner server with local LLM, you simply need to execute the command:

```bash
python run.py miner_model_server
```

To run a miner, navigate to the `solidity-audit` directory, run this command:

```
export BT_AXON_PORT=<MINER_PORT> \
    CHAIN_ENDPOINT=<CHAIN_ENDPOINT> \
    NETWORK_TYPE=<NETWORK_TYPE> \
    MNEMONIC_HOTKEY=<YOUR_WALLET_HOTKEY_MNEMONIC> \
    MODEL_SERVER=<MODEL_SERVER_URL>
    
python run.py miner
```

### For mainnet 

`NETWORK_TYPE` must be `mainnet` AND `CHAIN_ENDPOINT` must be `wss://entrypoint-finney.opentensor.ai:443/`

### For testnet

`NETWORK_TYPE` must be `testnet` AND `CHAIN_ENDPOINT` must be `wss://test.finney.opentensor.ai:443/`

> **IMPORTANT**: Do not run more than one miner per machine. Running multiple miners will result in the loss of incentive and emissions on all miners.

## Model servers <a id="model-servers"></a>

To fully leverage the capabilities of the `SoldityAudit` subnetwork, it is essential to implement the logic for your model servers.

Model server is required for the miner, enabling it to send data for processing, and subsequently receive, structure, and return that data to the validator within a synapse.

The model server is essential for the validator to generate tasks for miners, including both secure and vulnerable smart contracts.

It is strongly recommended to use the validator's built-in model server to ensure consensus consistency across the network.