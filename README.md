<div align="center">

# **Solidity-Audit** <!-- omit in toc -->
</div>

## An Incentivized and Decentralized Subtensor Network <!-- omit in toc -->


- [Machine Requirements](#machine-requirements)
  - [Validator](#validator-requirements)
  - [Miner](#miner-requirements)
- [Fast Setup and Run](#fast-setup-and-run)
  - [Validator](#validator-fast-setup-and-run)
  - [Miner](#miner-fast-setup-and-run)
- [Installation](#installation)
  - [Install SubVortex](#install-subvortex)
  - [Install Subtensor](#install-local-subtensor)
  - [Install Redis](#install-redis)
  - [Install Wandb](#install-wandb)
- [Registering your wallet](#registering-your-wallet)
- [Running a Miner](#running-a-miner)
- [Running a Validator](#running-a-validator)


## Introduction

Subtensor nodes play a vital role in the Bittensor network, governing various aspects such as incentivization, governance, and network health. Solidity-Audit aims to enhance the decentralization and functionality of Bittensor by establishing an incentivized network of subtensors.



## Machine requirements

In terms of Operation System, you have to follow the requirements

- Ubuntu (>= 22.04)
- Others - please share with us to update our docs.

### Miner <a id="miner-requirements"></a>

For miner, you need a CPU machine (no GPU needed!) with the same requirements as a local subtensor. Go to the [Subtensor github](https://github.com/opentensor/subtensor) for more information;.

For more information, take a look on the [min requirements](./min_compute.yml)


### Validator <a id="validator-requirements"></a>

For validator, you need a CPU machine (no GPU needed!).

For more information, take a look on the [min requirements](./min_compute.yml)

## Fast Setup and Run

For a quick and seamless setup, we provide a comprehensive script that installs and runs a miner or validator, taking care of everything from installation to execution.

### Setup and run a miner <a id="miner-fast-setup-and-run"></a>

> **IMPORTANT** <br />
> To use the full script, you have to follow the steps to install the subnet (**EXCEPT** executing **subnet_setup.sh**) by following the [Subnet guide](./scripts/subnet/README.md)

Be sure you are in the **Solidity-Audit** directory, if not

```
cd solidity-audit
```

Then, you can run the script

```
./scripts/setup_and_run.sh -t miner
```

> IMPORTANT
>
> - If you any prompts, just confirm them
> - Other options are available, pleaser take a look

Check the available options by running

```
./scripts/setup_and_run.sh -h
```

Once the script is successfully executed, you'll have a miner up and running—nothing else required!

Of course, if you have specific settings in mind, you can use this script as a base and update anything you want to tailor your experience to your needs.

Finally, if you prefer setup and run the miner in a more controlled way, you can follow the different sections below.

### Setup and run a validator <a id="validator-fast-setup-and-run"></a>

> **IMPORTANT** <br />
> To use the full script, you have to follow the steps to install the subnet (**EXCEPT** executing **subnet_setup.sh**) by following the [Subnet guide](./scripts/subnet/README.md)

Be sure you are in the **SubVortex** directory, if not

```
cd SubVortex
```

Then, you can run the script

```
./scripts/setup_and_run.sh -t validator
```

Check the available options by running

```
./scripts/setup_and_run.sh -h
```

Once the script is successfully executed, you'll have a validator up and running—nothing else required!

Of course, if you have specific settings in mind, you can use this script as a base and update anything you want to tailor your experience to your needs.

Finally, if you prefer setup and run the validator in a more controlled way, you can follow the different sections below.

## Installation

### Pre-requisite

- Local Subtensor is mandatory for all miners, and highly recommended for validators.
- Validators will need to install and configure Redis

### Install SubVortex

To install the subnet, refer to the [Subnet guide](./scripts/subnet/README.md)

### Install Local Subtensor

To install a local subtensor, refer to the [Subtensor guide](./scripts/subtensor/README.md)


### Registering your wallet

In order to run either a miner or a validator, you will need to have a wallet registered to the subnet. If you do not already have wallet set up on the server, following the steps below:

If you are restoring an existing wallet:

```
btcli w regen_coldkey --wallet.name YOUR_WALLET_NAME
btcli w regen_hotkey --wallet.name YOUR_WALLET_NAME --wallet.hotkey YOUR_HOTKEY_NAME
```

If you are creating the wallet for the first time:

```
btcli w new_coldkey --wallet.name YOUR_WALLET_NAME
btcli w new_hotkey --wallet.name YOUR_WALLET_NAME --wallet.hotkey YOUR_HOTKEY_NAME
```

Once your wallet is ready, ensure you have sufficient funds to register to the subnet. To register, use the following command:

```
btcli s register --netuid <SUBNET_UID> --subtensor.network local --wallet.name YOUR_WALLET_NAME --wallet.hotkey YOUR_HOTKEY_NAME
```

Once you have successfully registered your wallet, you are now ready to start either your miner or validator.

### Running a Miner

> IMPORTANT: Before running a miner, be sure you have a local subtensor up and running. Please see the [Subtensor guide](./scripts/subtensor/README.md) for more details.

> IMPORTANT: **wandb** **IS NOT** for miners, **ONLY FOR** validators.

To run a miner, navigate to the SubVortex directory. It is highly recommended to run via a process manager like PM2.

```
pm2 start neurons/miner.py \
  --name MINER_NAME \
  --interpreter <PATH_TO_PYTHON_LIBRARY> -- \
  --netuid <SUBNET_UID> \
  --wallet.name YOUR_WALLET_NAME \
  --wallet.hotkey YOUR_HOTKEY_NAME \
  --subtensor.network local \
  --logging.debug \
  --auto-update
```

> IMPORTANT: Do not run more than one miner per machine. Running multiple miners will result in the loss of incentive and emissions on all miners.

To enable the firewall, add the `--firewall.on` flag. It is highly recommended to enable the firewall to protect your miner from attacks that could impact your score. For more details about the firewall, please refer to our [firewall guide](./docs/features/firewall.md)

### Running a Validator

> IMPORTANT: Before running a validator, be sure you have a redis up and running. Please see the [Redis guide](./scripts/redis/README.md) for more details.

> IMPORTANT: Before running a validator, be sure you have a local subtensor up and running. Please see the [Subtensor guide](./scripts/subtensor/README.md) for more details.

> IMPORTANT: By default wandb is enabled when running a validator. It is **HIGHLY RECOMMANDED** to not disable it as it enables everyone to access various statistics for better performance on the subnet but if you want to do it, just add `--wandb.off` to the followed pm2 command. If you want to keep wandb enabled, please refer to the [Wandb guide](./docs/wandb/wandb.md) for more details as there are some manually steps to go throught before running the validator.

> Please use `--database.index <INDEX>`if you have multiple subnet sharing the same redis instance and the index 1 (default value) is already taken by another subnet

Similar to running a miner in the above section, navigate to the SubVortex directory and run the following to launch in PM2.

```
pm2 start neurons/validator.py \
  --name VALIDATOR_NAME \
  --interpreter <PATH_TO_PYTHON_LIBRARY> -- \
  --netuid <SUBNET_UID> \
  --wallet.name YOUR_WALLET_NAME \
  --wallet.hotkey YOUR_HOTKEY_NAME \
  --subtensor.network local \
  --logging.debug \
  --auto-update
```

> NOTE: if you run a validator in testnet do not forget to add the argument `--subtensor.network test` or `--subtensor.chain_endpoint ws://<LOCAL_SUBTENSOR_IP>:9944` (the local subtensor has to target the network testnet)

> NOTE: to access the wandb UI to get statistics about the miners, you can click on this [link](https://wandb.ai/eclipsevortext/subvortex-team) and choose the validator run you want.

> NOTE: by default the dumps created by the auto-update will be stored in /etc/redis. If you want to change the location, please use `--database.redis_dump_path`.

