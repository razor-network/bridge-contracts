# Razor Bridge Contracts • [![ci](https://github.com/razor-network/bridge-contracts/actions/workflows/ci.yml/badge.svg)](https://github.com/razor-network/bridge-contracts/actions/workflows/ci.yml) ![solidity](https://img.shields.io/badge/solidity-^0.8.15-lightgrey)


**Prerequisites**

_Note_: This project uses **Foundry** for tests and **Hardhat** for deployment make sure to install both. 

## Getting Started
### Foundry Installation

See the official Foundry installation [instructions](https://github.com/foundry-rs/foundry/blob/master/README.md#installation).

Then, install the [foundry](https://github.com/foundry-rs/foundry) toolchain installer (`foundryup`) with:
```bash
curl -L https://foundry.paradigm.xyz | bash
```

Now that you've installed the `foundryup` binary,
anytime you need to get the latest `forge` or `cast` binaries,
you can run `foundryup`.

So, simply execute:
```bash
foundryup
```

Foundry is installed! 🎉


### Hardhat Installation

Install all the packages from root directory. Compatible node version `>=16.0.0`.

```bash
yarn install
```

Packages installed! 🎉


## Development

**Setup**
```bash
forge install
```
current version of git submodules used in the repository: 

[foundry-rs/forge-std@d26946a](https://github.com/foundry-rs/forge-std/tree/d26946aeef956d9d11238ce02c94b7a22ac23ca8)

[openzeppelin/openzeppelin-contracts@ce0068c](https://github.com/openzeppelin/openzeppelin-contracts/tree/ce0068c21ecd97c6ec8fb0db08570f4b43029dde)

[transmissions11/solmate@bff24e8](https://github.com/transmissions11/solmate/tree/bff24e835192470ed38bf15dbed6084c2d723ace)

to confirm the installed versions you can run:

```bash
 git submodule status   
 ```



**Building**

foundry: 
```bash
forge build
```
hardhat: 
```bash
npx hardhat compile
```
**Testing**
```bash
forge test -vvvv
```

**Devnet deployment**

First, modify the .env with 

`NETWORK_TYPE=DEVNET`

`SEED_AMOUNT=1000000000000000000000`

To start a local node with a local block explorer first install [ethernal](https://doc.tryethernal.com/getting-started/quickstart). Only sign up is required.

```bash
ETHERNAL_EMAIL=your@email.com ETHERNAL_PASSWORD=yourpwd npx hardhat node
```
_Note: make sure to set the `resetOnStart` parameter of `ethernal` in the hardhat config file to your workspace name set in ethernal after sign up._


To start a localhost hardhat node without a block explorer just run:
```bash
npm run deploy:devnet
```

This creates a localhost hardhat node with mining interval 10 seconds.
This also does the following:
1. Deploys the contracts to the following addresses:

```
{
    "Tss": "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
    "MockERC20": "0x5FbDB2315678afecb367f032d93F642f64180aa3"
}
```

2. Sends stake amount and whitelists the first 10 accounts on localhost hardhat network and creates a fixed number of requests for the bridge nodes to fulfill.


Once this is complete, run the following command on a new terminal tab:

```bash
npm run adminScript:devnet
```
1. Runs the adminScript, which is required to be run on the 1st dynasty only. It allows the admin to call `confirmSigner()` so that the `activeSet` and `signerAddress` for the dynasty can be confirmed. _Note: The adminScript will continue to run in the background until the nodes running from bridge-node attest a signer address. Please continue with bridge-node set up and let the script continue running._

After this is done, you can run devnet nodes on the bridge-node(for documentation, refer bridge-node repo.)

**Linting**
```bash
forge fmt
```

**Coverage**
```bash
forge coverage
```

**Snapshot**
```bash
forge snapshot
```

## Deployment 

1. Create a copy of local environment `.env` from `.env.example` by running `yarn cp-example-env` and set the environment variables accordingly.
2. Run hardhat node (`yarn deploy`)
3. This will run `scripts/deploy.sh` which will deploy the contracts using ` npx hardhat --network $NETWORK deploy`

## Deployed Contracts

**Whispering Turais**
Bridge: 0x284Ff064B465C5477582C0713eDd627533cD3838
MockERC20: 0x3270C19B4e05a15DE2f02c1c3BFD779DAcb7B270

## Contribution

1. Fork repository from [here](https://github.com/razor-network/bridge-contracts/fork) and follow the installation steps.
2. To make contributions see our [contribution guideline](https://github.com/razor-network/bridge-contracts/blob/master/.github/CONTRIBUTING.md)
