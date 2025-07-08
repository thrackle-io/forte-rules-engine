## Forte Rules Engine - UNDER DEVELOPMENT 
[![Project Version][version-image]][version-url]

This is the next iteration of the Forte Rules Engine! If you're looking for the original version, go [here](https://github.com/thrackle-io/forte-rules-engine-v1). 

This enhanced architecture prioritizes ease of integration and increased rule configurability. Check out our quickstart guide [here](https://docs.forterulesengine.io/v2/quickstart)!

This project is under development and __not yet audited__. 

This repository contains an EVM-based protocol designed to meet the unique needs of tokenized assets and on-chain economies. The protocol enables the creation and management of economic and compliance controls for your on-chain economy at the token level, allowing for maximum flexibility while maintaining the transparency and trustlessness of Web3.

## Contributing

Please visit our [Contributor Guide](./CONTRIBUTING.md).

## Forte x Thrackle

Forte’s work is aided and supported by our ecosystem partner, Thrackle, a team of industry experts, including PhD-level engineers specializing in computer science, math, engineering, economics, and finance. Thrackle leverages its deep technical expertise to develop purpose-built, customizable products that enable the creation, growth, and stability of thriving digital asset economies. Together, Forte and Thrackle are driving innovation to build healthy, sustainable blockchain economies.

## Getting Started
###  Environment dependencies

This guide assumes the following tools are installed and configured correctly. Please see each tool's installation instructions for more details:

- [Git](https://git-scm.com/)
- [NodeJS](https://nodejs.org/) - v20.x.x
- [Foundry](https://book.getfoundry.sh/getting-started/installation) - v1.2.1-stable
- [Python3](https://www.python.org/downloads/) - v3.x.x 

### Building
To build and install dependencies, run the following commands:
```bash
npm install
forge soldeer install
forge build
```

### Testing
In order to run the full test suite, there are some other requirements. First, a python virtual environment is needed to install the python requirements. We'll also set the env source now.
```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
source .env
```
Once everything is ready to go, we'll run the test suite:
```bash
 forge test -vv --ffi
```
### Deployment

The following section will run through the deployment process of the Forte Rules Engine, as well as how to utilize a local deployment of the FRE. The main deployment script is located at [`script/deployment/DeployRulesDiamond.s.sol`](script/deployment/DeployRulesDiamond.s.sol).

#### Environment Configuration

Before deploying, configure your environment variables in the `.env` file:

```bash
# Deployment Configuration
DEPLOYER_PRIVATE_KEY=0x1234567890abcdef...  # Private key of the deploying account
DESIRED_DEPLOYMENT_ADDRESS=0x742d35Cc6634C0532925a3b8D400414004C07f5F  # Target deployment address
ETH_RPC_URL=https://mainnet.infura.io/v3/your-project-id  # RPC URL for target chain
GAS_NUMBER=20000000000  # Gas price in wei (optional)
```

**Important**: 
- Set `DEPLOYER_PRIVATE_KEY` to the private key of the account that will deploy the contracts
- Set `DESIRED_DEPLOYMENT_ADDRESS` to your preferred deployment address
- Set `ETH_RPC_URL` to the RPC endpoint of your target blockchain network
- Ensure the deployer account has sufficient funds for gas fees

#### Local Development with Anvil

For local development and testing, you can use Anvil to create a persistent state:

**Method 1: Manual Anvil State Creation**
```bash
# Start Anvil with state dumping
anvil --dump-state diamondDeployedAnvilState.json
```

**Method 2: Automated State Generation**
```bash
# Use the automated script to deploy and save Anvil state
./script/deployment/generateAnvilSavedDiamondState.sh
```

This will:
1. Start Anvil in the background with `--dump-state diamondDeployedAnvilState.json`
2. Deploy the Rules Engine Diamond to the local network
3. Save the deployment state to `diamondDeployedAnvilState.json`
4. Clean up the Anvil process

**Loading Saved State**

The saved state file contains the complete blockchain state after deployment, allowing you to resume development with pre-deployed contracts.

#### Deployment Methods

```bash
# Source environment variables
source .env
```

**Direct Forge Deployment**
Using the bash script
```bash
bash script/deployment/SimpleDeploy.sh
```

Or using forge script directly
```bash
forge script script/deployment/DeployRulesDiamond.s.sol \
  --ffi \
  --broadcast \
  -vvv \
  --non-interactive \
  --rpc-url=$ETH_RPC_URL \
  --gas-price $GAS_NUMBER \
  --legacy
```

## Licensing

The primary license for Forte Protocol Rules Engine is the Business Source License 1.1 (`BUSL-1.1`), see [`LICENSE`](./LICENSE). However, some files are dual licensed under `GPL-2.0-or-later`:

- All files in `src/example/` may also be licensed under `GPL-2.0-or-later` (as indicated in their SPDX headers), see [`src/example/LICENSE`](./src/example/LICENSE)

### Other Exceptions

- All files in `lib/` are licensed under `MIT` (as indicated in its SPDX header), see [`lib/LICENSE_MIT`](lib/LICENSE_MIT)
- All files in `src/example/` may also be licensed under `GPL-2.0-or-later` (as indicated in their SPDX headers), see [src/example/LICENSE](src/example/LICENSE)
Other Exceptions



[version-image]: https://img.shields.io/badge/Version-0.0.1-brightgreen?style=for-the-badge&logo=appveyor
[version-url]: https://github.com/thrackle-io/forte-rules-engine
