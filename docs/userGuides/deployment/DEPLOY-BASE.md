# Deployment Using Individual Scripts

[![Project Version][version-image]][version-url]


NOTE: These commands must all be run one at a time

## Deploy the Protocol, if necessary

```bash
sh script/SetupProtocolDeploy.sh
forge script script/DeployAllModulesPt1.s.sol --ffi --broadcast --rpc-url $ETH_RPC_URL --gas-price $GAS_NUMBER 
sh script/ParseProtocolDeploy.sh
forge script script/DeployAllModulesPt2.s.sol --ffi --broadcast --rpc-url $ETH_RPC_URL --gas-price $GAS_NUMBER 
forge script script/DeployAllModulesPt3.s.sol --ffi --broadcast --rpc-url $ETH_RPC_URL --gas-price $GAS_NUMBER 
forge script script/DeployAllModulesPt4.s.sol --ffi --broadcast --rpc-url $ETH_RPC_URL --gas-price $GAS_NUMBER 
```

## Deploy Application Assets, if necessary

```bash
forge script script/clientScripts/Application_Deploy_01_AppManager.s.sol --ffi --broadcast --rpc-url $ETH_RPC_URL --gas-price $GAS_NUMBER 
sh script/ParseApplicationDeploy.sh 1
forge script script/clientScripts/Application_Deploy_02_ApplicationFT1.s.sol --ffi --broadcast --rpc-url $ETH_RPC_URL --gas-price $GAS_NUMBER 
sh script/ParseApplicationDeploy.sh 2
forge script script/clientScripts/Application_Deploy_02_ApplicationFT1Pt2.s.sol --ffi --broadcast --rpc-url $ETH_RPC_URL --gas-price $GAS_NUMBER 
forge script script/clientScripts/Application_Deploy_04_ApplicationNFT.s.sol --ffi --broadcast --rpc-url $ETH_RPC_URL --gas-price $GAS_NUMBER 
forge script script/clientScripts/Application_Deploy_04_ApplicationNFTUpgradeable.s.sol --ffi --broadcast --rpc-url $ETH_RPC_URL --gas-price $GAS_NUMBER 
sh script/ParseApplicationDeploy.sh 3
forge script script/clientScripts/Application_Deploy_04_ApplicationNFTPt2.s.sol --ffi --broadcast --rpc-url $ETH_RPC_URL --gas-price $GAS_NUMBER 
forge script script/clientScripts/Application_Deploy_04_ApplicationNFTUpgradeablePt2.s.sol --ffi --broadcast --rpc-url $ETH_RPC_URL --gas-price $GAS_NUMBER 
forge script script/clientScripts/Application_Deploy_05_Oracle.s.sol --ffi --broadcast --rpc-url $ETH_RPC_URL --gas-price $GAS_NUMBER 
sh script/ParseApplicationDeploy.sh 4
forge script script/clientScripts/Application_Deploy_06_Pricing.s.sol --ffi --broadcast --rpc-url $ETH_RPC_URL --gas-price $GAS_NUMBER 
sh script/ParseApplicationDeploy.sh 5
forge script script/clientScripts/Application_Deploy_07_ApplicationAdminRoles.s.sol --ffi --broadcast --rpc-url $ETH_RPC_URL --gas-price $GAS_NUMBER 
```

Make sure that all the srcipts ran successfully, and then:

```bash 
forge test --ffi --rpc-url $ETH_RPC_URL --gas-price $GAS_NUMBER  
```


##### Note: an ETH_RPC_URL can be found in the .env file.

#### Deploy The Protocol

Be sure to [set environmental variables](./deployment/SET-ENVIRONMENT.md) and source the .env file (`source .env`) and then feel free to run this script:

`scripts/deploy/DeployProtocol.sh`
This script is responsible for deploying all the protocol contracts. Take into account that no application-specific contracts are deployed here.

#### Deploy Some Test Application Tokens

`script/clientScripts/Application_Deploy_01_AppManager.s.sol`
`script/clientScripts/Application_Deploy_02_ApplicationFT1.s.sol`
`script/clientScripts/Application_Deploy_03_ApplicationFT2.s.sol`
`script/clientScripts/Application_Deploy_04_ApplicationNFT.s.sol`
`script/clientScripts/Application_Deploy_05_Oracle.s.sol`
`script/clientScripts/Application_Deploy_06_Pricing.s.sol`
These scripts deploy the contracts that are specific for applications, emulating the steps that a application dev would follow. They will deploy 2 ERC20s and 2 ERC721 tokens, among the other setup contracts.

If anvil is not listening to the commands in the scripts, make sure you have exported the local foundry profile `export FOUNDRY_PROFILE=local`.


<!-- These are the header links -->
[version-image]: https://img.shields.io/badge/Version-1.3.0-brightgreen?style=for-the-badge&logo=appveyor
[version-url]: https://github.com/thrackle-io/rules-protocol