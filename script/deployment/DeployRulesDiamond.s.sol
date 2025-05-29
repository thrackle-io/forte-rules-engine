/// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "forge-std/src/Script.sol";
import "src/engine/RulesEngineDiamond.sol";
import "src/utils/DiamondMine.sol";
import {IDiamondInit} from "diamond-std/initializers/IDiamondInit.sol";
import {DiamondInit} from "diamond-std/initializers/DiamondInit.sol";
import {FacetCut, FacetCutAction} from "diamond-std/core/DiamondCut/DiamondCutLib.sol";
import {IDiamondCut} from "diamond-std/core/DiamondCut/IDiamondCut.sol";
import "src/example/ExampleUserContract.sol";

/**
 * @title DeployRulesDiamond
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 * @dev This contract handles the deployment of the RulesEngineDiamond and ExampleUserContract.
 * It sets up the necessary environment variables and connects the deployed contracts.
 * The deployment process uses environment variables for the owner address and private key.
 * Additionally, it updates environment variables with the deployed contract addresses.
 */
contract DeployRulesDiamond is DiamondMine {

    /**
     * @notice Deploys the RulesEngineDiamond and ExampleUserContract, and sets up the environment variables.
     * @dev Uses environment variables for deployment owner address and private key.
     */
    function run() external {
        // Address and Private Key used for deployment
        address owner = vm.envAddress("DEPLOYMENT_OWNER");
        uint256 privateKey = vm.envUint("DEPLOYMENT_OWNER_KEY");
        
        vm.startBroadcast(privateKey);

        // Deploy the RulesEngineDiamond contract
        RulesEngineDiamond diamond = _createRulesEngineDiamond(owner);
        string memory diamondAddress = vm.toString(address(diamond));
        setENVAddress("DIAMOND_ADDRESS", diamondAddress);

        // Deploy the ExampleUserContract
        ExampleUserContract cont = new ExampleUserContract();
        string memory contractAddress = vm.toString(address(cont));
        setENVAddress("EXAMPLE_CONTRACT_ADDRESS", contractAddress);

        // Connect the ExampleUserContract to the RulesEngineDiamond and set the admin
        cont.setRulesEngineAddress(address(diamond));
        cont.setCallingContractAdmin(owner); 

        vm.stopBroadcast();
    }

    /**
     * @notice Sets an environment variable with the specified key and value.
     * @dev Uses a Python script to update the environment variable.
     * @param variable The name of the environment variable to set.
     * @param value The value to assign to the environment variable.
     */
    function setENVAddress(string memory variable, string memory value) internal {
        // Clear the value of the RULE_PROCESSOR_DIAMOND in the env file
        string[] memory setENVInput = new string[](4);
        setENVInput[0] = "python3";
        setENVInput[1] = "script/python/set_env_address.py";
        setENVInput[2] = variable;
        setENVInput[3] = value;
        vm.ffi(setENVInput);
    }

}
