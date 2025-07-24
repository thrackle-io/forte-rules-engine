/// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "forge-std/src/Script.sol";
import "src/engine/ForteRulesEngine.sol";
import "src/utils/DiamondMine.sol";
import {IDiamondInit} from "diamond-std/initializers/IDiamondInit.sol";
import {DiamondInit} from "diamond-std/initializers/DiamondInit.sol";
import {FacetCut, FacetCutAction} from "diamond-std/core/DiamondCut/DiamondCutLib.sol";
import {IDiamondCut} from "diamond-std/core/DiamondCut/IDiamondCut.sol";
import {IDiamondLoupe} from "lib/diamond-std/core/DiamondLoupe/IDiamondLoupe.sol";
import {IERC173} from "lib/diamond-std/implementations/ERC173/IERC173.sol";

/**
 * @title DeployRulesDiamond
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 * @dev This contract handles the deployment of the ForteRulesEngine and ExampleUserContract.
 * It sets up the necessary environment variables and connects the deployed contracts.
 * The deployment process uses environment variables for the owner address and private key.
 * Additionally, it updates environment variables with the deployed contract addresses.
 */
contract DeployRulesDiamond is DiamondMine {
    /**
     * @notice Deploys the ForteRulesEngine and ExampleUserContract, and sets up the environment variables.
     * @dev Uses environment variables for deployment owner address and private key.
     */
    function run() external {
        // Validate environment before deployment
        validateEnvironment();

        address owner = vm.envAddress("DEPLOYMENT_OWNER");
        uint256 privateKey = vm.envUint("DEPLOYMENT_OWNER_KEY");

        console.log("Starting deployment with owner:", owner);

        vm.startBroadcast(privateKey);

        // Deploy the ForteRulesEngine contract
        ForteRulesEngine diamond = createRulesEngineDiamond(owner);

        vm.stopBroadcast();

        // Verify deployment
        verifyDeployment(address(diamond), owner);

        // Update environment variables
        string memory diamondAddress = vm.toString(address(diamond));
        setENVAddress("DIAMOND_ADDRESS", diamondAddress);

        console.log("Deployment completed successfully");
        console.log("Diamond address:", diamondAddress);
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

    /**
     * @notice Validates that all required environment variables are properly set before deployment.
     * @dev Checks for DEPLOYMENT_OWNER, DEPLOYMENT_OWNER_KEY, and ETH_RPC_URL environment variables.
     */
    function validateEnvironment() internal view {
        // Validate required environment variables
        require(vm.envAddress("DEPLOYMENT_OWNER") != address(0), "DEPLOYMENT_OWNER not set");
        require(vm.envUint("DEPLOYMENT_OWNER_KEY") != 0, "DEPLOYMENT_OWNER_KEY not set");
        require(bytes(vm.envString("ETH_RPC_URL")).length > 0, "ETH_RPC_URL not set");
    }

    /**
     * @notice Verifies that the diamond contract was deployed successfully and is properly configured.
     * @dev Performs comprehensive checks on the deployed diamond including code presence, ownership, and facet installation.
     * @param diamond The address of the deployed diamond contract to verify.
     * @param expectedOwner The expected owner address that should be set on the diamond.
     */
    function verifyDeployment(address diamond, address expectedOwner) internal view {
        // Verify diamond is deployed
        require(diamond != address(0), "Diamond not deployed");
        require(diamond.code.length > 0, "Diamond has no code");

        // Verify owner is set correctly
        require(IERC173(diamond).owner() == expectedOwner, "Owner mismatch");

        // Verify facets are properly installed
        IDiamondLoupe.Facet[] memory facets = IDiamondLoupe(diamond).facets();
        require(facets.length > 0, "No facets installed");

        console.log("Deployment verified successfully");
        console.log("Facets installed:", facets.length);
    }
}
