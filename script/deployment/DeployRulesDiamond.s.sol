// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "src/engine/RulesEngineDiamond.sol";
import "src/utils/DiamondMine.sol";
import {IDiamondInit} from "diamond-std/initializers/IDiamondInit.sol";
import {DiamondInit} from "diamond-std/initializers/DiamondInit.sol";
import {FacetCut, FacetCutAction} from "diamond-std/core/DiamondCut/DiamondCutLib.sol";
import {IDiamondCut} from "diamond-std/core/DiamondCut/IDiamondCut.sol";
import "src/example/ExampleUserContract.sol";

contract DeployRulesDiamond is DiamondMine {

    function run() external {
        // Address and Private Key used for deployment
        address owner = vm.envAddress("DEPLOYMENT_OWNER");
        uint256 privateKey = vm.envUint("DEPLOYMENT_OWNER_KEY");
        
        vm.startBroadcast(privateKey);

        RulesEngineDiamond diamond = _createRulesEngineDiamond(owner);
        string memory diamondAddress = vm.toString(address(diamond));
        setENVAddress("DIAMOND_ADDRESS", diamondAddress);

        ExampleUserContract cont = new ExampleUserContract();
        string memory contractAddress = vm.toString(address(cont));
        setENVAddress("EXAMPLE_CONTRACT_ADDRESS", contractAddress);

        vm.stopBroadcast();
    }

    function setENVAddress(string memory variable, string memory value) internal {
        /// we clear the value of the RULE_PROCESSOR_DIAMOND in the env file
        string[] memory setENVInput = new string[](4);
        setENVInput[0] = "python3";
        setENVInput[1] = "script/python/set_env_address.py";
        setENVInput[2] = variable;
        setENVInput[3] = value;
        vm.ffi(setENVInput);
    }

}