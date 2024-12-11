// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "src/engine/RulesEngineDiamond.sol";
import {IDiamondInit} from "diamond-std/initializers/IDiamondInit.sol";
import {DiamondInit} from "diamond-std/initializers/DiamondInit.sol";
import {FacetCut, FacetCutAction} from "diamond-std/core/DiamondCut/DiamondCutLib.sol";
import {IDiamondCut} from "diamond-std/core/DiamondCut/IDiamondCut.sol";

contract DeployRulesDiamond is Script {

    function run() external {
        // Address and Private Key used for deployment
        uint256 privateKey = vm.envUint("DEPLOYMENT_OWNER_KEY");
        
        vm.startBroadcast(privateKey);

        RulesEngineDiamond diamond = deployDiamond();
        string memory diamondAddress = vm.toString(address(diamond));
        setENVAddress("DIAMOND_ADDRESS", diamondAddress);

        vm.stopBroadcast();
    }

    function deployDiamond() public returns (RulesEngineDiamond) {
        DiamondInit diamondInit = new DiamondInit();
        FacetCut[] memory _facetCuts = new FacetCut[](2);

        string[2] memory facets = [
            "RulesEngineMainFacet",
            "RulesEngineDataFacet"
        ];

        string[2] memory directories = [
            "./out/RulesEngineMainFacet.sol/",
            "./out/RulesEngineDataFacet.sol/"
        ];

        string[] memory getSelectorsInput = new string[](3);
        getSelectorsInput[0] = "python3";
        getSelectorsInput[1] = "script/python/get_selectors.py";

        // Loop on each facet, deploy them and create the FacetCut.
        for (uint256 facetIndex = 0; facetIndex < facets.length; facetIndex++) {
            string memory facet = facets[facetIndex];
            string memory directory = directories[facetIndex];

            /// Deploy the facet.
            bytes memory bytecode = vm.getCode(string.concat(directory, string.concat(facet, ".json")));
            address facetAddress;
            assembly {
                facetAddress := create(0, add(bytecode, 0x20), mload(bytecode))
            }

            // Get the facet selectors.
            getSelectorsInput[2] = facet;
            bytes memory res = vm.ffi(getSelectorsInput);
            bytes4[] memory selectors = abi.decode(res, (bytes4[]));

            // Create the FacetCut struct for this facet.
            _facetCuts[facetIndex] = FacetCut({facetAddress: facetAddress, action: FacetCutAction.Add, functionSelectors: selectors});
        }

        // Build the DiamondArgs.
        RulesEngineDiamondArgs memory diamondArgs = RulesEngineDiamondArgs({
            init: address(diamondInit),
            // NOTE: "interfaceId" can be used since "init" is the only function in IDiamondInit.
            initCalldata: abi.encode(type(IDiamondInit).interfaceId)
        });
        /// Build the diamond
        RulesEngineDiamond handlerInternal = new RulesEngineDiamond(_facetCuts, diamondArgs);

        // Deploy the diamond.
        return handlerInternal;
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