// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {IDiamondInit} from "diamond-std/initializers/IDiamondInit.sol";
import {DiamondInit} from "diamond-std/initializers/DiamondInit.sol";
import {FacetCut, FacetCutAction} from "diamond-std/core/DiamondCut/DiamondCutLib.sol";
import {RuleProcessorDiamondArgs, RuleProcessorDiamond} from "src/protocol/economic/ruleProcessor/RuleProcessorDiamond.sol";
import {SampleFacet} from "diamond-std/core/test/SampleFacet.sol";
import {IDiamondCut} from "diamond-std/core/DiamondCut/IDiamondCut.sol";
import {TaggedRuleDataFacet} from "src/protocol/economic/ruleProcessor/TaggedRuleDataFacet.sol";
import {RuleDataFacet} from "src/protocol/economic/ruleProcessor/RuleDataFacet.sol";
import {DiamondScriptUtil} from "./DiamondScriptUtil.sol";
import {DeployABIUtil} from "./DeployABIUtil.sol";
import {VersionFacet} from "src/protocol/diamond/VersionFacet.sol";

/**
 * @title The final deployment script for the Protocol. It deploys the final set of facets.
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett, @mpetersoCode55
 * @notice This contract deploys the final set of facets for the protocol
 * @dev This script will set contract addresses needed by protocol interaction in connectAndSetUpAll()
 */

contract DeployAllModulesPt3Script is Script, DiamondScriptUtil, DeployABIUtil {
    /// Store the FacetCut struct for each facet that is being deployed.
    /// NOTE: using storage array to easily "push" new FacetCut as we
    /// process the facets.
    FacetCut[] private _facetCutsRuleProcessor;
    /// address and private key used to for deployment
    uint256 privateKey;
    address ownerAddress;
    bool recordAllChains;
    uint256 timestamp;
    string private constant VERSION="2.4.0";

    /**
     * @dev This is the main function that gets called by the Makefile or CLI
     */
    function run() external {
        timestamp = vm.envUint("DEPLOYMENT_TIMESTAMP");
        privateKey = vm.envUint("DEPLOYMENT_OWNER_KEY");
        ownerAddress = vm.envAddress("DEPLOYMENT_OWNER");
        recordAllChains = vm.envBool("RECORD_DEPLOYMENTS_FOR_ALL_CHAINS");
        vm.startBroadcast(privateKey);

        deployFacets();

        vm.stopBroadcast();
    }

    /**
     * @dev Deploy the set of facets
     */
    function deployFacets() internal {

        /// Register all facets.
        string[4] memory facets = [
            "RuleApplicationValidationFacet",
            "RuleDataFacet",
            "TaggedRuleDataFacet",
            "AppRuleDataFacet"
        ];

        string[4] memory directories = [
            "./out/RuleApplicationValidationFacet.sol/",
            "./out/RuleDataFacet.sol/",
            "./out/TaggedRuleDataFacet.sol/",
            "./out/AppRuleDataFacet.sol/"
        ];

        string[] memory getSelectorsInput = new string[](3);
        getSelectorsInput[0] = "python3";
        getSelectorsInput[1] = "script/python/get_selectors.py";

        /// Loop on each facet, deploy them and create the FacetCut.
        for (uint256 facetIndex = 0; facetIndex < facets.length; facetIndex++) {
            string memory facet = facets[facetIndex];
            string memory directory = directories[facetIndex];

            /// Deploy the facet.
            bytes memory bytecode = vm.getCode(string.concat(directory, string.concat(facet, ".json")));
            address facetAddress;
            assembly {
                facetAddress := create(0, add(bytecode, 0x20), mload(bytecode))
            }
            recordABI(facet, recordAllChains, timestamp);
            /// Get the facet selectors.
            getSelectorsInput[2] = facet;
            bytes memory res = vm.ffi(getSelectorsInput);
            bytes4[] memory selectors = abi.decode(res, (bytes4[]));

            /// Create the FacetCut struct for this facet.
            _facetCutsRuleProcessor.push(FacetCut({facetAddress: facetAddress, action: FacetCutAction.Add, functionSelectors: selectors}));
            recordFacet("ProtocolProcessorDiamond", facet, facetAddress, recordAllChains, timestamp);
        }

        address ruleProcessorAddress = vm.envAddress("RULE_PROCESSOR_DIAMOND");

        IDiamondCut(ruleProcessorAddress).diamondCut(_facetCutsRuleProcessor, address(0x0), "");

        // Set the version
        VersionFacet(ruleProcessorAddress).updateVersion(VERSION);

        setENVVariable("RECORD_DEPLOYMENTS_FOR_ALL_CHAINS", "false");
    }
}