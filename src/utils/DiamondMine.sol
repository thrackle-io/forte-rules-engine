/// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/RulesEngineDiamond.sol";
import "forge-std/src/Script.sol";
import "src/engine/facets/NativeFacet.sol";
import "src/engine/facets/RulesEngineProcessorFacet.sol";
import "src/engine/facets/RulesEnginePolicyFacet.sol";
import "src/engine/facets/RulesEngineRuleFacet.sol";
import "src/engine/facets/RulesEngineComponentFacet.sol";
import "src/engine/facets/RulesEngineForeignCallFacet.sol";
import "src/engine/facets/RulesEngineAdminRolesFacet.sol";
import "src/engine/facets/RulesEngineInitialFacet.sol";
import {IDiamondInit} from "diamond-std/initializers/IDiamondInit.sol";
import {DiamondInit} from "diamond-std/initializers/DiamondInit.sol";
import {FacetCut, FacetCutAction} from "diamond-std/core/DiamondCut/DiamondCutLib.sol";

/**
 * @title DiamondMine
 * @dev This contract is an abstract template for deploying and configuring a Rules Engine Diamond. It provides functionality
 *      to deploy the diamond, initialize it with facets, and set up the Rules Engine. The contract uses the diamond proxy
 *      pattern to enable modular and dynamic functionality.
 * @notice This contract is intended to be reused in scenarios where a Rules Engine Diamond needs to be deployed and configured.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract DiamondMine is Script {
    FacetCut[] _ruleProcessorFacetCuts;
    RulesEngineDiamond red;
    address constant OWNER = address(0xB0b);

    /**
     * @notice Deploy and set up the Rules Engine Diamond.
     * @dev This function deploys the diamond, initializes it with the required facets, and sets the owner.
     * @param owner The address to be set as the owner of the diamond.
     * @return diamond The fully configured Rules Engine Diamond.
     */
    function createRulesEngineDiamond(address owner) public returns (RulesEngineDiamond diamond) {
        delete _ruleProcessorFacetCuts;
        // Start by deploying the DiamonInit contract.
        DiamondInit diamondInit = new DiamondInit();

        // Build the DiamondArgs.
        RulesEngineDiamondArgs memory diamondArgs = RulesEngineDiamondArgs({
            init: address(diamondInit),
            // NOTE: "interfaceId" can be used since "init" is the only function in IDiamondInit.
            initCalldata: abi.encode(type(IDiamondInit).interfaceId)
        });

        // Protocol Facets

        // Native
        _ruleProcessorFacetCuts.push(
            FacetCut({
                facetAddress: address(new NativeFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArray("NativeFacet")
            })
        );

        // Main
        _ruleProcessorFacetCuts.push(
            FacetCut({
                facetAddress: address(new RulesEngineProcessorFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArray("RulesEngineProcessorFacet")
            })
        );

        // Data
        _ruleProcessorFacetCuts.push(
            FacetCut({
                facetAddress: address(new RulesEnginePolicyFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArray("RulesEnginePolicyFacet")
            })
        );

        // Data
        _ruleProcessorFacetCuts.push(
            FacetCut({
                facetAddress: address(new RulesEngineComponentFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArray("RulesEngineComponentFacet")
            })
        );

        // Data
        _ruleProcessorFacetCuts.push(
            FacetCut({
                facetAddress: address(new RulesEngineForeignCallFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArray("RulesEngineForeignCallFacet")
            })
        );

        // Data
        _ruleProcessorFacetCuts.push(
            FacetCut({
                facetAddress: address(new RulesEngineAdminRolesFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArray("RulesEngineAdminRolesFacet")
            })
        );

        // Data
        _ruleProcessorFacetCuts.push(
            FacetCut({
                facetAddress: address(new RulesEngineInitialFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArray("RulesEngineInitialFacet")
            })
        );

        // Data
        _ruleProcessorFacetCuts.push(
            FacetCut({
                facetAddress: address(new RulesEngineRuleFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArray("RulesEngineRuleFacet")
            })
        );

        /// Build the diamond
        // Deploy the diamond.
        RulesEngineDiamond rulesEngineInternal = new RulesEngineDiamond(_ruleProcessorFacetCuts, diamondArgs);
        RulesEngineInitialFacet(address(rulesEngineInternal)).initialize(owner);
        return rulesEngineInternal;
    }

    /**
     * @notice Create the selector array for a given facet.
     * @dev This function uses a Python script to generate the function selectors for the specified facet.
     * @param facet The name of the facet for which to generate selectors.
     * @return selectors The array of function selectors for the facet.
     */
    function createSelectorArray(string memory facet) public returns (bytes4[] memory selectors) {
        string[] memory _inputs = new string[](3);
        _inputs[0] = "python3";
        _inputs[1] = "script/python/get_selectors.py";
        _inputs[2] = facet;
        bytes memory res = vm.ffi(_inputs);
        return abi.decode(res, (bytes4[]));
    }

    /****************************** Non-cheatcode Diamond Deployment Methods ********************************************/
    function createSelectorArrayNoCheatcodes(string memory facet) internal pure returns (bytes4[] memory) {
        if (keccak256(abi.encodePacked(facet)) == keccak256(abi.encodePacked("RulesEnginePolicyFacet"))) {
            bytes4[] memory selectors = new bytes4[](13);
            selectors[0] = RulesEnginePolicyFacet.createPolicy.selector;
            selectors[1] = RulesEnginePolicyFacet.updatePolicy.selector;
            selectors[2] = RulesEnginePolicyFacet.getPolicy.selector;
            selectors[3] = RulesEnginePolicyFacet.applyPolicy.selector;
            selectors[4] = RulesEnginePolicyFacet.unapplyPolicy.selector;
            selectors[5] = RulesEnginePolicyFacet.getAppliedPolicyIds.selector;
            selectors[6] = RulesEnginePolicyFacet.cementPolicy.selector;
            selectors[7] = RulesEnginePolicyFacet.isCementedPolicy.selector;
            selectors[8] = RulesEnginePolicyFacet.isClosedPolicy.selector;
            selectors[9] = RulesEnginePolicyFacet.isDisabledPolicy.selector;
            selectors[10] = RulesEnginePolicyFacet.disablePolicy.selector;
            selectors[11] = RulesEnginePolicyFacet.openPolicy.selector;
            selectors[12] = RulesEnginePolicyFacet.closePolicy.selector;
            return selectors;
        } else if (keccak256(abi.encodePacked(facet)) == keccak256(abi.encodePacked("RulesEngineComponentFacet"))) {
            bytes4[] memory selectors = new bytes4[](8); // Only create enough slots for actual selectors
            selectors[0] = RulesEngineComponentFacet.createCallingFunction.selector;
            selectors[1] = RulesEngineComponentFacet.updateCallingFunction.selector;
            selectors[2] = RulesEngineComponentFacet.getCallingFunction.selector;
            selectors[3] = RulesEngineComponentFacet.deleteCallingFunction.selector;
            selectors[4] = RulesEngineComponentFacet.getAllCallingFunctions.selector;
            selectors[5] = RulesEngineComponentFacet.getTracker.selector;
            selectors[6] = RulesEngineComponentFacet.deleteTracker.selector;
            selectors[7] = RulesEngineComponentFacet.getAllTrackers.selector;
            return selectors;
        } else if (keccak256(abi.encodePacked(facet)) == keccak256(abi.encodePacked("RulesEngineForeignCallFacet"))) {
            bytes4[] memory selectors = new bytes4[](5); // Only create enough slots for actual selectors
            selectors[0] = RulesEngineForeignCallFacet.createForeignCall.selector;
            selectors[1] = RulesEngineForeignCallFacet.updateForeignCall.selector;
            selectors[2] = RulesEngineForeignCallFacet.getForeignCall.selector;
            selectors[3] = RulesEngineForeignCallFacet.deleteForeignCall.selector;
            selectors[4] = RulesEngineForeignCallFacet.getAllForeignCalls.selector;
            return selectors;
        } else if (keccak256(abi.encodePacked(facet)) == keccak256(abi.encodePacked("RulesEngineAdminRolesFacet"))) {
            bytes4[] memory selectors = new bytes4[](16); // Only create enough slots for actual selectors
            selectors[0] = RulesEngineAdminRolesFacet.proposeNewPolicyAdmin.selector;
            selectors[1] = RulesEngineAdminRolesFacet.confirmNewPolicyAdmin.selector;
            selectors[2] = RulesEngineAdminRolesFacet.isPolicyAdmin.selector;
            selectors[3] = RulesEngineAdminRolesFacet.generatePolicyAdminRole.selector;
            selectors[4] = RulesEngineAdminRolesFacet.proposeNewCallingContractAdmin.selector;
            selectors[5] = RulesEngineAdminRolesFacet.confirmNewCallingContractAdmin.selector;
            selectors[6] = RulesEngineAdminRolesFacet.isCallingContractAdmin.selector;
            selectors[7] = RulesEngineAdminRolesFacet.grantCallingContractRole.selector;
            selectors[8] = RulesEngineAdminRolesFacet.grantCallingContractRoleAccessControl.selector;
            selectors[9] = RulesEngineAdminRolesFacet.grantCallingContractRoleOwnable.selector;
            selectors[10] = RulesEngineAdminRolesFacet.grantForeignCallAdminRole.selector;
            selectors[11] = RulesEngineAdminRolesFacet.isForeignCallAdmin.selector;
            selectors[12] = RulesEngineAdminRolesFacet.proposeNewForeignCallAdmin.selector;
            selectors[13] = RulesEngineAdminRolesFacet.confirmNewForeignCallAdmin.selector;
            selectors[14] = AccessControlEnumerable.getRoleMemberCount.selector;
            selectors[15] = AccessControl.hasRole.selector;
            return selectors;
        } else if (keccak256(abi.encodePacked(facet)) == keccak256(abi.encodePacked("RulesEngineInitialFacet"))) {
            bytes4[] memory selectors = new bytes4[](1);
            selectors[0] = RulesEngineInitialFacet.initialize.selector;
            return selectors;
        } else if (keccak256(abi.encodePacked(facet)) == keccak256(abi.encodePacked("RulesEngineProcessorFacet"))) {
            bytes4[] memory selectors = new bytes4[](3);
            selectors[0] = RulesEngineProcessorFacet.checkPolicies.selector;
            selectors[1] = RulesEngineProcessorFacet.evaluateForeignCalls.selector;
            selectors[2] = RulesEngineProcessorFacet.evaluateForeignCallForRule.selector;
            return selectors;
        } else if (keccak256(abi.encodePacked(facet)) == keccak256(abi.encodePacked("RulesEngineRuleFacet"))) {
            bytes4[] memory selectors = new bytes4[](5);
            selectors[0] = RulesEngineRuleFacet.createRule.selector;
            selectors[1] = RulesEngineRuleFacet.updateRule.selector;
            selectors[2] = RulesEngineRuleFacet.getRule.selector;
            selectors[3] = RulesEngineRuleFacet.deleteRule.selector;
            selectors[4] = RulesEngineRuleFacet.getAllRules.selector;
            return selectors;
        }

        // Default return for unknown facets - empty array
        return new bytes4[](0);
    }

    // Implementation of createRulesEngineDiamond without cheatcodes
    function createRulesEngineDiamondNoCheatcodes(address owner) internal returns (RulesEngineDiamond diamond) {
        delete _ruleProcessorFacetCuts;
        // Start by deploying the DiamonInit contract.
        DiamondInit diamondInit = new DiamondInit();

        // Build the DiamondArgs.
        RulesEngineDiamondArgs memory diamondArgs = RulesEngineDiamondArgs({
            init: address(diamondInit),
            // NOTE: "interfaceId" can be used since "init" is the only function in IDiamondInit.
            initCalldata: abi.encode(type(IDiamondInit).interfaceId)
        });

        _ruleProcessorFacetCuts.push(
            FacetCut({
                facetAddress: address(new RulesEngineProcessorFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayNoCheatcodes("RulesEngineProcessorFacet")
            })
        );

        _ruleProcessorFacetCuts.push(
            FacetCut({
                facetAddress: address(new RulesEnginePolicyFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayNoCheatcodes("RulesEnginePolicyFacet")
            })
        );

        _ruleProcessorFacetCuts.push(
            FacetCut({
                facetAddress: address(new RulesEngineComponentFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayNoCheatcodes("RulesEngineComponentFacet")
            })
        );

        // Data
        _ruleProcessorFacetCuts.push(
            FacetCut({
                facetAddress: address(new RulesEngineForeignCallFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArray("RulesEngineForeignCallFacet")
            })
        );

        _ruleProcessorFacetCuts.push(
            FacetCut({
                facetAddress: address(new RulesEngineAdminRolesFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayNoCheatcodes("RulesEngineAdminRolesFacet")
            })
        );

        _ruleProcessorFacetCuts.push(
            FacetCut({
                facetAddress: address(new RulesEngineInitialFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayNoCheatcodes("RulesEngineInitialFacet")
            })
        );

        _ruleProcessorFacetCuts.push(
            FacetCut({
                facetAddress: address(new RulesEngineRuleFacet()),
                action: FacetCutAction.Add,
                functionSelectors: createSelectorArrayNoCheatcodes("RulesEngineRuleFacet")
            })
        );

        // Deploy the diamond and initialize
        RulesEngineDiamond rulesEngineInternal = new RulesEngineDiamond(_ruleProcessorFacetCuts, diamondArgs);

        RulesEngineInitialFacet(address(rulesEngineInternal)).initialize(owner);
        return rulesEngineInternal;
    }
}
