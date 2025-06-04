/// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/RulesEngineDiamond.sol";
import "forge-std/src/Script.sol";
import "src/engine/facets/NativeFacet.sol";
import "src/engine/facets/RulesEngineProcessorFacet.sol";
import "src/engine/facets/RulesEnginePolicyFacet.sol";
import "src/engine/facets/RulesEngineRuleFacet.sol";
import "src/engine/facets/RulesEngineComponentFacet.sol";
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
    function createRulesEngineDiamond(
        address owner
    ) public returns (RulesEngineDiamond diamond) {
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
        RulesEngineDiamond rulesEngineInternal = new RulesEngineDiamond(
            _ruleProcessorFacetCuts,
            diamondArgs
        );
        RulesEngineInitialFacet(address(rulesEngineInternal)).initialize(owner);
        return rulesEngineInternal;
    }

    /**
     * @notice Create the selector array for a given facet.
     * @dev This function uses a Python script to generate the function selectors for the specified facet.
     * @param facet The name of the facet for which to generate selectors.
     * @return selectors The array of function selectors for the facet.
     */
    function createSelectorArray(
        string memory facet
    ) public returns (bytes4[] memory selectors) {
        string[] memory _inputs = new string[](3);
        _inputs[0] = "python3";
        _inputs[1] = "script/python/get_selectors.py";
        _inputs[2] = facet;
        bytes memory res = vm.ffi(_inputs);
        return abi.decode(res, (bytes4[]));
    }
}
