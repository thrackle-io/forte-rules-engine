// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "src/engine/RulesEngineDiamond.sol";
import "src/engine/facets/NativeFacet.sol";
import "src/engine/facets/RulesEngineMainFacet.sol";
import "src/engine/facets/RulesEngineDataFacet.sol";
import "lib/forge-std/src/Test.sol";
import {IDiamondInit} from "diamond-std/initializers/IDiamondInit.sol";
import {DiamondInit} from "diamond-std/initializers/DiamondInit.sol";
import {FacetCut, FacetCutAction} from "diamond-std/core/DiamondCut/DiamondCutLib.sol";


/**
 * @title Test Common Foundry
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev This contract is an abstract template to be reused by all the Foundry tests. NOTE: function prefixes and their usages are as follows:
 * setup = set to proper user, deploy contracts, set global variables, reset user
 * create = set to proper user, deploy contracts, reset user, return the contract
 * _create = deploy contract, return the contract
 */
abstract contract DiamondMine is Test {
    FacetCut[] _ruleProcessorFacetCuts;
    RulesEngineDiamond red;
    address constant OWNER = address(0xB0b);
   
   /**
     * @dev Deploy and set up the Rules Engine Diamond
     * @return diamond fully configured rules engine diamond
     */
    function _createRulesEngineDiamond() public returns (RulesEngineDiamond diamond) {
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
        _ruleProcessorFacetCuts.push(FacetCut({facetAddress: address(new NativeFacet()), action: FacetCutAction.Add, functionSelectors: _createSelectorArray("NativeFacet")}));

        // Main
        _ruleProcessorFacetCuts.push(FacetCut({facetAddress: address(new RulesEngineMainFacet()), action: FacetCutAction.Add, functionSelectors: _createSelectorArray("RulesEngineMainFacet")}));

        // Data 
        _ruleProcessorFacetCuts.push(FacetCut({facetAddress: address(new RulesEngineDataFacet()), action: FacetCutAction.Add, functionSelectors: _createSelectorArray("RulesEngineDataFacet")}));

        /// Build the diamond
        // Deploy the diamond.
        RulesEngineDiamond rulesEngineInternal = new RulesEngineDiamond(_ruleProcessorFacetCuts, diamondArgs);
        RulesEngineMainFacet(address(rulesEngineInternal)).initialize(OWNER);
        return rulesEngineInternal;
    }

    /**
     * @dev Create the selector array for the facet
     * @return _selectors loaded selector array
     */
    function _createSelectorArray(string memory _facet) public returns (bytes4[] memory _selectors) {
        string[] memory _inputs = new string[](3);
        _inputs[0] = "python3";
        _inputs[1] = "script/python/get_selectors.py";
        _inputs[2] = _facet;
        bytes memory res = vm.ffi(_inputs);
        return abi.decode(res, (bytes4[]));
    }

    }