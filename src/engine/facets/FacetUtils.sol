// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {RulesEngineDiamondLib, RulesEngineDiamondStorage} from "src/engine/RulesEngineDiamondLib.sol";

/**
 * @title Facet Utilities
 * @dev This contract provides utility functions for interacting with other facets in the Rules Engine.
 *      It includes functionality for performing delegate calls to other facets using their function selectors.
 * @notice This contract is intended to be used internally by facets in the Rules Engine to streamline cross-facet interactions.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract FacetUtils{

    /**
     * @notice Performs a delegate call to another facet in the Rules Engine.
     * @dev Uses the function selector to locate the target facet and executes the provided call data.
     *      Reverts with the returned error message if the delegate call fails.
     * @param _functionSelector The function selector of the target function in the other facet.
     * @param _callData The encoded call data to pass to the target function.
     * @return success A boolean indicating whether the delegate call was successful.
     * @return res The returned data from the delegate call.
     */
    function callAnotherFacet(bytes4 _functionSelector, bytes memory _callData) internal returns(bool success, bytes memory res){
        RulesEngineDiamondStorage storage ds = RulesEngineDiamondLib.s();
        address facet = ds.facetAddressAndSelectorPosition[_functionSelector].facetAddress;
        (success, res) = address(facet).delegatecall(_callData);
        if (!success) assembly {revert(add(res,0x20),mload(res))}
    }

}