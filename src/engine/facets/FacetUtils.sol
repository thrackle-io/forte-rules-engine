// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {RulesEngineDiamondLib, RulesEngineDiamondStorage} from "src/engine/RulesEngineDiamondLib.sol";

contract FacetUtils{

    function callAnotherFacet(bytes4 _functionSelector, bytes memory _callData) internal returns(bool success, bytes memory res){
        RulesEngineDiamondStorage storage ds = RulesEngineDiamondLib.s();
        address facet = ds.facetAddressAndSelectorPosition[_functionSelector].facetAddress;
        (success, res) = address(facet).delegatecall(_callData);
        if (!success) assembly {revert(add(res,0x20),mload(res))}
    }

}