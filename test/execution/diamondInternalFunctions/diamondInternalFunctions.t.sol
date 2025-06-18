/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract diamondInternalFunctions is RulesEngineCommon {

    /**
    *
    *
    * Execution tests for the diamond internal functions 
    *
    *
    */
    function test_initialize_onlyOnce_negative() public ifDeploymentTestsEnabled{
        vm.expectRevert("Already initialized");
        RulesEngineInitialFacet(address(red)).initialize(
            address(this)
        );
        
    }


}
