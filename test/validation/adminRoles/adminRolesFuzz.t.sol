/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract adminRolesFuzz is RulesEngineCommon {
    /**
     *
     *
     * Validation fuzz tests for the admin roles within the rules engine
     *
     *
     */

    function testRulesEngine_Fuzz_createPolicyAndAdmin_simple(uint8 addrIndex) public {
        testAddressArray.push(policyAdmin);
        testAddressArray.push(newPolicyAdmin);

        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();

        address sender = testAddressArray[addrIndex % testAddressArray.length];
        vm.stopPrank();
        vm.startPrank(sender);

        if (sender == policyAdmin) {
            RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(newPolicyAdmin, policyID);
            vm.stopPrank();
            vm.startPrank(newPolicyAdmin);
            RulesEngineAdminRolesFacet(address(red)).confirmNewPolicyAdmin(policyID);
            RulesEnginePolicyFacet(address(red)).createPolicy(PolicyType.CLOSED_POLICY, policyName, policyDescription);
        } else {
            vm.expectRevert("Not Policy Admin");
            RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(newPolicyAdmin, policyID);
        }
    }

    function testRulesEngine_Fuzz_createForeignCallAdmin(uint8 addrIndex) public {
        // For a given Foreign contract and selector pair, the Foreign Call Admin is the only one who can configure which Policy Admins may leverage the Foreign Call in their policies
    }
}
