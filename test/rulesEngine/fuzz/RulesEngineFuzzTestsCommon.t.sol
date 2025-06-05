/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "src/engine/facets/RulesEngineComponentFacet.sol";

abstract contract RulesEngineFuzzTestsCommon is RulesEngineCommon {

    /// Creation and update Fuzz Tests 
    // Rule creation 
    // 45   This single function is not the full fuzz test suite. Only serving as a stepping stone to further fuzz tests. TODO remove in fuzz test ticket
    function testRulesEngine_Fuzz_createRule_simple(uint256 ruleValue, uint256 transferValue) public {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        uint256 response;
        uint256[] memory policyIds = new uint256[](1); 
        policyIds[0] = _createBlankPolicy();
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(ruleValue);
        // Build the calling function argument placeholder 
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule);

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        // Save the calling function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0], 
            bytes4(keccak256(bytes(callingFunction))),
            pTypes,
            callingFunction,
            ""
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction))));  
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
         
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], callingFunctions, callingFunctionIds, ruleIds, PolicyType.CLOSED_POLICY);    
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);    
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), transferValue);
        if (ruleValue < transferValue) {
            response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
            assertEq(response, 1);
        } else if (ruleValue > transferValue){ 
            response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
            assertFalse(response == 1);
        }
    }

    function testRulesEngine_Fuzz_createPolicyAndAdmin_simple(uint8 addrIndex) public {
        testAddressArray.push(policyAdmin); 
        testAddressArray.push(newPolicyAdmin);

        vm.startPrank(policyAdmin); 
        uint256 policyID = _createBlankPolicy();

        address sender = testAddressArray[addrIndex % testAddressArray.length];
        vm.stopPrank();
        vm.startPrank(sender);

        if(sender == policyAdmin) {
            RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(newPolicyAdmin, policyID); 
            vm.stopPrank();
            vm.startPrank(newPolicyAdmin); 
            RulesEngineAdminRolesFacet(address(red)).confirmNewPolicyAdmin(policyID);
            RulesEnginePolicyFacet(address(red)).createPolicy(PolicyType.CLOSED_POLICY);
        } else {
            vm.expectRevert("Not Policy Admin");
            RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(newPolicyAdmin, policyID);
        }


    }


}
