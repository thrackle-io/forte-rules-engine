/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract RulesEngineFuzzTestsCommon is RulesEngineCommon {

    /// Creation and update Fuzz Tests 
    // Rule creation 
    // 45   This single function is not the full fuzz test suite. Only serving as a stepping stone to further fuzz tests. TODO remove in fuzz test ticket
    function testRulesEngine_Fuzz_createRule_simple(uint256 ruleValue, uint256 transferValue) public {
        uint256 response;
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
       Rule memory rule;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(ruleValue);
        // Build the calling function argument placeholder 
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType =PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0,rule);

       PT[] memory pTypes = new PT[](2);
        pTypes[0] =PT.ADDR;
        pTypes[1] =PT.UINT;
        // Save the function signature
        uint256 functionSignatureId = RulesEngineDataFacet(address(red)).updateFunctionSignature(0, bytes4(bytes(functionSignature)),pTypes);
        // Save the Policy
        signatures.push(bytes(functionSignature));  
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        uint256[] memory policyIds = new uint256[](1); 
        policyIds[0] = RulesEngineDataFacet(address(red)).updatePolicy(0, signatures, functionSignatureIds, ruleIds);        
        RulesEngineDataFacet(address(red)).applyPolicy(address(userContract), policyIds);
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly 
       Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] =PT.ADDR;
        arguments.argumentTypes[1] =PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(transferValue);
        bytes memory retVal = abi.encode(arguments);
        if (ruleValue < transferValue) {
            response = RulesEngineMainFacet(address(red)).checkPolicies(address(userContract), bytes(functionSignature), retVal);
            assertEq(response, 1);
        } else if (ruleValue > transferValue){ 
            response = RulesEngineMainFacet(address(red)).checkPolicies(address(userContract), bytes(functionSignature), retVal);
            assertFalse(response == 1);
        }
    }


}
