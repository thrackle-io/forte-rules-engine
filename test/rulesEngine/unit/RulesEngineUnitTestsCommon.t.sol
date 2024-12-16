/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract RulesEngineUnitTestsCommon is RulesEngineCommon {

    
    /// TestRulesEngine: 
    // Test attempt to add a policy with no signatures saved.
    function testRulesEngine_Unit_UpdatePolicy_InvalidRule() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        // Save the function signature
        uint256 functionSignatureId = RulesEngineDataFacet(address(red)).updateFunctionSignature(0, bytes4(bytes(functionSignature)),pTypes);
        signatures.push(bytes(functionSignature));  
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= 1;
        vm.expectRevert("Invalid Rule");
        RulesEngineDataFacet(address(red)).updatePolicy(policyId, signatures, functionSignatureIds, ruleIds);
    }

    // Test attempt to add a policy with no signatures saved.
    function testRulesEngine_Unit_UpdatePolicy_InvalidSignature() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        signatures.push(bytes(functionSignature));  
        functionSignatureIds.push(1);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= 1;
        vm.expectRevert("Invalid Signature");
        RulesEngineDataFacet(address(red)).updatePolicy(policyId, signatures, functionSignatureIds, ruleIds);
    }

    // Test attempt to add a policy with valid parts.
    function testRulesEngine_Unit_UpdatePolicy_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Instruction set: LC.PLH, 0, LC.NUM, 4, LC.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);

        // Build the calling function argument placeholder 
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0,rule);
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        // Save the function signature
        uint256 functionSignatureId = RulesEngineDataFacet(address(red)).updateFunctionSignature(0, bytes4(bytes(functionSignature)),pTypes);
        // Save the Policy
        signatures.push(bytes(functionSignature));  
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        assertGt(RulesEngineDataFacet(address(red)).updatePolicy(0, signatures, functionSignatureIds, ruleIds),0);        

    }

    function testRulesEngine_Unit_CheckRules_Explicit() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithoutForeignCall();
        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(5);
        bytes memory retVal = abi.encode(arguments);
        uint256 response = RulesEngineMainFacet(address(red)).checkPolicies(address(userContract), bytes(functionSignature), retVal);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_checkRule_simple_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithoutForeignCall();
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly 
        bool response = userContract.transfer(address(0x7654321), 47);
        assertTrue(response);
    }

    function testRulesEngine_Unit_checkRule_simple_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithoutForeignCall();
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly 
        bool response = userContract.transfer(address(0x7654321), 3);
        assertFalse(response);
    }

    function testRulesEngine_Unit_createRule_ForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 ruleValue = 10; 
        uint256 transferValue = 15;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"        
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1); 
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(ruleValue);
        // Build the mapping between calling function arguments and foreign call arguments
        rule.fcArgumentMappingsConditions = new ForeignCallArgumentMappings[](1);
        rule.fcArgumentMappingsConditions[0].mappings = new IndividualArgumentMapping[](1);
        rule.fcArgumentMappingsConditions[0].mappings[0].functionCallArgumentType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.foreignCall = false;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.pType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0,rule);
        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        RulesEngineDataFacet(address(red)).updateForeignCall(policyIds[0], address(testContract), "simpleCheck(uint256)", PT.UINT, fcArgs);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);       
        RulesEngineDataFacet(address(red)).applyPolicy(address(userContract), policyIds); 

        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(transferValue);
        bytes memory retVal = abi.encode(arguments);

        uint256 response = RulesEngineMainFacet(address(red)).checkPolicies(address(userContract), bytes(functionSignature), retVal);
        assertEq(response, 1);
        
    }

    function testRulesEngine_Unit_createRule_ForeignCall_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 ruleValue = 15; 
        uint256 transferValue = 10;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"        
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1); 
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(ruleValue);
        // Build the mapping between calling function arguments and foreign call arguments
        rule.fcArgumentMappingsConditions = new ForeignCallArgumentMappings[](1);
        rule.fcArgumentMappingsConditions[0].mappings = new IndividualArgumentMapping[](1);
        rule.fcArgumentMappingsConditions[0].mappings[0].functionCallArgumentType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.foreignCall = false;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.pType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0,rule);
        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        RulesEngineDataFacet(address(red)).updateForeignCall(policyIds[0], address(testContract), "simpleCheck(uint256)", PT.UINT, fcArgs);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);       
        RulesEngineDataFacet(address(red)).applyPolicy(address(userContract), policyIds); 

        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(transferValue);
        bytes memory retVal = abi.encode(arguments);

        vm.expectRevert(abi.encodePacked(revert_text)); 
        RulesEngineMainFacet(address(red)).checkPolicies(address(userContract), bytes(functionSignature), retVal);
    }

    function testRulesEngine_Unit_checkRule_ForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 ruleValue = 10; 
        uint256 transferValue = 15;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"        
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1); 
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(ruleValue);
        // Build the mapping between calling function arguments and foreign call arguments
        rule.fcArgumentMappingsConditions = new ForeignCallArgumentMappings[](1);
        rule.fcArgumentMappingsConditions[0].mappings = new IndividualArgumentMapping[](1);
        rule.fcArgumentMappingsConditions[0].mappings[0].functionCallArgumentType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.foreignCall = false;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.pType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0,rule);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        RulesEngineDataFacet(address(red)).updateForeignCall(policyIds[0], address(testContract), "simpleCheck(uint256)", PT.UINT, fcArgs);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);       
        RulesEngineDataFacet(address(red)).applyPolicy(address(userContract), policyIds);
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly 
        bool response = userContract.transfer(address(0x7654321), transferValue);
        assertTrue(response);
    }

    function testRulesEngine_Unit_checkRule_ForeignCall_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 ruleValue = 15; 
        uint256 transferValue = 10;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"        
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1); 
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(ruleValue);
        // Build the mapping between calling function arguments and foreign call arguments
        rule.fcArgumentMappingsConditions = new ForeignCallArgumentMappings[](1);
        rule.fcArgumentMappingsConditions[0].mappings = new IndividualArgumentMapping[](1);
        rule.fcArgumentMappingsConditions[0].mappings[0].functionCallArgumentType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.foreignCall = false;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.pType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0,rule);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        RulesEngineDataFacet(address(red)).updateForeignCall(policyIds[0], address(testContract), "simpleCheck(uint256)", PT.UINT, fcArgs);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);       
        RulesEngineDataFacet(address(red)).applyPolicy(address(userContract), policyIds);
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly 
        vm.expectRevert(abi.encodePacked(revert_text)); 
        userContract.transfer(address(0x7654321), transferValue);
    }

    function testRulesEngine_Unit_CheckPolicies_Explicit_StringComparison_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithStringComparison();
        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.STR;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode("Bad Info");
        bytes memory retVal = abi.encode(arguments);
        uint256 response = RulesEngineMainFacet(address(red)).checkPolicies(address(userContract), bytes(functionSignature2), retVal);
        assertEq(response, 1);
    }

        function testRulesEngine_Unit_CheckPolicies_Explicit_StringComparison_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithStringComparison();
        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.STR;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode("test");
        bytes memory retVal = abi.encode(arguments);
        uint256 response = RulesEngineMainFacet(address(red)).checkPolicies(address(userContract), bytes(functionSignature2), retVal);
        assertEq(response, 0);
    }

    function testRulesEngine_Unit_RetrieveRawStringFromInstructionSet() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 ruleId = setupRuleWithStringComparison();
        StringVerificationStruct memory retVal = RulesEngineMainFacet(address(red)).retrieveRawStringFromInstructionSet(ruleId, 3);
        console2.log(retVal.instructionSetValue);
        console2.log(retVal.rawData);
        assertEq(retVal.instructionSetValue, uint256(keccak256(abi.encode(retVal.rawData))));
    }

    function testRulesEngine_Unit_CheckPolicies_Explicit_AddressComparison_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithAddressComparison();
        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.STR;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x1234567));
        arguments.values[1] = abi.encode("test");
        bytes memory retVal = abi.encode(arguments);
        uint256 response = RulesEngineMainFacet(address(red)).checkPolicies(address(userContract), bytes(functionSignature2), retVal);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_CheckPolicies_Explicit_AddressComparison_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithAddressComparison();
        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.STR;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode("test");
        bytes memory retVal = abi.encode(arguments);
        uint256 response = RulesEngineMainFacet(address(red)).checkPolicies(address(userContract), bytes(functionSignature2), retVal);
        assertEq(response, 0);
    }

    function testRulesEngine_Unit_RetrieveRawAddressFromInstructionSet() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 ruleId = setupRuleWithAddressComparison();
        AddressVerificationStruct memory retVal = RulesEngineMainFacet(address(red)).retrieveRawAddressFromInstructionSet(ruleId, 3);
        console2.log(retVal.instructionSetValue);
        console2.log(retVal.rawData);
        assertEq(retVal.instructionSetValue, uint256(uint160(address(retVal.rawData))));
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCall(4, ET.REVERT, false);
        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(5);
        bytes memory retVal = abi.encode(arguments);

        uint256 response = RulesEngineMainFacet(address(red)).checkPolicies(address(userContract), bytes(functionSignature), retVal);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithForeignCallEffect() public ifDeploymentTestsEnabled endWithStopPrank {
        setupEffectWithForeignCall();
        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(5);
        bytes memory retVal = abi.encode(arguments);
        // The Foreign call will be placed during the effect for the single rule in this policy.
        // The value being set in the foreign contract is then polled to verify that it has been udpated.
        RulesEngineMainFacet(address(red)).checkPolicies(address(userContract), bytes(functionSignature), retVal);
        assertEq(testContract.getInternalValue(), 5);
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithTrackerUpdateEffect() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = setupEffectWithTrackerUpdate();
        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(5);
        bytes memory retVal = abi.encode(arguments);
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the foreign call (simpleCheck) added to it. 
        // original tracker value 2, added value 5, resulting updated tracker value should be 7
        RulesEngineMainFacet(address(red)).checkPolicies(address(userContract), bytes(functionSignature), retVal);
        Trackers memory tracker = RulesEngineDataFacet(address(red)).getTracker(policyId, 1);
        assertEq(tracker.trackerValue, abi.encode(7));
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithForeignCallNegative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCall(4, ET.REVERT, false);
        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(3);
        bytes memory retVal = abi.encode(arguments);
        vm.expectRevert(abi.encodePacked(revert_text)); 
        RulesEngineMainFacet(address(red)).checkPolicies(address(userContract), bytes(functionSignature), retVal);
    }

    /// Ensure that rule with a negative effect revert applied, that passes, will revert
    function testRulesEngine_Unit_CheckRules_WithExampleContract_Negative_Revert() public ifDeploymentTestsEnabled endWithStopPrank {
        _setupRuleWithRevert();
        vm.expectRevert(abi.encodePacked(revert_text)); 
        userContract.transfer(address(0x7654321), 3);
    }

    /// Ensure that rule with a positive effect event applied, that passes, will emit the event
    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        _setupRuleWithPosEvent();
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text);
        userContract.transfer(address(0x7654321), 5);
    }

    // Ensure that a policy with multiple rules with positive events fire in the correct order
    function testRulesEngine_Unit_CheckPolicy_ExecuteRuleOrder() public ifDeploymentTestsEnabled endWithStopPrank {
        _setupPolicyWithMultipleRulesWithPosEvents();
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text2);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text2);
        userContract.transfer(address(0x7654321), 11);
    }

    /// Ensure that rule with a positive effect event applied, that passes, will emit the event
    function testRulesEngine_Unit_CheckRules_WithExampleContract_Multiple_Positive_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        _setupRuleWith2PosEvent();
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text2);
        userContract.transfer(address(0x7654321), 11);
    }

    function testRulesEngine_Unit_EncodingForeignCall() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSig(uint256,string,uint256,string,address)";

        PT[] memory parameterTypes = new PT[](5);
        parameterTypes[0] = PT.UINT;
        parameterTypes[1] = PT.STR;
        parameterTypes[2] = PT.UINT;
        parameterTypes[3] = PT.STR;
        parameterTypes[4] = PT.ADDR;

        bytes[] memory vals = new bytes[](5);
        vals[0] = abi.encode(1);
        vals[1] = abi.encode("test");
        vals[2] = abi.encode(2);
        vals[3] = abi.encode("superduperduperduperduperduperduperduperduperduperlongstring");
        vals[4] = abi.encode(address(0x1234567));

        uint256[] memory dynamicVarLengths = new uint256[](2);
        dynamicVarLengths[0] = 4;
        dynamicVarLengths[1] = 44;

        bytes4 FUNC_SELECTOR = bytes4(keccak256(bytes(functionSig)));

        bytes memory argsEncoded = RulesEngineMainFacet(address(red)).assemblyEncode(parameterTypes, vals, FUNC_SELECTOR, dynamicVarLengths);
        
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        (bool response, bytes memory data) = address(foreignCall).call(argsEncoded);
        assertEq(foreignCall.getDecodedIntOne(), 1);
        assertEq(foreignCall.getDecodedIntTwo(), 2);
        assertEq(foreignCall.getDecodedStrOne(), "test");
        assertEq(foreignCall.getDecodedStrTwo(), "superduperduperduperduperduperduperduperduperduperlongstring");
        assertEq(foreignCall.getDecodedAddr(), address(0x1234567));
        response; 
        data; // added to silence warnings - we should have these in an assertion 
    }

    function testRulesEngine_Unit_EvaluateForeignCallForRule() public ifDeploymentTestsEnabled endWithStopPrank {
        ForeignCall memory fc;
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        string memory functionSig = "testSig(uint256,string,uint256,string,address)";

        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.foreignCallIndex = 0;
        fc.returnType = PT.BOOL;

        fc.parameterTypes = new PT[](5);
        fc.parameterTypes[0] = PT.UINT;
        fc.parameterTypes[1] = PT.STR;
        fc.parameterTypes[2] = PT.UINT;
        fc.parameterTypes[3] = PT.STR;
        fc.parameterTypes[4] = PT.ADDR;

        Arguments memory functionArguments;
        // rule signature function arguments (RS): string, uint256, uint256, string, uint256, string, address
        // foreign call function arguments (FC): uint256, string, uint256, string, address
        //
        // Mapping:
        // FC index: 0 1 2 3 4
        // RS index: 1 3 4 5 6

        // Build the rule signature function arguments structure
        functionArguments.argumentTypes = new PT[](7);
        functionArguments.argumentTypes[0] = PT.STR;
        functionArguments.argumentTypes[1] = PT.UINT;
        functionArguments.argumentTypes[2] = PT.UINT;
        functionArguments.argumentTypes[3] = PT.STR;
        functionArguments.argumentTypes[4] = PT.UINT;
        functionArguments.argumentTypes[5] = PT.STR;
        functionArguments.argumentTypes[6] = PT.ADDR;

        functionArguments.values = new bytes[](6);
        functionArguments.values[0] = abi.encode("one");
        functionArguments.values[1] = abi.encode(2);
        functionArguments.values[2] = abi.encode(3);
        functionArguments.values[3] = abi.encode("four");
        functionArguments.values[4] = abi.encode(5);
        functionArguments.values[5] = abi.encode(address(0x12345678));

        Rule memory rule;

        // Build the mapping between calling function arguments and foreign call arguments
        rule.fcArgumentMappingsConditions = new ForeignCallArgumentMappings[](1);
        rule.fcArgumentMappingsConditions[0].foreignCallIndex = 0;
        rule.fcArgumentMappingsConditions[0].mappings = new IndividualArgumentMapping[](5);

        rule.fcArgumentMappingsConditions[0].mappings[0].functionCallArgumentType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.pType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.typeSpecificIndex = 1;

        rule.fcArgumentMappingsConditions[0].mappings[1].functionCallArgumentType = PT.STR;
        rule.fcArgumentMappingsConditions[0].mappings[1].functionSignatureArg.pType = PT.STR;
        rule.fcArgumentMappingsConditions[0].mappings[1].functionSignatureArg.typeSpecificIndex = 0;

        rule.fcArgumentMappingsConditions[0].mappings[2].functionCallArgumentType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[2].functionSignatureArg.pType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[2].functionSignatureArg.typeSpecificIndex = 2;

        rule.fcArgumentMappingsConditions[0].mappings[3].functionCallArgumentType = PT.STR;
        rule.fcArgumentMappingsConditions[0].mappings[3].functionSignatureArg.pType = PT.STR;
        rule.fcArgumentMappingsConditions[0].mappings[3].functionSignatureArg.typeSpecificIndex = 3;

        rule.fcArgumentMappingsConditions[0].mappings[4].functionCallArgumentType = PT.ADDR;
        rule.fcArgumentMappingsConditions[0].mappings[4].functionSignatureArg.pType = PT.ADDR;
        rule.fcArgumentMappingsConditions[0].mappings[4].functionSignatureArg.typeSpecificIndex = 5;

        ForeignCallReturnValue memory retVal = RulesEngineMainFacet(address(red)).evaluateForeignCallForRule(fc, rule.fcArgumentMappingsConditions, functionArguments);
        console2.logBytes(retVal.value);
    }

    function testRulesEngine_Unit_CheckRules_WithTrackerValue() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithTracker(2);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text);
        bool retVal = userContract.transfer(address(0x7654321), 3);
        assertTrue(retVal);
    }

    function testRulesEngine_Unit_CheckRules_WithTrackerValue_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithTracker(7);
        vm.expectRevert(abi.encodePacked(revert_text)); 
        userContract.transfer(address(0x7654321), 6);
    }

    function testRulesEngine_Unit_CheckRules_ManualUpdateToTracker() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = setupRuleWithTracker(4);
        bool retVal = userContract.transfer(address(0x7654321), 5);
        assertTrue(retVal); 
        // expect failure here 
        vm.expectRevert(abi.encodePacked(revert_text)); 
        retVal = userContract.transfer(address(0x7654321), 3);
        /// manually update the tracker here to higher value so that rule fails
        //                  calling contract,  updated uint, empty address, empty string, bool, empty bytes 
        RulesEngineDataFacet(address(red)).updateTracker(policyId, 7, address(0x00), "", true, ""); 

        vm.expectRevert(abi.encodePacked(revert_text)); 
        retVal = userContract.transfer(address(0x7654321), 4);

        retVal = userContract.transfer(address(0x7654321), 9);
        assertTrue(retVal);
    }

    // Tracker creation 
    function testRulesEngine_Unit_createRule_Tracker_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithTracker(10);
        uint256 transferValue = 15;

        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(transferValue);
        bytes memory retVal = abi.encode(arguments);

        uint256 response = RulesEngineMainFacet(address(red)).checkPolicies(address(userContract), bytes(functionSignature), retVal);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_createRule_Tracker_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
         setupRuleWithTracker(15);
        uint256 transferValue = 10;

        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(transferValue);
        bytes memory retVal = abi.encode(arguments);

        vm.expectRevert(abi.encodePacked(revert_text)); 
        RulesEngineMainFacet(address(red)).checkPolicies(address(userContract), bytes(functionSignature), retVal);

    }

    function testRulesEngine_Unit_GetTrackerValue() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = setupRuleWithTracker(2);
        bool retVal = userContract.transfer(address(0x7654321), 3);
        assertTrue(retVal);

        Trackers memory testTracker = RulesEngineDataFacet(address(red)).getTracker(policyId, 1); 

        assertTrue(abi.decode(testTracker.trackerValue, (uint256)) == 2); 
        assertFalse(abi.decode(testTracker.trackerValue, (uint256)) == 3); 

    }

    function testRulesEngine_Unit_UpdatePolicy_ValidatesForeignCalls() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        
        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].foreignCall = true;

        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        vm.expectRevert("Foreign Call referenced in rule not set");
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
    }

    function testRulesEngine_Unit_UpdatePolicy_ValidatesTrackers() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Instruction set: LC.PLH, 0, LC.PLH, 1, LC.GT, 0, 1
        rule.instructionSet = _createInstructionSet(0,1);
        
        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].trackerValue = true;

        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        vm.expectRevert("Tracker referenced in rule not set");
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
    }


    /// Test utility functions within ExampleUserContract.sol and RulesEngineRunRulesEngineMainFacet(address(red)).sol 
    function testRulesEngine_Utils_UserContract_setRulesEngineAddress() public ifDeploymentTestsEnabled endWithStopPrank {
        userContract.setRulesEngineAddress(address(red));
        assertTrue(userContract.rulesEngineAddress() == address(red)); 
    }

    function testRulesEngine_Utils_uintToBool() public ifDeploymentTestsEnabled endWithStopPrank {
        bool success = RulesEngineMainFacet(address(red)).ui2bool(1); 
        assertTrue(success); 
    }

    function testRulesEngine_Utils_BoolToUint() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 success = RulesEngineMainFacet(address(red)).bool2ui(false); 
        assertTrue(success == 0);
    }

    function testRulesEngine_Utils_deleteEffect() public ifDeploymentTestsEnabled endWithStopPrank {
        Effect memory effectIdToDelete = _createEffectEvent("Event"); 
        RulesEngineDataFacet(address(red)).deleteEffect(effectIdToDelete.effectId);
    }

    function testRulesEngine_Utils_evaluateRulesAndExecuteEffects() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);
        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule =  _createGTRule(4);
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0,rule);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(address(userContract), policyIds);

        Rule[] memory applicableRules = new Rule[](0);

        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(5);
        RulesEngineMainFacet(address(red)).evaluateRulesAndExecuteEffects(0, applicableRules, arguments);
    }

    function testRulesEngine_Utils_evaluateExpression() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);
        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule =  _createGTRule(4);
        rule.posEffects[0] = effectId_event;

        rule.instructionSet = _createInstructionSet();
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0,rule);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(address(userContract), policyIds);

        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(5);

        RulesEngineMainFacet(address(red)).evaluateExpression(0, rule, arguments, rule.instructionSet);
    }

    function testRulesEngine_Utils_buildArguments() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"        
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1); 
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the mapping between calling function arguments and foreign call arguments
        rule.fcArgumentMappingsConditions = new ForeignCallArgumentMappings[](1);
        rule.fcArgumentMappingsConditions[0].mappings = new IndividualArgumentMapping[](1);
        rule.fcArgumentMappingsConditions[0].mappings[0].functionCallArgumentType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.foreignCall = false;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.pType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0,rule);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        RulesEngineDataFacet(address(red)).updateForeignCall(policyIds[0], address(testContract), "simpleCheck(uint256)", PT.UINT, fcArgs);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);       
        RulesEngineDataFacet(address(red)).applyPolicy(address(userContract), policyIds);
        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(5);

        RulesEngineMainFacet(address(red)).buildArguments(0, rule.placeHolders, rule.fcArgumentMappingsConditions, arguments);
    }

    function testRulesEngine_Utils_evaluateForeignCalls() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"        
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1); 
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the mapping between calling function arguments and foreign call arguments
        rule.fcArgumentMappingsConditions = new ForeignCallArgumentMappings[](1);
        rule.fcArgumentMappingsConditions[0].mappings = new IndividualArgumentMapping[](1);
        rule.fcArgumentMappingsConditions[0].mappings[0].functionCallArgumentType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.foreignCall = false;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.pType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0,rule);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        RulesEngineDataFacet(address(red)).updateForeignCall(policyIds[0], address(testContract), "simpleCheck(uint256)", PT.UINT, fcArgs);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);       
        RulesEngineDataFacet(address(red)).applyPolicy(address(userContract), policyIds);
        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(5);

        RulesEngineMainFacet(address(red)).evaluateForeignCalls(0, rule.placeHolders, rule.fcArgumentMappingsConditions, arguments, 0);
    }

    function testRulesEngine_Utils_doEffects() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);
        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule =  _createGTRule(4);
        rule.posEffects[0] = effectId_event;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.NUM);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LC.GT);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0,rule);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(address(userContract), policyIds);

        Effect[] memory effectIDs = new Effect[](2);
        effectIDs[0] = effectId_event;
        effectIDs[1] = effectId_event2;

        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(5);

        RulesEngineMainFacet(address(red)).doEffects(0, effectIDs, rule, arguments);
    }

    function testRulesEngine_Utils_run() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);
        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule =  _createGTRule(4);
        rule.posEffects[0] = effectId_event;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.NUM);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LC.GT);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0,rule);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(address(userContract), policyIds);

        uint256[] memory effectIDs = new uint256[](2);
        effectIDs[0] = 0;
        effectIDs[1] = 1;


        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(5);

        RulesEngineMainFacet(address(red)).run(0, rule.instructionSet, arguments);
    }



    /// Foreign call tests
    function testRulesEngine_ForeignCalls_getFCAddress() public ifDeploymentTestsEnabled endWithStopPrank {
        ForeignCallReturnValue memory retVal;
        retVal.pType = PT.ADDR;
        retVal.value = abi.encode(address(1));
        address addr = FCEncodingLib.getFCAddress(retVal);
        assertEq(addr, address(1));
    }

    function testRulesEngine_ForeignCalls_getFCAddress_wrongType() public ifDeploymentTestsEnabled endWithStopPrank {
        ForeignCallReturnValue memory retVal;
        retVal.pType = PT.UINT;
        retVal.value = abi.encode(uint256(1));
        vm.expectRevert();
        FCEncodingLib.getFCAddress(retVal);
    }

    function testRulesEngine_ForeignCalls_getFCString() public ifDeploymentTestsEnabled endWithStopPrank {
        ForeignCallReturnValue memory retVal;
        retVal.pType = PT.STR;
        retVal.value = abi.encode("hello");
        string memory str = FCEncodingLib.getFCString(retVal);
        assertEq(str, "hello");
    }

    function testRulesEngine_ForeignCalls_getFCString_negative() public ifDeploymentTestsEnabled endWithStopPrank {
        ForeignCallReturnValue memory retVal;
        retVal.pType = PT.UINT;
        retVal.value = abi.encode(uint256(1));
        vm.expectRevert();
        FCEncodingLib.getFCString(retVal);
    }

    function testRulesEngine_ForeignCalls_getFCUint() public ifDeploymentTestsEnabled endWithStopPrank {
        ForeignCallReturnValue memory retVal;
        retVal.pType = PT.UINT;
        retVal.value = abi.encode(uint256(1));
        uint256 uintVal = FCEncodingLib.getFCUint(retVal);
        assertEq(uintVal, 1);
    }

    function testRulesEngine_ForeignCalls_getFCUint_negative() public ifDeploymentTestsEnabled endWithStopPrank {
        ForeignCallReturnValue memory retVal;
        retVal.pType = PT.STR;
        retVal.value = abi.encode("hello");
        vm.expectRevert();
        FCEncodingLib.getFCUint(retVal);
    }

    function testRulesEngine_ForeignCalls_getFCBool() public ifDeploymentTestsEnabled endWithStopPrank {
        ForeignCallReturnValue memory retVal;
        retVal.pType = PT.BOOL;
        retVal.value = abi.encode(true);
        bool boolVal = FCEncodingLib.getFCBool(retVal);
        assertEq(boolVal, true);
    }

    function testRulesEngine_ForeignCalls_getFCBool_negative() public ifDeploymentTestsEnabled endWithStopPrank {
        ForeignCallReturnValue memory retVal;
        retVal.pType = PT.UINT;
        retVal.value = abi.encode(uint256(1));
        vm.expectRevert();
        FCEncodingLib.getFCBool(retVal);
    }


}
