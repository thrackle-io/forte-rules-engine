/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "src/example/ExampleUserContract.sol";

abstract contract RulesEngineUnitTestsCommon is RulesEngineCommon {

    ExampleUserContract userContract;
    ExampleUserContractExtraParams userContract2;
    
    /// TestRulesEngine: 
    // Test attempt to add a policy with no signatures saved.
    function testRulesEngine_Unit_UpdatePolicy_InvalidRule()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        // Save the function signature
        uint256 functionSignatureId = RulesEngineDataFacet(address(red))
            .createFunctionSignature(
                policyId,
                bytes4(keccak256(bytes(functionSignature))),
                pTypes
            );
        signatures.push(bytes4(keccak256(bytes(functionSignature))));
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = 1;
        vm.expectRevert("Invalid Rule");
        RulesEngineDataFacet(address(red)).updatePolicy(
            policyId,
            signatures,
            functionSignatureIds,
            ruleIds
        );
    }

    // Test attempt to add a policy with no signatures saved.
    function testRulesEngine_Unit_UpdatePolicy_InvalidSignature()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        signatures.push(bytes4(keccak256(bytes(functionSignature))));
        functionSignatureIds.push(1);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = 1;
        vm.expectRevert("Invalid Signature");
        RulesEngineDataFacet(address(red)).updatePolicy(
            policyId,
            signatures,
            functionSignatureIds,
            ruleIds
        );
    }

    // Test attempt to add a policy with valid parts.
    function testRulesEngine_Unit_UpdatePolicy_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Instruction set: LC.PLH, 0, LC.NUM, 4, LC.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);

        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.policyId = policyId;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).createRule(policyId, rule);
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        // Save the function signature
        uint256 functionSignatureId = RulesEngineDataFacet(address(red))
            .createFunctionSignature(
                policyId,
                bytes4(keccak256(bytes(functionSignature))),
                pTypes
            );
        // Save the Policy
        signatures.push(bytes4(keccak256(bytes(functionSignature))));
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        assertGt(
            RulesEngineDataFacet(address(red)).updatePolicy(
                policyId,
                signatures,
                functionSignatureIds,
                ruleIds
            ),
            0
        );
    }

    function testRulesEngine_Unit_CheckRules_Explicit()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithoutForeignCall();
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), 5);
        uint256 response = RulesEngineMainFacet(address(red)).checkPolicies(
            address(userContract),
            arguments
        );
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_checkRule_simple_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
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

    function testRulesEngine_Unit_createRule_ForeignCall_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 ruleValue = 10;
        uint256 transferValue = 15;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(ruleValue);
        // Build the mapping between calling function arguments and foreign call arguments
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.policyId = policyIds[0];
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).createRule(policyIds[0], rule);
        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 1;
        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineDataFacet(address(red)).createForeignCall(
            policyIds[0],
            fc
        );
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(
            address(userContract),
            policyIds
        );

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), transferValue);

        uint256 response = RulesEngineMainFacet(address(red)).checkPolicies(
            address(userContract),
            arguments
        );
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_createRule_ForeignCall_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 ruleValue = 15;
        uint256 transferValue = 10;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(ruleValue);
        // Build the mapping between calling function arguments and foreign call arguments
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.policyId = policyIds[0];
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).createRule(policyIds[0], rule);
        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 1;
        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineDataFacet(address(red)).createForeignCall(
            policyIds[0],
            fc
        );
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(
            address(userContract),
            policyIds
        );

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), transferValue);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineMainFacet(address(red)).checkPolicies(
            address(userContract),
            arguments
        );
    }

    function testRulesEngine_Unit_checkRule_ForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        uint256 ruleValue = 10; 
        uint256 transferValue = 15;
        _setup_checkRule_ForeignCall_Positive(ruleValue, functionSignature);
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly 
        bool response = userContract.transfer(address(0x7654321), transferValue);
        assertTrue(response);
    }

    function testRulesEngine_Unit_checkRule_ForeignCall_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 ruleValue = 15;
        uint256 transferValue = 10;
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _setup_checkRule_ForeignCall_Negative(ruleValue, functionSignature, pTypes);
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly 
        vm.expectRevert(abi.encodePacked(revert_text)); 
        userContract.transfer(address(0x7654321), transferValue);
    }

    function testRulesEngine_Unit_CheckPolicies_Explicit_StringComparison_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithStringComparison();
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature2))), address(0x7654321), "Bad Info");
        uint256 response = RulesEngineMainFacet(address(red)).checkPolicies(
            address(userContract),
            arguments
        );
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_CheckPolicies_Explicit_StringComparison_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithStringComparison();
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature2))), address(0x7654321), "test");
        uint256 response = RulesEngineMainFacet(address(red)).checkPolicies(
            address(userContract),
            arguments
        );
        assertEq(response, 0);
    }

    function testRulesEngine_Unit_RetrieveRawStringFromInstructionSet()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 ruleId = setupRuleWithStringComparison();
        StringVerificationStruct memory retVal = RulesEngineMainFacet(
            address(red)
        ).retrieveRawStringFromInstructionSet(ruleId, 3);
        console2.log(retVal.instructionSetValue);
        console2.log(retVal.rawData);
        assertEq(
            retVal.instructionSetValue,
            uint256(keccak256(abi.encode(retVal.rawData)))
        );
    }

    function testRulesEngine_Unit_CheckPolicies_Explicit_AddressComparison_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithAddressComparison();
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature2))), address(0x1234567), "test");
        uint256 response = RulesEngineMainFacet(address(red)).checkPolicies(
            address(userContract),
            arguments
        );
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_CheckPolicies_Explicit_AddressComparison_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithAddressComparison();
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature2))), address(0x7654321), "test");
        uint256 response = RulesEngineMainFacet(address(red)).checkPolicies(
            address(userContract),
            arguments
        );
        assertEq(response, 0);
    }

    function testRulesEngine_Unit_RetrieveRawAddressFromInstructionSet()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 ruleId = setupRuleWithAddressComparison();
        AddressVerificationStruct memory retVal = RulesEngineMainFacet(
            address(red)
        ).retrieveRawAddressFromInstructionSet(ruleId, 3);
        console2.log(retVal.instructionSetValue);
        console2.log(retVal.rawData);
        assertEq(
            retVal.instructionSetValue,
            uint256(uint160(address(retVal.rawData)))
        );
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithForeignCall_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithForeignCall(4, ET.REVERT, false);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), 5);

        uint256 response = RulesEngineMainFacet(address(red)).checkPolicies(
            address(userContract),
            arguments
        );
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithForeignCallEffect()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithForeignCall(4, ET.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), 5);
        // The Foreign call will be placed during the effect for the single rule in this policy.
        // The value being set in the foreign contract is then polled to verify that it has been udpated.
        RulesEngineMainFacet(address(red)).checkPolicies(
            address(userContract),
            arguments
        );
        assertEq(testContract.getInternalValue(), 5);
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithTrackerUpdateEffect()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        userContract = new ExampleUserContract();
        userContractAddress = address(userContract);
        testContract = new ForeignCallTestContract();
        uint256 policyId = setupEffectWithTrackerUpdate();

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), 5);
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the foreign call (simpleCheck) added to it.
        // original tracker value 2, added value 5, resulting updated tracker value should be 7
        RulesEngineMainFacet(address(red)).checkPolicies(
            userContractAddress,
            arguments
        );
        Trackers memory tracker = RulesEngineDataFacet(address(red)).getTracker(
            policyId,
            0
        );
        assertEq(tracker.trackerValue, abi.encode(7));
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithForeignCallNegative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithForeignCall(4, ET.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), 3);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineMainFacet(address(red)).checkPolicies(
            address(userContract),
            arguments
        );
    }

    /// Ensure that rule with a negative effect revert applied, that passes, will revert
    function testRulesEngine_Unit_CheckRules_WithExampleContract_Negative_Revert()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        _setupRuleWithRevert(address(userContract));
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.transfer(address(0x7654321), 5);
    }

    /// Ensure that rule with a positive effect event applied, that passes, will emit the event
    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        _setupRuleWithPosEvent();
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        userContract.transfer(address(0x7654321), 5);
    }

    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event_CustomParams_Uint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        bytes memory eventParam = abi.encode(uint256(100)); 
        _setupRuleWithPosEventParams(eventParam, PT.UINT);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, 100);
        userContract.transfer(address(0x7654321), 5);
    }

    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event_CustomParams_String()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        bytes memory eventParam = abi.encode(string("Test")); 
        _setupRuleWithPosEventParams(eventParam, PT.STR);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, string("test"));
        userContract.transfer(address(0x7654321), 5);
    }

    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event_CustomParams_Address()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        bytes memory eventParam = abi.encode(address(0x100)); 
        _setupRuleWithPosEventParams(eventParam, PT.ADDR);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, address(0x100));
        userContract.transfer(address(0x7654321), 5);
    }

    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event_CustomParams_Bool()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        bytes memory eventParam = abi.encode(bool(true)); 
        _setupRuleWithPosEventParams(eventParam, PT.BOOL);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, true);
        userContract.transfer(address(0x7654321), 5);
    }

    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event_CustomParams_Bytes32()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        bytes memory eventParam = abi.encode(bytes32("Bytes32 Test")); 
        _setupRuleWithPosEventParams(eventParam, PT.BYTES);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, bytes32("Bytes32 Test"));
        userContract.transfer(address(0x7654321), 5);
    }

    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event_DynamicParams_Uint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        _setupRuleWithPosEventDynamicParamsFromCallingFunctionParams(PT.UINT);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, 100);
        userContract.transfer(address(0x7654321), 100);
    }


    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event_DynamicParams_Address()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        _setupRuleWithPosEventDynamicParamsFromCallingFunctionParams(PT.ADDR);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, address(0x7654321));
        userContract.transfer(address(0x7654321), 100);
    }

    // Ensure that a policy with multiple rules with positive events fire in the correct order
    function testRulesEngine_Unit_CheckPolicy_ExecuteRuleOrder()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        _setupPolicyWithMultipleRulesWithPosEvents();
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT2, event_text2);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT2, event_text2);
        userContract.transfer(address(0x7654321), 11);
    }

    /// Ensure that rule with a positive effect event applied, that passes, will emit the event
    function testRulesEngine_Unit_CheckRules_WithExampleContract_Multiple_Positive_Event()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        _setupRuleWith2PosEvent();
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT2, event_text2);
        userContract.transfer(address(0x7654321), 11);
    }

    function testRulesEngine_Unit_EncodingForeignCallUint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSig(uint256)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.UINT;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 0;
        bytes memory vals = abi.encode(1);
        RulesEngineMainFacet(address(red))
            .evaluateForeignCallForRule(
                fc,
                vals
            );
        assertEq(foreignCall.getDecodedIntOne(), 1);
    }

    function testRulesEngine_Unit_EncodingForeignCallTwoUint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSig(uint256,uint256)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](2);
        fc.parameterTypes[0] = PT.UINT;
        fc.parameterTypes[1] = PT.UINT;
        fc.typeSpecificIndices = new uint8[](2);
        fc.typeSpecificIndices[0] = 0;
        fc.typeSpecificIndices[1] = 1;
        bytes memory vals = abi.encode(1, 2);
        RulesEngineMainFacet(address(red)).evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getDecodedIntOne(), 1);
        assertEq(foreignCall.getDecodedIntTwo(), 2);
    }

    function testRulesEngine_Unit_EncodingForeignCallAddress()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSig(address)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.ADDR;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 0;
        bytes memory vals = abi.encode(address(0x1234567));
        RulesEngineMainFacet(address(red))
            .evaluateForeignCallForRule(
                fc,
                vals
            );
        assertEq(foreignCall.getDecodedAddr(), address(0x1234567));
    }

    function testRulesEngine_Unit_EncodingForeignCallTwoAddress()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSig(address,address)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](2);
        fc.parameterTypes[0] = PT.ADDR;
        fc.parameterTypes[1] = PT.ADDR;
        fc.typeSpecificIndices = new uint8[](2);
        fc.typeSpecificIndices[0] = 0;
        fc.typeSpecificIndices[1] = 1;
        bytes memory vals = abi.encode(address(0x1234567), address(0x7654321));
        RulesEngineMainFacet(address(red)).evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getDecodedAddr(), address(0x1234567));
        assertEq(foreignCall.getDecodedAddrTwo(), address(0x7654321));
    }   

    function testRulesEngine_Unit_EncodingForeignCallString()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSig(string)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.STR;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 0;
        bytes memory vals = abi.encode("test");
        RulesEngineMainFacet(address(red))
            .evaluateForeignCallForRule(
                fc,
                vals
            );
        assertEq(foreignCall.getDecodedStrOne(), "test");
    }

    function testRulesEngine_Unit_EncodingForeignCallTwoString()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSig(string,string)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](2);
        fc.parameterTypes[0] = PT.STR;
        fc.parameterTypes[1] = PT.STR;
        fc.typeSpecificIndices = new uint8[](2);
        fc.typeSpecificIndices[0] = 0;
        fc.typeSpecificIndices[1] = 1;
        bytes memory vals = abi.encode("test", "superduper");
        RulesEngineMainFacet(address(red)).evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getDecodedStrOne(), "test");
        assertEq(foreignCall.getDecodedStrTwo(), "superduper");
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayUint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithArray(uint256[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.STATIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 0;
        uint256[] memory array = new uint256[](5);
        array[0] = 1;
        array[1] = 2;
        array[2] = 3;
        array[3] = 4;
        array[4] = 5;
        bytes memory vals = abi.encode(array);
        RulesEngineMainFacet(address(red))
            .evaluateForeignCallForRule(
                fc,
                vals
            );
        assertEq(foreignCall.getInternalArrayUint()[0], 1);
        assertEq(foreignCall.getInternalArrayUint()[1], 2);
        assertEq(foreignCall.getInternalArrayUint()[2], 3);
        assertEq(foreignCall.getInternalArrayUint()[3], 4);
        assertEq(foreignCall.getInternalArrayUint()[4], 5);
    }

    function testRulesEngine_Unit_EncodingForeignCallTwoArrayUint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithArray(uint256[],uint256[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](2);
        fc.parameterTypes[0] = PT.STATIC_TYPE_ARRAY;
        fc.parameterTypes[1] = PT.STATIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](2);
        fc.typeSpecificIndices[0] = 0;
        fc.typeSpecificIndices[1] = 1;
        uint256[] memory array = new uint256[](5);
        array[0] = 1;
        array[1] = 2;
        array[2] = 3;
        array[3] = 4;
        array[4] = 5;
        uint256[] memory arrayTwo = new uint256[](5);
        arrayTwo[0] = 6;
        arrayTwo[1] = 7;
        arrayTwo[2] = 8;
        arrayTwo[3] = 9;
        arrayTwo[4] = 10;
        bytes memory vals = abi.encode(array, arrayTwo);
        RulesEngineMainFacet(address(red)).evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getInternalArrayUint()[0], 1);
        assertEq(foreignCall.getInternalArrayUint()[1], 2);
        assertEq(foreignCall.getInternalArrayUint()[2], 3);
        assertEq(foreignCall.getInternalArrayUint()[3], 4);
        assertEq(foreignCall.getInternalArrayUint()[4], 5);
        assertEq(foreignCall.getInternalArrayUint()[5], 6);
        assertEq(foreignCall.getInternalArrayUint()[6], 7);
        assertEq(foreignCall.getInternalArrayUint()[7], 8);
        assertEq(foreignCall.getInternalArrayUint()[8], 9);
        assertEq(foreignCall.getInternalArrayUint()[9], 10);
    }

    function testRulesEngine_Unit_EncodingForeignCallTwoArrayString()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithArray(string[],string[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](2);
        fc.parameterTypes[0] = PT.DYNAMIC_TYPE_ARRAY;
        fc.parameterTypes[1] = PT.DYNAMIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](2);
        fc.typeSpecificIndices[0] = 0;
        fc.typeSpecificIndices[1] = 1;
        string[] memory array = new string[](5);
        array[0] = "test";
        array[1] = "superduper";
        array[2] = "superduperduper";
        array[3] = "superduperduperduper";
        array[4] = "superduperduperduperduperduperduperduperduperduperduperduperlongstring";
        string[] memory arrayTwo = new string[](5);
        arrayTwo[0] = "muper";
        arrayTwo[1] = "muperduper";
        arrayTwo[2] = "muperduperduper";
        arrayTwo[3] = "muperduperduperduper";
        arrayTwo[4] = "muperduperduperduperduperduperduperduperduperduperduperduperlongstring";
        bytes memory vals = abi.encode(array, arrayTwo);
        RulesEngineMainFacet(address(red)).evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getInternalArrayStr()[0], "test");
        assertEq(foreignCall.getInternalArrayStr()[1], "superduper");
        assertEq(foreignCall.getInternalArrayStr()[2], "superduperduper");
        assertEq(foreignCall.getInternalArrayStr()[3], "superduperduperduper");
        assertEq(foreignCall.getInternalArrayStr()[4], "superduperduperduperduperduperduperduperduperduperduperduperlongstring");
        assertEq(foreignCall.getInternalArrayStr()[5], "muper");
        assertEq(foreignCall.getInternalArrayStr()[6], "muperduper");
        assertEq(foreignCall.getInternalArrayStr()[7], "muperduperduper");
        assertEq(foreignCall.getInternalArrayStr()[8], "muperduperduperduper");
        assertEq(foreignCall.getInternalArrayStr()[9], "muperduperduperduperduperduperduperduperduperduperduperduperlongstring");
    }


    function testRulesEngine_Unit_EncodingForeignCallArrayAddr()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithArray(address[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.STATIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 0;
        address[] memory array = new address[](5);
        array[0] = address(0x1234567);
        array[1] = address(0x7654321);
        array[2] = address(0x1111111);
        array[3] = address(0x2222222);
        array[4] = address(0x3333333);
        bytes memory vals = abi.encode(array);
        RulesEngineMainFacet(address(red))
            .evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getInternalArrayAddr()[0], address(0x1234567));
        assertEq(foreignCall.getInternalArrayAddr()[1], address(0x7654321));
        assertEq(foreignCall.getInternalArrayAddr()[2], address(0x1111111));
        assertEq(foreignCall.getInternalArrayAddr()[3], address(0x2222222));
        assertEq(foreignCall.getInternalArrayAddr()[4], address(0x3333333));
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayStr()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithArray(string[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.DYNAMIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 0;
        string[] memory array = new string[](5);
        array[0] = "test";
        array[1] = "superduper";
        array[2] = "superduperduper";
        array[3] = "superduperduperduper";
        array[4] = "superduperduperduperduperduperduperduperduperlongstring";
        bytes memory vals = abi.encode(array);
        RulesEngineMainFacet(address(red))
            .evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getInternalArrayStr()[0], "test");
        assertEq(foreignCall.getInternalArrayStr()[1], "superduper");
        assertEq(foreignCall.getInternalArrayStr()[2], "superduperduper");
        assertEq(foreignCall.getInternalArrayStr()[3], "superduperduperduper");
        assertEq(foreignCall.getInternalArrayStr()[4], "superduperduperduperduperduperduperduperduperlongstring");
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayBytes()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithArray(bytes[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.DYNAMIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 0;
        bytes[] memory array = new bytes[](5);
        array[0] = abi.encodeWithSelector(bytes4(keccak256(bytes("test(uint256)"))), 1);
        array[1] = abi.encodeWithSelector(bytes4(keccak256(bytes("superduper(uint256)"))), 2);
        array[2] = abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduper(uint256)"))), 3);
        array[3] = abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduperduper(uint256)"))), 4);
        array[4] = abi.encodeWithSelector(bytes4(keccak256(bytes("test(uint256,string,address)"))), 5, "superduperduperduperduperduperduperduperduperduperduperduperlongstring", address(0x1234567));
        bytes memory vals = abi.encode(array);
        RulesEngineMainFacet(address(red))
            .evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getInternalArrayBytes()[0], abi.encodeWithSelector(bytes4(keccak256(bytes("test(uint256)"))), 1));
        assertEq(foreignCall.getInternalArrayBytes()[1], abi.encodeWithSelector(bytes4(keccak256(bytes("superduper(uint256)"))), 2));
        assertEq(foreignCall.getInternalArrayBytes()[2], abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduper(uint256)"))), 3));
        assertEq(foreignCall.getInternalArrayBytes()[3], abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduperduper(uint256)"))), 4));
        assertEq(foreignCall.getInternalArrayBytes()[4], abi.encodeWithSelector(bytes4(keccak256(bytes("test(uint256,string,address)"))), 5, "superduperduperduperduperduperduperduperduperduperduperduperlongstring", address(0x1234567)));
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayMixedTypes_Complex()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithMultiArrays(uint256[],address[],string[],bytes[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](4);
        fc.parameterTypes[0] = PT.STATIC_TYPE_ARRAY;
        fc.parameterTypes[1] = PT.STATIC_TYPE_ARRAY;
        fc.parameterTypes[2] = PT.DYNAMIC_TYPE_ARRAY;
        fc.parameterTypes[3] = PT.DYNAMIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](4);
        fc.typeSpecificIndices[0] = 0;
        fc.typeSpecificIndices[1] = 1;
        fc.typeSpecificIndices[2] = 2;
        fc.typeSpecificIndices[3] = 3;
        uint256[] memory array1 = new uint256[](5);
        array1[0] = 1;
        array1[1] = 2;
        array1[2] = 3;
        array1[3] = 4;
        array1[4] = 5;

        address[] memory array2 = new address[](5);
        array2[0] = address(0x1234567);
        array2[1] = address(0x7654321);
        array2[2] = address(0x1111111);
        array2[3] = address(0x2222222);
        array2[4] = address(0x3333333);

        string[] memory array3 = new string[](5);
        array3[0] = "test";
        array3[1] = "superduper";
        array3[2] = "superduperduper";
        array3[3] = "superduperduperduper";
        array3[4] = "superduperduperduperduperduperduperduperduperduperduperduperlongstring";
        bytes[] memory array4 = new bytes[](5); 
        array4[0] = abi.encodeWithSelector(bytes4(keccak256(bytes("test(uint256)"))), 1);
        array4[1] = abi.encodeWithSelector(bytes4(keccak256(bytes("superduper(uint256)"))), 2);
        array4[2] = abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduper(uint256)"))), 3);
        array4[3] = abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduperduper(uint256)"))), 4);
        array4[4] = abi.encodeWithSelector(bytes4(keccak256(bytes("test(uint256,string,address)"))), 5, "superduperduperduperduperduperduperduperduperduperduperduperduperlongstring", address(0x1234567));
        bytes memory vals = abi.encode(array1, array2, array3, array4);

        RulesEngineMainFacet(address(red))
            .evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getInternalArrayUint()[0], 1);
        assertEq(foreignCall.getInternalArrayUint()[1], 2);
        assertEq(foreignCall.getInternalArrayUint()[2], 3);
        assertEq(foreignCall.getInternalArrayUint()[3], 4);
        assertEq(foreignCall.getInternalArrayUint()[4], 5);
        assertEq(foreignCall.getInternalArrayAddr()[0], address(0x1234567));
        assertEq(foreignCall.getInternalArrayAddr()[1], address(0x7654321));
        assertEq(foreignCall.getInternalArrayAddr()[2], address(0x1111111));
        assertEq(foreignCall.getInternalArrayAddr()[3], address(0x2222222));
        assertEq(foreignCall.getInternalArrayAddr()[4], address(0x3333333));
        assertEq(foreignCall.getInternalArrayStr()[0], "test");
        assertEq(foreignCall.getInternalArrayStr()[1], "superduper");
        assertEq(foreignCall.getInternalArrayStr()[2], "superduperduper");
        assertEq(foreignCall.getInternalArrayStr()[3], "superduperduperduper");
        assertEq(foreignCall.getInternalArrayStr()[4], "superduperduperduperduperduperduperduperduperduperduperduperlongstring");
        assertEq(foreignCall.getInternalArrayBytes()[0], abi.encodeWithSelector(bytes4(keccak256(bytes("test(uint256)"))), 1));
        assertEq(foreignCall.getInternalArrayBytes()[1], abi.encodeWithSelector(bytes4(keccak256(bytes("superduper(uint256)"))), 2));
        assertEq(foreignCall.getInternalArrayBytes()[2], abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduper(uint256)"))), 3));
        assertEq(foreignCall.getInternalArrayBytes()[3], abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduperduper(uint256)"))), 4));
        assertEq(foreignCall.getInternalArrayBytes()[4], abi.encodeWithSelector(bytes4(keccak256(bytes("test(uint256,string,address)"))), 5, "superduperduperduperduperduperduperduperduperduperduperduperduperlongstring", address(0x1234567)));
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayMixedTypes_Simple()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithMultiArrays(string[],uint256[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](2);
        fc.parameterTypes[0] = PT.DYNAMIC_TYPE_ARRAY;
        fc.parameterTypes[1] = PT.STATIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](2);
        fc.typeSpecificIndices[0] = 0;
        fc.typeSpecificIndices[1] = 1;
        string[] memory array3 = new string[](5);
        array3[0] = "test";
        array3[1] = "superduper";
        array3[2] = "superduperduper";
        array3[3] = "superduperduperduper";
        array3[4] = "superduperduperduperduperduperduperduperduperduperduperduperlongstring";
        uint256[] memory array1 = new uint256[](5);
        array1[0] = 1;
        array1[1] = 2;
        array1[2] = 3;
        array1[3] = 4;
        array1[4] = 5;
        bytes memory vals = abi.encode(array3, array1);
        RulesEngineMainFacet(address(red))
            .evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getInternalArrayStr()[0], "test");
        assertEq(foreignCall.getInternalArrayStr()[1], "superduper");
        assertEq(foreignCall.getInternalArrayStr()[2], "superduperduper");
        assertEq(foreignCall.getInternalArrayStr()[3], "superduperduperduper");
        assertEq(foreignCall.getInternalArrayStr()[4], "superduperduperduperduperduperduperduperduperduperduperduperlongstring");
        assertEq(foreignCall.getInternalArrayUint()[0], 1);
        assertEq(foreignCall.getInternalArrayUint()[1], 2);
        assertEq(foreignCall.getInternalArrayUint()[2], 3);
        assertEq(foreignCall.getInternalArrayUint()[3], 4);
        assertEq(foreignCall.getInternalArrayUint()[4], 5);
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayMixedTypes_ReverseOrderSimple()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithMultiArrays(uint256[],string[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](2);
        fc.parameterTypes[0] = PT.STATIC_TYPE_ARRAY;
        fc.parameterTypes[1] = PT.DYNAMIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](2);
        fc.typeSpecificIndices[0] = 0;
        fc.typeSpecificIndices[1] = 1;
        uint256[] memory array1 = new uint256[](5);
        array1[0] = 1;
        array1[1] = 2;
        array1[2] = 3;
        array1[3] = 4;
        array1[4] = 5;
        string[] memory array3 = new string[](5);
        array3[0] = "test";
        array3[1] = "superduper";
        array3[2] = "superduperduper";
        array3[3] = "superduperduperduper";
        array3[4] = "superduperduperduperduperduperduperduperduperduperduperduperlongstring";

        bytes memory vals = abi.encode(array1, array3);

        RulesEngineMainFacet(address(red))
            .evaluateForeignCallForRule(fc, vals);
        
        assertEq(foreignCall.getInternalArrayUint()[0], 1);
        assertEq(foreignCall.getInternalArrayUint()[1], 2);
        assertEq(foreignCall.getInternalArrayUint()[2], 3);
        assertEq(foreignCall.getInternalArrayUint()[3], 4);
        assertEq(foreignCall.getInternalArrayUint()[4], 5);
        assertEq(foreignCall.getInternalArrayStr()[0], "test");
        assertEq(foreignCall.getInternalArrayStr()[1], "superduper");
        assertEq(foreignCall.getInternalArrayStr()[2], "superduperduper");
        assertEq(foreignCall.getInternalArrayStr()[3], "superduperduperduper");
        assertEq(foreignCall.getInternalArrayStr()[4], "superduperduperduperduperduperduperduperduperduperduperduperlongstring");
    }

    function testRulesEngine_Unit_EncodingForeignCallMixedTypes()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSig(uint256,string,uint256,string,address)";
        //string memory functionSig = "testSig(string)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](5);
        fc.parameterTypes[0] = PT.UINT;
        fc.parameterTypes[1] = PT.STR;
        fc.parameterTypes[2] = PT.UINT;
        fc.parameterTypes[3] = PT.STR;
        fc.parameterTypes[4] = PT.ADDR;

        fc.typeSpecificIndices = new uint8[](5);
        fc.typeSpecificIndices[0] = 0;
        fc.typeSpecificIndices[1] = 1;
        fc.typeSpecificIndices[2] = 2;
        fc.typeSpecificIndices[3] = 3;
        fc.typeSpecificIndices[4] = 4;

        bytes memory vals = abi.encode(
            1, 
            "test", 
            2, 
            "superduperduperduperduperduperduperduperduperduperduperduperlongstring", 
            address(0x1234567)
        );

        ForeignCallReturnValue memory retVal = RulesEngineMainFacet(address(red))
            .evaluateForeignCallForRule(
                fc,
                vals
            );

        assertEq(foreignCall.getDecodedIntOne(), 1);
        assertEq(foreignCall.getDecodedIntTwo(), 2);
        assertEq(foreignCall.getDecodedStrOne(), "test");
        assertEq(
            foreignCall.getDecodedStrTwo(),
            "superduperduperduperduperduperduperduperduperduperduperduperlongstring"
        );
        assertEq(foreignCall.getDecodedAddr(), address(0x1234567));
        retVal;
    }

    function testRulesEngine_Unit_EvaluateForeignCallForRule_WithStringAndDynamicAndStaticArray()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        ForeignCall memory fc;
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        string memory functionSig = "testSigWithMultiArrays(string,uint256[],string[])";
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](3);
        fc.parameterTypes[0] = PT.STR;
        fc.parameterTypes[1] = PT.STATIC_TYPE_ARRAY;
        fc.parameterTypes[2] = PT.DYNAMIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](3);
        fc.typeSpecificIndices[0] = 2;
        fc.typeSpecificIndices[1] = 1;
        fc.typeSpecificIndices[2] = 0;

        string memory str = "superduperduperduperduperduperduperduperduperduperduperduperlongstring";
        uint256[] memory uintArray = new uint256[](5);
        uintArray[0] = 1;
        uintArray[1] = 2;
        uintArray[2] = 3;
        uintArray[3] = 4;
        uintArray[4] = 5;
        string[] memory strArray = new string[](5);
        strArray[0] = "test";
        strArray[1] = "superduper";
        strArray[2] = "superduperduper";
        strArray[3] = "superduperduperduper";
        strArray[4] = "superduperduperduperduperduperduperduperduperduperduperduperlongstring";
        bytes memory vals = abi.encode(strArray, uintArray, str);
        ForeignCallReturnValue memory retVal = RulesEngineMainFacet(address(red)).evaluateForeignCallForRule(fc, vals);
        retVal;
    }

    function testRulesEngine_Unit_EvaluateForeignCallForRule()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        ForeignCall memory fc;
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        string
            memory functionSig = "testSig(uint256,string,uint256,string,address)";

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

        fc.typeSpecificIndices = new uint8[](5);
        fc.typeSpecificIndices[0] = 1;
        fc.typeSpecificIndices[1] = 0;
        fc.typeSpecificIndices[2] = 2;
        fc.typeSpecificIndices[3] = 3;
        fc.typeSpecificIndices[4] = 5;

        // rule signature function arguments (RS): string, uint256, uint256, string, uint256, string, address
        // foreign call function arguments (FC): uint256, string, uint256, string, address
        //
        // Mapping:
        // FC index: 0 1 2 3 4
        // RS index: 1 0 2 3 5

        // Build the rule signature function arguments structure

        bytes memory arguments = abi.encode("one", 2, 3, "four", 5, address(0x12345678));

        // Build the mapping between calling function arguments and foreign call arguments

        ForeignCallReturnValue memory retVal = RulesEngineMainFacet(
            address(red)
        ).evaluateForeignCallForRule(
                fc,
                arguments
            );
        console2.logBytes(retVal.value);
    }

    function testRulesEngine_Unit_CheckRules_WithTrackerValue()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithTracker(2);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        bool retVal = userContract.transfer(address(0x7654321), 3);
        assertTrue(retVal);
    }

    function testRulesEngine_Unit_CheckRules_WithTrackerValue_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithTracker(7);
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.transfer(address(0x7654321), 6);
    }

    function testRulesEngine_Unit_CheckRules_ManualUpdateToTracker()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = setupRuleWithTracker(4);
        bool retVal = userContract.transfer(address(0x7654321), 5);
        assertTrue(retVal);
        // expect failure here
        vm.expectRevert(abi.encodePacked(revert_text));
        retVal = userContract.transfer(address(0x7654321), 3);
        /// manually update the tracker here to higher value so that rule fails
        //                  calling contract,  updated uint, empty address, empty string, bool, empty bytes
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(7);
        RulesEngineDataFacet(address(red)).updateTracker(
            policyId,
            1,
            tracker
        );

        vm.expectRevert(abi.encodePacked(revert_text));
        retVal = userContract.transfer(address(0x7654321), 4);

        retVal = userContract.transfer(address(0x7654321), 9);
        assertTrue(retVal);
    }

    // Tracker creation
    function testRulesEngine_Unit_createRule_Tracker_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithTracker(10);
        uint256 transferValue = 15;

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), transferValue);

        uint256 response = RulesEngineMainFacet(address(red)).checkPolicies(
            address(userContract),
            arguments
        );
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_createRule_Tracker_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithTracker(15);
        uint256 transferValue = 10;

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), transferValue);

        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineMainFacet(address(red)).checkPolicies(
            address(userContract),
            arguments
        );
    }

    function testRulesEngine_Unit_GetTrackerValue()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = setupRuleWithTracker(2);
        bool retVal = userContract.transfer(address(0x7654321), 3);
        assertTrue(retVal);

        Trackers memory testTracker = RulesEngineDataFacet(address(red))
            .getTracker(policyId, 0);

        assertTrue(abi.decode(testTracker.trackerValue, (uint256)) == 2);
        assertFalse(abi.decode(testTracker.trackerValue, (uint256)) == 3);
    }

    function testRulesEngine_Unit_UpdatePolicy_ValidatesForeignCalls()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].foreignCall = true;
        rule.placeHolders[1].typeSpecificIndex = 0;
        rule.policyId = policyIds[0];

        uint256 ruleId = RulesEngineDataFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        vm.expectRevert("Foreign Call referenced in rule not set");
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
    }

    function testRulesEngine_Unit_UpdatePolicy_ValidatesTrackers()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Instruction set: LC.PLH, 0, LC.PLH, 1, LC.GT, 0, 1
        rule.instructionSet = _createInstructionSet(0, 1);

        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].trackerValue = true;
        rule.placeHolders[1].typeSpecificIndex = 0;
        rule.policyId = policyIds[0];

        uint256 ruleId = RulesEngineDataFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        vm.expectRevert("Tracker referenced in rule not set");
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
    }

    /// Test utility functions within ExampleUserContract.sol and RulesEngineRunRulesEngineMainFacet(address(red)).sol
    function testRulesEngine_Utils_UserContract_setRulesEngineAddress()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        userContract.setRulesEngineAddress(address(red));
        assertTrue(userContract.rulesEngineAddress() == address(red));
    }

    function testRulesEngine_Utils_uintToBool()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        bool success = RulesEngineMainFacet(address(red)).ui2bool(1);
        assertTrue(success);
    }

    function testRulesEngine_Utils_BoolToUint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 success = RulesEngineMainFacet(address(red)).bool2ui(false);
        assertTrue(success == 0);
    }

    function testRulesEngine_Utils_evaluateForeignCalls()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the mapping between calling function arguments and foreign call arguments
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.policyId = policyIds[0];
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).createRule(policyIds[0], rule);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 1;
        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineDataFacet(address(red)).createForeignCall(
            policyIds[0],
            fc
        );
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(
            address(userContract),
            policyIds
        );

        bytes memory arguments = abi.encode(address(0x7654321), 5);
        RulesEngineMainFacet(address(red)).evaluateForeignCalls(
            0,
            rule.placeHolders,
            arguments,
            0
        );
    }

    /// Foreign call tests
    function testRulesEngine_ForeignCalls_getFCAddress()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        ForeignCallReturnValue memory retVal;
        retVal.pType = PT.ADDR;
        retVal.value = abi.encode(address(1));
        address addr = FCEncodingLib.getFCAddress(retVal);
        assertEq(addr, address(1));
    }

    function testRulesEngine_ForeignCalls_getFCAddress_wrongType()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        ForeignCallReturnValue memory retVal;
        retVal.pType = PT.UINT;
        retVal.value = abi.encode(uint256(1));
        vm.expectRevert();
        FCEncodingLib.getFCAddress(retVal);
    }

    function testRulesEngine_ForeignCalls_getFCString()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        ForeignCallReturnValue memory retVal;
        retVal.pType = PT.STR;
        retVal.value = abi.encode("hello");
        string memory str = FCEncodingLib.getFCString(retVal);
        assertEq(str, "hello");
    }

    function testRulesEngine_ForeignCalls_getFCString_negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        ForeignCallReturnValue memory retVal;
        retVal.pType = PT.UINT;
        retVal.value = abi.encode(uint256(1));
        vm.expectRevert();
        FCEncodingLib.getFCString(retVal);
    }

    function testRulesEngine_ForeignCalls_getFCUint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        ForeignCallReturnValue memory retVal;
        retVal.pType = PT.UINT;
        retVal.value = abi.encode(uint256(1));
        uint256 uintVal = FCEncodingLib.getFCUint(retVal);
        assertEq(uintVal, 1);
    }

    function testRulesEngine_ForeignCalls_getFCUint_negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        ForeignCallReturnValue memory retVal;
        retVal.pType = PT.STR;
        retVal.value = abi.encode("hello");
        vm.expectRevert();
        FCEncodingLib.getFCUint(retVal);
    }

    function testRulesEngine_ForeignCalls_getFCBool()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        ForeignCallReturnValue memory retVal;
        retVal.pType = PT.BOOL;
        retVal.value = abi.encode(true);
        bool boolVal = FCEncodingLib.getFCBool(retVal);
        assertEq(boolVal, true);
    }

    function testRulesEngine_ForeignCalls_getFCBool_negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        ForeignCallReturnValue memory retVal;
        retVal.pType = PT.UINT;
        retVal.value = abi.encode(uint256(1));
        vm.expectRevert();
        FCEncodingLib.getFCBool(retVal);
    }

    function testRulesEngine_unit_adminRoles_GeneratePolicyAdminRole_ThroughRulesEngine()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // policy admin role bytes string for policy 0: 0x35f49fd04fdc3104e07cf8040d0ede098e2a5ac11af26093ebea3a88e5ef9e2c
        vm.startPrank(policyAdmin);
        _createBlankPolicyWithAdminRoleString();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red))
            .isPolicyAdmin(1, policyAdmin);
        assertTrue(hasAdminRole);
    }

    function testRulesEngine_unit_adminRoles_GeneratePolicyAdminRole_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red))
            .isPolicyAdmin(policyID, newPolicyAdmin);
        assertFalse(hasAdminRole);
        vm.expectRevert(abi.encodeWithSignature("NotPolicyAdmin()"));
        RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(
            newPolicyAdmin,
            policyID
        );
    }

    function testRulesEngine_unit_adminRoles_ProposedPolicyAdminRole_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicyWithAdminRoleString();
        RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(
            newPolicyAdmin,
            policyID
        );
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        RulesEngineAdminRolesFacet(address(red)).confirmNewPolicyAdmin(
            policyID
        );

        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red))
            .isPolicyAdmin(1, newPolicyAdmin);

        assertTrue(hasAdminRole);
    }

    function testRulesEngine_unit_adminRoles_ProposedPolicyAdminRole_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicyWithAdminRoleString();
        RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(
            newPolicyAdmin,
            policyID
        );
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        vm.expectRevert(abi.encodeWithSignature("NotPolicyAdmin()"));
        RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(
            newPolicyAdmin,
            policyID
        );
    }

    function testRulesEngine_unit_adminRoles_RevokePolicyAdminRole_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        _createBlankPolicyWithAdminRoleString();
        bytes32 adminRole = bytes32(
            abi.encodePacked(
                keccak256(
                    bytes(string.concat(string(abi.encode(1)), "TestString"))
                )
            )
        );
        vm.expectRevert();
        RulesEngineAdminRolesFacet(address(red)).revokeRole(
            adminRole,
            policyAdmin
        );
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red))
            .isPolicyAdmin(1, policyAdmin);
        assertTrue(hasAdminRole);
    }

    function testRulesEngine_unit_adminRoles_RenouncePolicyAdminRole_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        _createBlankPolicyWithAdminRoleString();
        bytes32 adminRole = bytes32(
            abi.encodePacked(
                keccak256(
                    bytes(string.concat(string(abi.encode(1)), "TestString"))
                )
            )
        );
        vm.expectRevert();
        RulesEngineAdminRolesFacet(address(red)).renounceRole(
            adminRole,
            policyAdmin
        );
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red))
            .isPolicyAdmin(1, policyAdmin);
        assertTrue(hasAdminRole);
    }

    function testRulesEngine_unit_adminRoles_CreateTracker_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red))
            .isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = PT.ADDR;

        RulesEngineDataFacet(address(red)).createTracker(
            policyID,
            tracker
        );
    }

    function testRulesEngine_unit_adminRoles_CreateTracker_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red))
            .isPolicyAdmin(policyID, newPolicyAdmin);
        assertFalse(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = PT.ADDR;

        vm.expectRevert("Not Authorized To Policy");
        RulesEngineDataFacet(address(red)).createTracker(
            policyID,
            tracker
        );
    }

    function testRulesEngine_unit_adminRoles_UpdateTracker_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red))
            .isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = PT.ADDR;

        uint256 trackerId = RulesEngineDataFacet(address(red)).createTracker(
            policyID,
            tracker
        );

        tracker.trackerValue = abi.encode(address(userContractAddress));
        RulesEngineDataFacet(address(red)).updateTracker(
            policyID,
            trackerId,
            tracker
        );
    }

    function testRulesEngine_unit_adminRoles_UpdateTracker_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = PT.ADDR;
        uint256 trackerId = RulesEngineDataFacet(address(red)).createTracker(
            policyID,
            tracker
        );
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red))
            .isPolicyAdmin(policyID, newPolicyAdmin);
        assertFalse(hasAdminRole);
        tracker.trackerValue = abi.encode(address(userContractAddress));
        tracker.pType = PT.ADDR;

        vm.expectRevert("Not Authorized To Policy");
        RulesEngineDataFacet(address(red)).updateTracker(
            policyID,
            trackerId,
            tracker
        );
    }

    function testRulesEngine_Unit_createFunctionSignature_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        uint256 functionSignatureId = RulesEngineDataFacet(address(red)).createFunctionSignature(policyId, bytes4(keccak256(bytes(functionSignature))), pTypes);
        assertEq(functionSignatureId, 0);
        FunctionSignatureStorageSet memory sig = RulesEngineDataFacet(address(red)).getFunctionSignature(policyId, functionSignatureId);
        assertEq(sig.set, true);
        assertEq(sig.signature, bytes4(keccak256(bytes(functionSignature))));
        for (uint256 i = 0; i < pTypes.length; i++) {
            assertEq(uint8(sig.parameterTypes[i]), uint8(pTypes[i]));
        }
    }

    function testRulesEngine_Unit_createFunctionSignature_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        vm.startPrank(newPolicyAdmin);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineDataFacet(address(red)).createFunctionSignature(policyId, bytes4(keccak256(bytes(functionSignature))), pTypes);
    }

    function testRulesEngine_Unit_updateFunctionSignature_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        uint256 functionSignatureId = RulesEngineDataFacet(address(red)).createFunctionSignature(policyId, bytes4(keccak256(bytes(functionSignature))), pTypes);
        PT[] memory pTypes2 = new PT[](4);
        pTypes2[0] = PT.ADDR;
        pTypes2[1] = PT.UINT;
        pTypes2[2] = PT.ADDR;
        pTypes2[3] = PT.UINT;
        RulesEngineDataFacet(address(red)).updateFunctionSignature(policyId, functionSignatureId, bytes4(keccak256(bytes(functionSignature))), pTypes2);
        FunctionSignatureStorageSet memory sig = RulesEngineDataFacet(address(red)).getFunctionSignature(policyId, functionSignatureId);
        assertEq(sig.set, true);
        assertEq(sig.signature, bytes4(keccak256(bytes(functionSignature))));
        for (uint256 i = 0; i < pTypes2.length; i++) {
            assertEq(uint8(sig.parameterTypes[i]), uint8(pTypes2[i]));
        }
    }

    function testRulesEngine_Unit_deleteFunctionSignature_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        bytes4 deletedSignature;
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory _functionSigs;
        uint256[] memory _functionSigIds;
        uint256[][] memory _ruleIds;
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        uint256 functionSignatureId = RulesEngineDataFacet(address(red)).createFunctionSignature(policyId, bytes4(keccak256(bytes(functionSignature))), pTypes);
        assertEq(functionSignatureId, 0);
        FunctionSignatureStorageSet memory matchingSignature = RulesEngineDataFacet(address(red)).getFunctionSignature(policyId, functionSignatureId);
        assertEq(matchingSignature.signature, bytes4(keccak256(bytes(functionSignature))));

        RulesEngineDataFacet(address(red)).deleteFunctionSignature(policyId, functionSignatureId); 
        FunctionSignatureStorageSet memory sig = RulesEngineDataFacet(address(red)).getFunctionSignature(policyId, functionSignatureId);
        assertEq(sig.set, false);
        assertEq(sig.signature, bytes4(""));
    }

    function testRulesEngine_Unit_deleteFunctionSignatureMultiple_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        bytes4 deletedSignature;
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory _functionSigs;
        uint256[] memory _functionSigIds;
        uint256[][] memory _ruleIds;
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        uint256 functionSignatureId = RulesEngineDataFacet(address(red)).createFunctionSignature(policyId, bytes4(keccak256(bytes(functionSignature))), pTypes);
        assertEq(functionSignatureId, 0);
        uint256 functionSignatureId2 = RulesEngineDataFacet(address(red)).createFunctionSignature(policyId, bytes4(keccak256(bytes(functionSignature2))), pTypes);
        assertEq(functionSignatureId2, 1);
        FunctionSignatureStorageSet memory matchingSignature = RulesEngineDataFacet(address(red)).getFunctionSignature(policyId, functionSignatureId);
        assertEq(matchingSignature.signature, bytes4(keccak256(bytes(functionSignature))));

        FunctionSignatureStorageSet memory matchingSignature2 = RulesEngineDataFacet(address(red)).getFunctionSignature(policyId, functionSignatureId2);
        assertEq(matchingSignature2.signature, bytes4(keccak256(bytes(functionSignature2))));

        RulesEngineDataFacet(address(red)).deleteFunctionSignature(policyId, functionSignatureId); 
        FunctionSignatureStorageSet memory sig = RulesEngineDataFacet(address(red)).getFunctionSignature(policyId, functionSignatureId);
        assertEq(sig.set, false);
        assertEq(sig.signature, bytes4(""));

        FunctionSignatureStorageSet memory matchingSignature3 = RulesEngineDataFacet(address(red)).getFunctionSignature(policyId, functionSignatureId2);
        assertEq(matchingSignature3.signature, bytes4(keccak256(bytes(functionSignature2))));

        //check that policy signatures array is resized to 1 
        (_functionSigs, _functionSigIds, _ruleIds) = RulesEngineDataFacet(address(red)).getPolicy(policyId);
        assertEq(_functionSigs.length, 1);

    }

    function testRulesEngine_Unit_deleteFunctionSignature_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        uint256 functionSignatureId = RulesEngineDataFacet(address(red)).createFunctionSignature(policyId, bytes4(keccak256(bytes(functionSignature))), pTypes);
        assertEq(functionSignatureId, 0);

        vm.startPrank(newPolicyAdmin);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineDataFacet(address(red)).deleteFunctionSignature(policyId, functionSignatureId); 
    }

    function testRulesEngine_Unit_deleteFunctionSignatureWithRuleCheck_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create rule and set rule to user contract 
        setupRuleWithoutForeignCall();
        // test rule works for user contract 
        bool response = userContract.transfer(address(0x7654321), 3);
        assertFalse(response);
        // create pTypes array for new contract + new transfer function 
        PT[] memory pTypes = new PT[](3);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.ADDR;
        FunctionSignatureStorageSet memory sig = RulesEngineDataFacet(address(red)).getFunctionSignature(1, 0);
        RulesEngineDataFacet(address(red)).deleteFunctionSignature(1, 0); 
        // test that rule no longer checks 
        bool ruleCheck = userContract.transfer(address(0x7654321), 3);
        assertTrue(ruleCheck);

    }

    function testRulesEngine_Unit_updateFunctionSignature_Negative_NewParameterTypesNotSameLength()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        uint256 functionSignatureId = RulesEngineDataFacet(address(red)).createFunctionSignature(policyId, bytes4(keccak256(bytes(functionSignature))), pTypes);
        PT[] memory pTypes2 = new PT[](1);
        pTypes2[0] = PT.ADDR;
        vm.expectRevert("New parameter types must be of greater or equal length to the original");
        RulesEngineDataFacet(address(red)).updateFunctionSignature(policyId, functionSignatureId, bytes4(keccak256(bytes(functionSignature))), pTypes2);
    }

    function testRulesEngine_Unit_updateFunctionSignature_Negative_NewParameterTypesNotSameType()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        uint256 functionSignatureId = RulesEngineDataFacet(address(red)).createFunctionSignature(policyId, bytes4(keccak256(bytes(functionSignature))), pTypes);
        PT[] memory pTypes2 = new PT[](2);
        pTypes2[0] = PT.UINT;
        pTypes2[1] = PT.UINT;
        vm.expectRevert("New parameter types must be of the same type as the original");
        RulesEngineDataFacet(address(red)).updateFunctionSignature(policyId, functionSignatureId, bytes4(keccak256(bytes(functionSignature))), pTypes2);
    }

    function testRulesEngine_Unit_updateFunctionSignature_Negative_NewSignatureNotSame()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        uint256 functionSignatureId = RulesEngineDataFacet(address(red)).createFunctionSignature(policyId, bytes4(keccak256(bytes(functionSignature))), pTypes);
        vm.expectRevert("Delete function signature before updating to a new one");
        RulesEngineDataFacet(address(red)).updateFunctionSignature(policyId, functionSignatureId, bytes4(keccak256(bytes(functionSignature2))), pTypes);
    }

    function testRulesEngine_Unit_updateFunctionSignature_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        uint256 functionSignatureId = RulesEngineDataFacet(address(red)).createFunctionSignature(policyId, bytes4(keccak256(bytes(functionSignature))), pTypes);
        vm.startPrank(newPolicyAdmin);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineDataFacet(address(red)).updateFunctionSignature(policyId, functionSignatureId, bytes4(keccak256(bytes(functionSignature2))), pTypes);
    }

    function testRulesEngine_Unit_updateFunctionSignatureWithRuleCheck_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create rule and set rule to user contract 
        setupRuleWithoutForeignCall();
        // test rule works for user contract 
        bool response = userContract.transfer(address(0x7654321), 47);
        assertTrue(response);
        // create pTypes array for new contract + new transfer function 
        PT[] memory pTypes = new PT[](3);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.ADDR;
        FunctionSignatureStorageSet memory sig = RulesEngineDataFacet(address(red)).getFunctionSignature(1, 0);
        RulesEngineDataFacet(address(red)).updateFunctionSignature(1, 0, bytes4(keccak256(bytes(functionSignature))), pTypes);
        assertEq(sig.set, true);
        // ensure orignal contract rule check works 
        bool ruleCheck = userContract.transfer(address(0x7654321), 47);
        assertTrue(ruleCheck);
        // test new contract rule check works 
        bool secondRuleCheck = userContract.transfer(address(0x7654321), 47);
        assertTrue(secondRuleCheck);
    }

    function testRulesEngine_Unit_updateFunctionSignatureWithRuleCheck_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create rule and set rule to user contract 
        setupRuleWithoutForeignCall();
        // test rule works for user contract 
        bool response = userContract.transfer(address(0x7654321), 3);
        assertFalse(response);
        // create pTypes array for new contract + new transfer function 
        PT[] memory pTypes = new PT[](3);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.ADDR;
        FunctionSignatureStorageSet memory sig = RulesEngineDataFacet(address(red)).getFunctionSignature(1, 0);
        RulesEngineDataFacet(address(red)).updateFunctionSignature(1, 0, bytes4(keccak256(bytes(functionSignature))), pTypes);
        assertEq(sig.set, true);
        // ensure orignal contract rule check works 
        bool ruleCheck = userContract.transfer(address(0x7654321), 3);
        assertFalse(ruleCheck);
        // test new contract rule check works 
        bool secondRuleCheck = userContract.transfer(address(0x7654321), 3);
        assertFalse(secondRuleCheck);
    }

    function testRulesEngine_unit_adminRoles_DeleteTracker_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = PT.ADDR;
        uint256 trackerId = RulesEngineDataFacet(address(red)).createTracker(
            policyID,
            tracker
        );
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red))
            .isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        RulesEngineDataFacet(address(red)).deleteTracker(
            policyID,
            trackerId
        );

        tracker = RulesEngineDataFacet(address(red)).getTracker(
            policyID,
            trackerId
        );
        assertEq(tracker.set, false);
        assertEq(uint8(tracker.pType), uint8(PT.ADDR));
        assertEq(tracker.trackerValue, bytes(""));
    }

    function testRulesEngine_unit_adminRoles_DeleteTracker_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = PT.ADDR;
        uint256 trackerId = RulesEngineDataFacet(address(red)).createTracker(
            policyID,
            tracker
        );
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red))
            .isPolicyAdmin(policyID, newPolicyAdmin);
        assertFalse(hasAdminRole);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineDataFacet(address(red)).deleteTracker(
            policyID,
            trackerId
        );
    }

    function testRulesEngine_unit_adminRoles_CreateForeignCall_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red))
            .isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        ForeignCall memory fc;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.UINT;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 1;
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;

        RulesEngineDataFacet(address(red)).createForeignCall(
            policyID,
            fc
        );
    }

    function testRulesEngine_unit_adminRoles_CreateForeignCall_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red))
            .isPolicyAdmin(policyID, newPolicyAdmin);
        assertFalse(hasAdminRole);
        ForeignCall memory fc;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.UINT;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 1;
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;

        vm.expectRevert("Not Authorized To Policy");
        RulesEngineDataFacet(address(red)).createForeignCall(
            policyID,
            fc
        );
    }

    function testRulesEngine_unit_adminRoles_UpdateForeignCall_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red))
            .isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        ForeignCall memory fc;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.UINT;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 1;
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;

        uint256 foreignCallId = RulesEngineDataFacet(address(red)).createForeignCall(
            policyID,
            fc
        );
        fc.foreignCallAddress = address(userContractAddress);
        RulesEngineDataFacet(address(red)).updateForeignCall(
            policyID,
            foreignCallId,
            fc
        );
    }

    function testRulesEngine_unit_adminRoles_UpdateForeignCall_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.UINT;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 1;
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;

        uint256 foreignCallId = RulesEngineDataFacet(address(red)).createForeignCall(
            policyID,
            fc
        );
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red))
            .isPolicyAdmin(policyID, newPolicyAdmin);
        assertFalse(hasAdminRole);
        fc.foreignCallAddress = address(userContractAddress);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineDataFacet(address(red)).updateForeignCall(
            policyID,
            foreignCallId,
            fc
        );
    }
    
    function testRulesEngine_unit_adminRoles_DeleteForeignCall_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();

        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red))
            .isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);

        ForeignCall memory fc;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.UINT;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 1;
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;

        uint256 foreignCallId = RulesEngineDataFacet(address(red)).createForeignCall(
            policyID,
            fc
        );

        RulesEngineDataFacet(address(red)).deleteForeignCall(
            policyID,
            foreignCallId
        );

        ForeignCall memory fc2 = RulesEngineDataFacet(address(red)).getForeignCall(
            policyID,
            foreignCallId
        );
        assertEq(fc2.set, false);
        assertEq(fc2.foreignCallAddress, address(0));
        assertEq(fc2.signature, bytes4(0));
        assertEq(fc2.parameterTypes.length, 0);
        assertEq(fc2.typeSpecificIndices.length, 0);
        assertEq(uint8(fc2.returnType), uint8(PT.ADDR));
        assertEq(fc2.foreignCallIndex, 0);
    }

    function testRulesEngine_unit_adminRoles_DeleteForeignCall_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        ForeignCall memory fc;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.UINT;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 1;
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;
        uint256 foreignCallId = RulesEngineDataFacet(address(red)).createForeignCall(
            policyID,
            fc
        );
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red))
            .isPolicyAdmin(policyID, newPolicyAdmin);
        assertFalse(hasAdminRole);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineDataFacet(address(red)).deleteForeignCall(
            policyID,
            foreignCallId
        );
    }

    function testRulesEngine_Unit_GetAllForeignCallsTest()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.UINT;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 1;
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;
        for (uint256 i = 0; i < 10; i++) {
            RulesEngineDataFacet(address(red)).createForeignCall(
                policyId,
                fc
            );
        }
        
        ForeignCall[] memory foreignCalls = RulesEngineDataFacet(address(red)).getAllForeignCalls(policyId);
        assertEq(foreignCalls.length, 10);
        RulesEngineDataFacet(address(red)).deleteForeignCall(policyId, 2);

        foreignCalls = RulesEngineDataFacet(address(red)).getAllForeignCalls(policyId);
        assertEq(foreignCalls.length, 10);

        for (uint256 i = 0; i < 9; i++) {
            if (i >= 2) {
                assertEq(foreignCalls[i].foreignCallIndex, i + 1);
            } else {
                assertEq(foreignCalls[i].foreignCallIndex, i);
            }
        }
    }

    function testRulesEngine_Unit_GetAllTrackersTest()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();


        for (uint256 i = 0; i < 10; i++) {
            Trackers memory tracker;
            tracker.trackerValue = abi.encode(uint256(i));
            tracker.pType = PT.UINT;
            RulesEngineDataFacet(address(red)).createTracker(policyId, tracker);
        }

        Trackers[] memory trackers = RulesEngineDataFacet(address(red)).getAllTrackers(policyId);
        assertEq(trackers.length, 10);
        RulesEngineDataFacet(address(red)).deleteTracker(policyId, 2);

        trackers = RulesEngineDataFacet(address(red)).getAllTrackers(policyId);
        assertEq(trackers.length, 10);
        for (uint256 i = 0; i < 9; i++) {
            if (i >= 2) {
                assertEq(trackers[i].trackerValue, abi.encode(uint256(i + 1)));
            } else {
                assertEq(trackers[i].trackerValue, abi.encode(uint256(i)));
            }
        }
    }

    /// Test the getter functions for Policy. These are specifically tested(rather than the other view functions that are used within the update tests) because they digest the policy into individual arrays.
    function testRulesEngine_Unit_GetPolicy_Blank()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256[] memory policyIds = new uint256[](1);
        bytes4[] memory _functionSigs;
        uint256[] memory _functionSigIds;
        uint256[][] memory _ruleIds;

        policyIds[0] = _createBlankPolicy();
        assertEq(_functionSigs.length, 0);
        assertEq(_functionSigIds.length, 0);
        assertEq(_ruleIds.length, 0);
    }

    function testRulesEngine_Unit_GetPolicy_FunctionSig()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256[] memory policyIds = new uint256[](1);
        bytes4[] memory _functionSigs;
        uint256[] memory _functionSigIds;
        uint256[][] memory _ruleIds;

        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );
        (_functionSigs, _functionSigIds, _ruleIds) = RulesEngineDataFacet(
            address(red)
        ).getPolicy(policyIds[0]);
        assertEq(_functionSigs.length, 1);
        assertEq(_functionSigIds.length, 1);
    }

    function testRulesEngine_Unit_GetPolicy_Rules()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256[] memory policyIds = new uint256[](1);
        bytes4[] memory _functionSigs;
        uint256[] memory _functionSigIds;
        uint256[][] memory _ruleIds;

        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Instruction set: LC.PLH, 0, LC.PLH, 1, LC.GT, 0, 1
        rule.instructionSet = _createInstructionSet(0, 1);

        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = PT.UINT;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;
        rule.policyId = policyIds[0];        

        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        (_functionSigs, _functionSigIds, _ruleIds) = RulesEngineDataFacet(
            address(red)
        ).getPolicy(policyIds[0]);
        assertEq(_ruleIds.length, 1);
        assertEq(_ruleIds[0].length, 1);
        assertEq(_ruleIds[0][0], ruleId);
    }

    // Test attempt to update a rule without policy admin permissions.
    function testRulesEngine_Unit_UpdateRule_NotPolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        address POLICY_ADMIN_USER = address(1);
        address NOT_POLICY_ADMIN_USER = address(2);
        vm.startPrank(POLICY_ADMIN_USER);
        uint256 policyId = _createBlankPolicy(); // this will create the initial policy admin
        Rule memory rule;
        // Instruction set: LC.PLH, 0, LC.PLH, 1, LC.GT, 0, 1
        rule.instructionSet = _createInstructionSet(0, 1);

        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = PT.UINT;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;
        rule.policyId = policyId;

        // Change to non policy admin user
        vm.startPrank(NOT_POLICY_ADMIN_USER);
        vm.expectRevert("Not Authorized To Policy");
        // Attempt to Save the rule
        RulesEngineDataFacet(address(red)).createRule(policyId,rule);
    }
}
