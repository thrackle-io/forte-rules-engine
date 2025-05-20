/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "test/utils/ExampleUserContractEncoding.sol";
import "src/example/ExampleUserContract.sol";
import "src/example/ExampleUserOwnableContract.sol";
import "src/example/ExampleUserAccessControl.sol";
import "src/engine/facets/RulesEngineComponentFacet.sol";
import "src/example/ExampleERC20.sol";

abstract contract RulesEngineUnitTestsCommon is RulesEngineCommon {

    ExampleUserContract userContract;
    ExampleUserContract newUserContract;
    ExampleUserContractExtraParams userContract2;
    ExampleUserContractEncoding encodingContract; 
    ExampleERC20 exampleERC20; 
    
    /// TestRulesEngine: 
    // Test attempt to add a policy with no signatures saved.
    function testRulesEngine_Unit_UpdatePolicy_InvalidRule()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        (uint256 policyId, uint256 ruleId) = setUpRuleSimple();
        ruleId; 
        // Save the function signature
        uint256 functionSignatureId = _addFunctionSignatureToPolicy(policyId);
        signatures.push(bytes4(keccak256(bytes(functionSignature))));
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = 1;
        vm.expectRevert("Invalid Rule");
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            signatures,
            functionSignatureIds,
            ruleIds,
            PolicyType.CLOSED_POLICY
        );
    }

    // Test attempt to add a policy with no signatures saved.
    function testRulesEngine_Unit_UpdatePolicy_InvalidSignature()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // setUpRuleSimple helper not used as test does not set the function signature ID intentionally
        uint256 policyId = _createBlankPolicy();
        signatures.push(bytes4(keccak256(bytes(functionSignature))));
        functionSignatureIds.push(1);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = 1;
        vm.expectRevert("Invalid Signature");
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            signatures,
            functionSignatureIds,
            ruleIds,
            PolicyType.CLOSED_POLICY
        );
    }

    // Test attempt to add a policy with valid parts.
    function testRulesEngine_Unit_UpdatePolicy_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        (uint256 policyId, uint256 ruleId) = setUpRuleSimple();
        ruleId;
        assertGt(
            RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyId,
                signatures,
                functionSignatureIds,
                ruleIds,
                PolicyType.CLOSED_POLICY
            ),
            0
        );
    }

    function testRulesEngine_Unit_CheckRules_Explicit()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        setUpRuleSimple();
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), 5);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(address(userContract), arguments);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_checkRule_simple_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setUpRuleSimple();
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        bool response = userContract.transfer(address(0x7654321), 47);
        assertTrue(response);
    }

    function testRulesEngine_Unit_checkRule_simpleGTEQL_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setUpRuleSimpleGTEQL();
        // test that rule ( amount >= 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        bool response = userContract.transfer(address(0x7654321), 4);
        assertTrue(response);
    }

    function testRulesEngine_Unit_checkRule_simpleLTEQL_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setUpRuleSimpleLTEQL();
        // test that rule ( ruleValue <= amount -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        bool response = userContract.transfer(address(0x7654321), 3);
        assertTrue(response);
    }
    
    function testRulesEngine_Unit_checkRule_simple_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setUpRuleSimple();
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        bool response = userContract.transfer(address(0x7654321), 3);
        assertFalse(response);
    }

    function testRulesEngine_Unit_checkRule_simpleGTEQL_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setUpRuleSimpleGTEQL();
        // test that rule ( ruleValue >= amount -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        bool response = userContract.transfer(address(0x7654321), 3);
        assertFalse(response);
    }

    function testRulesEngine_Unit_checkRule_simpleLTEQL_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setUpRuleSimpleLTEQL();
        // test that rule ( ruleValue <= amount -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        bool response = userContract.transfer(address(0x7654321), 5);
        assertFalse(response);
    }

    function testRulesEngine_Unit_createRule_ForeignCall_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithForeignCall(4, ET.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), transferValue);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(address(userContract), arguments);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_createRule_ForeignCall_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // change values in order to violate rule 
        ruleValue = 15;
        transferValue = 10;
        setupRuleWithForeignCall(ruleValue, ET.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), transferValue);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(address(userContract), arguments);
    }

    function testRulesEngine_Unit_checkRule_ForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        _setup_checkRule_ForeignCall_Positive(ruleValue);
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly 
        bool response = userContract.transfer(address(0x7654321), transferValue);
        assertTrue(response);
    }

    function testRulesEngine_Unit_checkRule_ForeignCall_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // change values in order to violate rule 
        ruleValue = 15;
        transferValue = 10;
        _setup_checkRule_ForeignCall_Negative(ruleValue);
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
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(address(userContract), arguments);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_CheckPolicies_Explicit_StringComparison_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithStringComparison();
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature2))), address(0x7654321), "test");
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(address(userContract), arguments);
        assertEq(response, 0);
    }

    function testRulesEngine_Unit_RetrieveRawStringFromInstructionSet()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 ruleId = setupRuleWithStringComparison();
        StringVerificationStruct memory retVal = RulesEngineProcessorFacet(address(red)).retrieveRawStringFromInstructionSet(1, ruleId, 3);
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
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(address(userContract), arguments);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_CheckPolicies_Explicit_AddressComparison_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithAddressComparison();
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature2))), address(0x7654321), "test");
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(address(userContract), arguments);
        assertEq(response, 0);
    }

    function testRulesEngine_Unit_RetrieveRawAddressFromInstructionSet()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 ruleId = setupRuleWithAddressComparison();
        AddressVerificationStruct memory retVal = RulesEngineProcessorFacet(address(red)).retrieveRawAddressFromInstructionSet(1, ruleId, 3);
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
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(address(userContract), arguments);
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
        RulesEngineProcessorFacet(address(red)).checkPolicies(address(userContract), arguments);
        assertEq(testContract.getInternalValue(), 5);
    }


    function testRulesEngine_Unit_CheckRules_Explicit_WithTrackerUpdateEffectAddress()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();
        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = PT.ADDR;
        tracker.set = true;
        tracker.trackerValue = abi.encode(0xD00D);
        setupRuleWithTrackerAddr(policyId, tracker);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), 5, address(0x7654321));
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the third parameter
        RulesEngineProcessorFacet(address(red)).checkPolicies(address(userContract), arguments);
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        assertEq(tracker.trackerValue, abi.encode(0x7654321));
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithTrackerUpdateEffectBool()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();
        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = PT.BOOL;
        tracker.set = true;
        tracker.trackerValue = abi.encode(bool(false));
        setupRuleWithTrackerBool(policyId, tracker);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), 5, bool(true));
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the third parameter
        RulesEngineProcessorFacet(address(red)).checkPolicies(address(userContract), arguments);
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        assertEq(tracker.trackerValue, abi.encode(bool(true)));
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithTrackerUpdateEffectUint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();
        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = PT.UINT;
        tracker.set = true;
        tracker.trackerValue = abi.encode(uint256(13));
        setupRuleWithTrackerUint(policyId, tracker);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), 5, 99);
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the third parameter
        RulesEngineProcessorFacet(address(red)).checkPolicies(address(userContract), arguments);
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        assertEq(tracker.trackerValue, abi.encode(uint256(99)));
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithTrackerUpdateEffectBytes()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();
        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = PT.BYTES;
        tracker.set = true;
        tracker.trackerValue = bytes("initial");
        setupRuleWithTracker2(policyId, tracker);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), 5, bytes("post"));
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the third parameter
        RulesEngineProcessorFacet(address(red)).checkPolicies(address(userContract), arguments);
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory comparison = abi.encode("post");
        assertEq(tracker.trackerValue, comparison);
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithTrackerUpdateEffectString()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();
        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = PT.BYTES;
        tracker.set = true;
        tracker.trackerValue = "initial";
        setupRuleWithTracker2(policyId, tracker);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), 5, "post");
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the third parameter
        RulesEngineProcessorFacet(address(red)).checkPolicies(address(userContract), arguments);
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory comparison = abi.encode("post");
        assertEq(tracker.trackerValue, comparison);
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithForeignCallNegative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithForeignCall(4, ET.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), 3);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(address(userContract), arguments);
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
        RulesEngineComponentFacet(address(red)).updateTracker(policyId, 1, tracker);

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

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), transferValue);

        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(address(userContract), arguments);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_createRule_Tracker_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithTracker(15);
        transferValue = 10;

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignature))), address(0x7654321), transferValue);

        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(address(userContract), arguments);
    }

    function testRulesEngine_Unit_GetTrackerValue()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = setupRuleWithTracker(2);
        bool retVal = userContract.transfer(address(0x7654321), 3);
        assertTrue(retVal);
        Trackers memory testTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
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
        _addFunctionSignatureToPolicy(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].foreignCall = true;
        rule.placeHolders[1].typeSpecificIndex = 1;

        uint256 ruleId = RulesEnginePolicyFacet(address(red)).updateRule(policyIds[0], 0, rule);

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
        _addFunctionSignatureToPolicy(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Instruction set: LC.PLH, 0, LC.PLH, 1, LC.GT, 0, 1
        rule.instructionSet = _createInstructionSet(0, 1);

        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].trackerValue = true;
        rule.placeHolders[1].typeSpecificIndex = 1;

        uint256 ruleId = RulesEnginePolicyFacet(address(red)).updateRule(policyIds[0], 0, rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        vm.expectRevert("Tracker referenced in rule not set");
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
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
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(1, policyAdmin);
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
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, newPolicyAdmin);
        assertFalse(hasAdminRole);
        vm.expectRevert("Not Policy Admin");
        RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(newPolicyAdmin, policyID);
    }

    function testRulesEngine_unit_adminRoles_ProposedPolicyAdminRole_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicyWithAdminRoleString();
        vm.expectEmit(true, true, false, false);
        emit PolicyAdminRoleProposed(newPolicyAdmin, policyID);
        RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(newPolicyAdmin, policyID);
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        vm.expectEmit(true, true, false, false);
        emit PolicyAdminRoleConfirmed(newPolicyAdmin, policyID);
        RulesEngineAdminRolesFacet(address(red)).confirmNewPolicyAdmin(policyID);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(1, newPolicyAdmin);
        assertTrue(hasAdminRole);
    }

    function testRulesEngine_unit_adminRoles_ProposedPolicyAdminRole_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicyWithAdminRoleString();
        RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(newPolicyAdmin, policyID);
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        vm.expectRevert("Not Policy Admin");
        RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(newPolicyAdmin, policyID);
    }

    function testRulesEngine_unit_adminRoles_RevokePolicyAdminRole_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicyWithAdminRoleString();
        bytes32 adminRole = bytes32(
            abi.encodePacked(
                keccak256(
                    bytes(string.concat(string(abi.encode(1)), "TestString"))
                )
            )
        );
        vm.expectRevert("Below Min Admin Threshold");
        RulesEngineAdminRolesFacet(address(red)).revokeRole(adminRole, policyAdmin, policyId);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(1, policyAdmin);
        assertTrue(hasAdminRole);
    }

    function testRulesEngine_unit_adminRoles_RenouncePolicyAdminRole_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicyWithAdminRoleString();
        bytes32 adminRole = bytes32(
            abi.encodePacked(
                keccak256(
                    bytes(string.concat(string(abi.encode(1)), "TestString"))
                )
            )
        );
        vm.expectRevert("Below Min Admin Threshold");
        RulesEngineAdminRolesFacet(address(red)).renounceRole(adminRole, policyAdmin, 
            policyId);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(1, policyAdmin);
        assertTrue(hasAdminRole);
    }

    function testRulesEngine_unit_adminRoles_CreateTracker_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = PT.ADDR;

        RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");
    }

    function testRulesEngine_unit_adminRoles_CreateTracker_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // TODO return test after admin roles are returned
        // vm.startPrank(policyAdmin);
        // uint256 policyID = _createBlankPolicy();
        // vm.stopPrank();
        // vm.startPrank(newPolicyAdmin);
        // bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, newPolicyAdmin);
        // assertFalse(hasAdminRole);
        // Trackers memory tracker;
        // tracker.trackerValue = abi.encode(address(testContract));
        // tracker.pType = PT.ADDR;

        // vm.expectRevert("Not Authorized To Policy");
        // RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker);
    }

    function testRulesEngine_unit_adminRoles_UpdateTracker_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = PT.ADDR;

        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");

        tracker.trackerValue = abi.encode(address(userContractAddress));
        RulesEngineComponentFacet(address(red)).updateTracker(policyID, trackerId, tracker);
    }

    function testRulesEngine_unit_adminRoles_UpdateTracker_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // TODO return test after admin roles are returned
        // vm.startPrank(policyAdmin);
        // uint256 policyID = _createBlankPolicy();
        // Trackers memory tracker;
        // tracker.trackerValue = abi.encode(address(testContract));
        // tracker.pType = PT.ADDR;
        // uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker);
        // vm.stopPrank();
        // vm.startPrank(newPolicyAdmin);
        // bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, newPolicyAdmin);
        // assertFalse(hasAdminRole);
        // tracker.trackerValue = abi.encode(address(userContractAddress));
        // tracker.pType = PT.ADDR;

        // vm.expectRevert("Not Authorized To Policy");
        // RulesEngineComponentFacet(address(red)).updateTracker(policyID, trackerId, tracker);
    }

    function testRulesEngine_Unit_createFunctionSignature_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        uint256 functionSignatureId = _addFunctionSignatureToPolicy(policyId);
        assertEq(functionSignatureId, 1);
        FunctionSignatureStorageSet memory sig = RulesEngineComponentFacet(address(red)).getFunctionSignature(policyId, functionSignatureId);
        assertEq(sig.set, true);
        assertEq(sig.signature, bytes4(keccak256(bytes(functionSignature))));
        assertEq(uint8(sig.parameterTypes[0]), uint8(PT.ADDR));
        assertEq(uint8(sig.parameterTypes[1]), uint8(PT.UINT));
    }

    function testRulesEngine_Unit_createFunctionSignature_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // TODO return test after admin roles are returned
        // uint256 policyId = _createBlankPolicy();
        // PT[] memory pTypes = new PT[](2);
        // pTypes[0] = PT.ADDR;
        // pTypes[1] = PT.UINT;
        // vm.startPrank(newPolicyAdmin);
        // vm.expectRevert("Not Authorized To Policy");
        // RulesEngineComponentFacet(address(red)).createFunctionSignature(policyId, bytes4(keccak256(bytes(functionSignature))), pTypes);
    }

    function testRulesEngine_Unit_updateFunctionSignature_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        uint256 functionSignatureId = _addFunctionSignatureToPolicy(policyId);
        PT[] memory pTypes2 = new PT[](4);
        pTypes2[0] = PT.ADDR;
        pTypes2[1] = PT.UINT;
        pTypes2[2] = PT.ADDR;
        pTypes2[3] = PT.UINT;
        RulesEngineComponentFacet(address(red)).updateFunctionSignature(policyId, functionSignatureId, bytes4(keccak256(bytes(functionSignature))), pTypes2);
        FunctionSignatureStorageSet memory sig = RulesEngineComponentFacet(address(red)).getFunctionSignature(policyId, functionSignatureId);
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
        uint256 policyId = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        uint256 functionSignatureId = _addFunctionSignatureToPolicy(policyId);
        assertEq(functionSignatureId, 1);
        FunctionSignatureStorageSet memory matchingSignature = RulesEngineComponentFacet(address(red)).getFunctionSignature(policyId, functionSignatureId);
        assertEq(matchingSignature.signature, bytes4(keccak256(bytes(functionSignature))));

        RulesEngineComponentFacet(address(red)).deleteFunctionSignature(policyId, functionSignatureId); 
        FunctionSignatureStorageSet memory sig = RulesEngineComponentFacet(address(red)).getFunctionSignature(policyId, functionSignatureId);
        assertEq(sig.set, false);
        assertEq(sig.signature, bytes4(""));
    }

    function testRulesEngine_Unit_deleteFunctionSignatureMultiple_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory _functionSigs;
        uint256[] memory _functionSigIds;
        uint256[][] memory _ruleIds;
        // This test does not utilize helper _addFunctionSignatureToPolicy(policyId) because it needs to individually set the function signatures for deletion 
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        uint256 functionSignatureId = RulesEngineComponentFacet(address(red)).createFunctionSignature(
            policyId, 
            bytes4(keccak256(bytes(functionSignature))), 
            pTypes,
            functionSignature,
            ""
        );
        assertEq(functionSignatureId, 1);
        uint256 functionSignatureId2 = RulesEngineComponentFacet(address(red)).createFunctionSignature(
            policyId, 
            bytes4(keccak256(bytes(functionSignature2))), 
            pTypes,
            functionSignature2,
            ""
        );
        assertEq(functionSignatureId2, 2);
        FunctionSignatureStorageSet memory matchingSignature = RulesEngineComponentFacet(address(red)).getFunctionSignature(policyId, functionSignatureId);
        assertEq(matchingSignature.signature, bytes4(keccak256(bytes(functionSignature))));

        FunctionSignatureStorageSet memory matchingSignature2 = RulesEngineComponentFacet(address(red)).getFunctionSignature(policyId, functionSignatureId2);
        assertEq(matchingSignature2.signature, bytes4(keccak256(bytes(functionSignature2))));

        RulesEngineComponentFacet(address(red)).deleteFunctionSignature(policyId, functionSignatureId); 
        FunctionSignatureStorageSet memory sig = RulesEngineComponentFacet(address(red)).getFunctionSignature(policyId, functionSignatureId);
        assertEq(sig.set, false);
        assertEq(sig.signature, bytes4(""));

        FunctionSignatureStorageSet memory matchingSignature3 = RulesEngineComponentFacet(address(red)).getFunctionSignature(policyId, functionSignatureId2);
        assertEq(matchingSignature3.signature, bytes4(keccak256(bytes(functionSignature2))));

        //check that policy signatures array is resized to 1 
        (_functionSigs, _functionSigIds, _ruleIds) = RulesEnginePolicyFacet(address(red)).getPolicy(policyId);
        assertEq(_functionSigs.length, 1);
        assertEq(_functionSigs[0], bytes4(keccak256(bytes(functionSignature2))));

    }

    function testRulesEngine_Unit_deleteFunctionSignature_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // TODO return test after admin roles are returned 
        // uint256 policyId = _createBlankPolicy();
        // PT[] memory pTypes = new PT[](2);
        // pTypes[0] = PT.ADDR;
        // pTypes[1] = PT.UINT;
        // uint256 functionSignatureId = _addFunctionSignatureToPolicy(policyId);
        // assertEq(functionSignatureId, 1);

        // vm.startPrank(newPolicyAdmin);
        // vm.expectRevert("Not Authorized To Policy");
        // RulesEngineComponentFacet(address(red)).deleteFunctionSignature(policyId, functionSignatureId); 
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
        RulesEngineComponentFacet(address(red)).getFunctionSignature(1, 0);
        RulesEngineComponentFacet(address(red)).deleteFunctionSignature(1, 1); 
        // test that rule no longer checks 
        bool ruleCheck = userContract.transfer(address(0x7654321), 3);
        assertTrue(ruleCheck);

    }

    function testRulesEngine_Unit_deleteRule_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;
        // Instruction set: LC.PLH, 0, LC.NUM, 4, LC.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder 
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).updateRule(policyId, 0, rule);

        RulesEnginePolicyFacet(address(red)).deleteRule(policyId, ruleId); 
        RuleStorageSet memory sig = RulesEnginePolicyFacet(address(red)).getRule(policyId, ruleId);
        assertEq(sig.set, false);
    }

    function testRulesEngine_Unit_deleteRule_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // TODO return test after admin roles are returned
        // uint256 policyId = _createBlankPolicy();
        // Rule memory rule;
        // // Instruction set: LC.PLH, 0, LC.NUM, 4, LC.GT, 0, 1
        // // Build the instruction set for the rule (including placeholders)
        // rule.instructionSet = _createInstructionSet(4);
        // // Build the calling function argument placeholder 
        // rule.placeHolders = new Placeholder[](1);
        // rule.placeHolders[0].pType = PT.UINT;
        // rule.placeHolders[0].typeSpecificIndex = 1;
        // // Save the rule
        // uint256 ruleId = RulesEnginePolicyFacet(address(red)).updateRule(policyId, 0, rule);

        // vm.startPrank(newPolicyAdmin);
        // vm.expectRevert("Not Authorized To Policy");
        // RulesEnginePolicyFacet(address(red)).deleteRule(policyId, ruleId); 
    }

    function testRulesEngine_Unit_updateFunctionSignature_Negative_NewParameterTypesNotSameLength()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        uint256 functionSignatureId = _addFunctionSignatureToPolicy(policyId);
        PT[] memory pTypes2 = new PT[](1);
        pTypes2[0] = PT.ADDR;
        vm.expectRevert("New parameter types must be of greater or equal length to the original");
        RulesEngineComponentFacet(address(red)).updateFunctionSignature(policyId, functionSignatureId, bytes4(keccak256(bytes(functionSignature))), pTypes2);
    }

    function testRulesEngine_Unit_updateFunctionSignature_Negative_NewParameterTypesNotSameType()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        uint256 functionSignatureId = _addFunctionSignatureToPolicy(policyId);
        PT[] memory pTypes2 = new PT[](2);
        pTypes2[0] = PT.UINT;
        pTypes2[1] = PT.UINT;
        vm.expectRevert("New parameter types must be of the same type as the original");
        RulesEngineComponentFacet(address(red)).updateFunctionSignature(policyId, functionSignatureId, bytes4(keccak256(bytes(functionSignature))), pTypes2);
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
        uint256 functionSignatureId = _addFunctionSignatureToPolicy(policyId);
        vm.expectRevert("Delete function signature before updating to a new one");
        RulesEngineComponentFacet(address(red)).updateFunctionSignature(policyId, functionSignatureId, bytes4(keccak256(bytes(functionSignature2))), pTypes);
    }

    function testRulesEngine_Unit_updateFunctionSignature_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // TODO return test after admin roles are returned
        // uint256 policyId = _createBlankPolicy();
        // PT[] memory pTypes = new PT[](2);
        // pTypes[0] = PT.ADDR;
        // pTypes[1] = PT.UINT;
        // uint256 functionSignatureId = _addFunctionSignatureToPolicy(policyId);
        // vm.startPrank(newPolicyAdmin);
        // vm.expectRevert("Not Authorized To Policy");
        // RulesEngineComponentFacet(address(red)).updateFunctionSignature(policyId, functionSignatureId, bytes4(keccak256(bytes(functionSignature2))), pTypes);
    }

    function testRulesEngine_Unit_updateFunctionSignatureWithRuleCheck_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create rule and set rule to user contract 
        setUpRuleSimple();
        // test rule works for user contract 
        bool response = userContract.transfer(address(0x7654321), 47);
        assertTrue(response);
        // create pTypes array for new contract + new transfer function 
        PT[] memory pTypes = new PT[](3);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.ADDR;
        FunctionSignatureStorageSet memory sig = RulesEngineComponentFacet(address(red)).getFunctionSignature(1, 1);
        RulesEngineComponentFacet(address(red)).updateFunctionSignature(1, 1, bytes4(keccak256(bytes(functionSignature))), pTypes);
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
        setUpRuleSimple();
        // test rule works for user contract 
        bool response = userContract.transfer(address(0x7654321), 3);
        assertFalse(response);
        // create pTypes array for new contract + new transfer function 
        PT[] memory pTypes = new PT[](3);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.ADDR;
        FunctionSignatureStorageSet memory sig = RulesEngineComponentFacet(address(red)).getFunctionSignature(1, 1);
        RulesEngineComponentFacet(address(red)).updateFunctionSignature(1, 1, bytes4(keccak256(bytes(functionSignature))), pTypes);
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
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        RulesEngineComponentFacet(address(red)).deleteTracker(policyID, trackerId);

        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyID, trackerId);
        assertEq(tracker.set, false);
        assertEq(uint8(tracker.pType), uint8(PT.ADDR));
        assertEq(tracker.trackerValue, bytes(""));
    }

    function testRulesEngine_unit_adminRoles_DeleteTracker_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // TODO return test after admin roles are returned
        // vm.startPrank(policyAdmin);
        // uint256 policyID = _createBlankPolicy();
        // Trackers memory tracker;
        // tracker.trackerValue = abi.encode(address(testContract));
        // tracker.pType = PT.ADDR;
        // uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker);
        // vm.stopPrank();
        // vm.startPrank(newPolicyAdmin);
        // bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, newPolicyAdmin);
        // assertFalse(hasAdminRole);
        // vm.expectRevert("Not Authorized To Policy");
        // RulesEngineComponentFacet(address(red)).deleteTracker(policyID, trackerId);
    }

    function testRulesEngine_unit_adminRoles_CreateForeignCall_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        _setUpForeignCallSimple(policyID);
    }

    function testRulesEngine_unit_adminRoles_CreateForeignCall_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // TODO return test after admin roles are returned
        // vm.startPrank(policyAdmin);
        // uint256 policyID = _createBlankPolicy();
        // vm.stopPrank();
        // vm.startPrank(newPolicyAdmin);
        // bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, newPolicyAdmin);
        // assertFalse(hasAdminRole);

        // vm.expectRevert("Not Authorized To Policy");
        // _setUpForeignCallSimple(policyID);
    }

    function testRulesEngine_unit_adminRoles_UpdateForeignCall_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        ForeignCall memory fc;
        fc = _setUpForeignCallSimple(policyID);

        uint256 foreignCallId = RulesEngineComponentFacet(address(red)).createForeignCall(policyID, fc, "simpleCheck(uint256)");
        fc.foreignCallAddress = address(userContractAddress);
        RulesEngineComponentFacet(address(red)).updateForeignCall(policyID, foreignCallId, fc);
    }

    function testRulesEngine_unit_adminRoles_UpdateForeignCall_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // TODO return test after admin roles are returned
        // vm.startPrank(policyAdmin);
        // uint256 policyID = _createBlankPolicy();
        // uint256 foreignCallId;
        // ForeignCall memory fc;
        // (fc, foreignCallId) = _setUpForeignCallSimpleReturnID(policyID);

        // vm.stopPrank();
        // vm.startPrank(newPolicyAdmin);
        // bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, newPolicyAdmin);
        // assertFalse(hasAdminRole);
        // fc.foreignCallAddress = address(userContractAddress);
        // vm.expectRevert("Not Authorized To Policy");
        // RulesEngineComponentFacet(address(red)).updateForeignCall(policyID, foreignCallId, fc);
    }
    
    function testRulesEngine_unit_adminRoles_DeleteForeignCall_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        uint256 foreignCallId;
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);

        ForeignCall memory fc;
        (fc, foreignCallId) = _setUpForeignCallSimpleReturnID(policyID);
        RulesEngineComponentFacet(address(red)).deleteForeignCall(policyID, foreignCallId);

        ForeignCall memory fc2 = RulesEngineComponentFacet(address(red)).getForeignCall(policyID, foreignCallId);
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
        // TODO return test after admin roles are returned
        // vm.startPrank(policyAdmin);
        // uint256 policyID = _createBlankPolicy();
        // uint256 foreignCallId;
        // ForeignCall memory fc;
        // (fc, foreignCallId) = _setUpForeignCallSimpleReturnID(policyID);
        // vm.stopPrank();
        // vm.startPrank(newPolicyAdmin);
        // bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, newPolicyAdmin);
        // assertFalse(hasAdminRole);
        // vm.expectRevert("Not Authorized To Policy");
        // RulesEngineComponentFacet(address(red)).deleteForeignCall(policyID, foreignCallId);
    }

    function testRulesEngine_Unit_GetAllForeignCallsTest()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        for (uint256 i = 0; i < 10; i++) {
            _setUpForeignCallSimpleReturnID(policyId);
        }
        
        ForeignCall[] memory foreignCalls = RulesEngineComponentFacet(address(red)).getAllForeignCalls(policyId);
        assertEq(foreignCalls.length, 10);
        RulesEngineComponentFacet(address(red)).deleteForeignCall(policyId, 3);

        foreignCalls = RulesEngineComponentFacet(address(red)).getAllForeignCalls(policyId);
        assertEq(foreignCalls.length, 10);

        for (uint256 i = 0; i < foreignCalls.length - 1; i++) {
            if (i >= 2) {
                assertEq(foreignCalls[i].foreignCallIndex, i + 2);
            } else {
                assertEq(foreignCalls[i].foreignCallIndex, i + 1);
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
            RulesEngineComponentFacet(address(red)).createTracker(policyId, tracker, "trName");
        }

        Trackers[] memory trackers = RulesEngineComponentFacet(address(red)).getAllTrackers(policyId);
        assertEq(trackers.length, 10);
        RulesEngineComponentFacet(address(red)).deleteTracker(policyId, 3);

        trackers = RulesEngineComponentFacet(address(red)).getAllTrackers(policyId);
        assertEq(trackers.length, 10);
        for (uint256 i = 0; i < trackers.length - 1; i++) {
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

        _addFunctionSignatureToPolicy(policyIds[0]);
        (_functionSigs, _functionSigIds, _ruleIds) = RulesEnginePolicyFacet(address(red)).getPolicy(policyIds[0]);
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

        policyIds[0] = setupEffectWithTrackerUpdateUint();

        (_functionSigs, _functionSigIds, _ruleIds) = RulesEnginePolicyFacet(address(red)).getPolicy(policyIds[0]);
        assertEq(_ruleIds.length, 1);
        assertEq(_ruleIds[0].length, 1);
        assertEq(_ruleIds[0][0], 1);
    }

    // Test attempt to update a rule without policy admin permissions.
    function testRulesEngine_Unit_UpdateRule_NotPolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        // TODO add back after admin roles are returned 
        // vm.startPrank(policyAdmin);

        // uint256 policyId = setupEffectWithTrackerUpdateUint();
        // Rule memory rule;
       
        // // Change to non policy admin user
        // vm.startPrank(user1);
        // vm.expectRevert("Not Authorized To Policy");
        // // Attempt to Save the rule
        // RulesEnginePolicyFacet(address(red)).updateRule(policyId, 0, rule);
    }

    function testRulesEngine_Unit_ApplyPolicy_ClosedPolicy_NotSubscriber() public ifDeploymentTestsEnabled endWithStopPrank {
        // TODO add back after admin roles are returned 
        // uint256 policyId = _createBlankPolicy();
        // bytes4[] memory blankSignatures = new bytes4[](0);
        // uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        // uint256[][] memory blankRuleIds = new uint256[][](0);
        // RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankSignatures, blankFunctionSignatureIds, blankRuleIds, PolicyType.CLOSED_POLICY);
        // uint256[] memory policyIds = new uint256[](1);
        // policyIds[0] = policyId;
        // address potentialSubscriber = address(0xdeadbeef);
        // vm.startPrank(address(1));
        // vm.expectRevert("Not Authorized Admin");
        // RulesEnginePolicyFacet(address(red)).applyPolicy(potentialSubscriber, policyIds);
    }

    function testRulesEngine_Unit_UpdatePolicy_ClosePolicy_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankSignatures, blankFunctionSignatureIds, blankRuleIds, PolicyType.OPEN_POLICY);
        ExampleUserContract potentialSubscriber = new ExampleUserContract();
        potentialSubscriber.setRulesEngineAddress(address(red));
        potentialSubscriber.setCallingContractAdmin(callingContractAdmin);
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(potentialSubscriber), policyIds);
        assertEq(RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(address(potentialSubscriber)).length, 1);
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankSignatures, blankFunctionSignatureIds, blankRuleIds, PolicyType.CLOSED_POLICY);
        assertEq(RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(address(potentialSubscriber)).length, 0);
    }

    function testRulesEngine_Unit_ClosePolicy_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankSignatures, blankFunctionSignatureIds, blankRuleIds, PolicyType.OPEN_POLICY);
        ExampleUserContract potentialSubscriber = new ExampleUserContract();
        potentialSubscriber.setRulesEngineAddress(address(red));
        potentialSubscriber.setCallingContractAdmin(callingContractAdmin);
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(potentialSubscriber), policyIds);
        assertEq(RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(address(potentialSubscriber)).length, 1);
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).closePolicy(policyId);
        assertEq(RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(address(potentialSubscriber)).length, 0);
    }

    function testRulesEngine_Unit_OpenPolicy_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        assertTrue(RulesEnginePolicyFacet(address(red)).isClosedPolicy(policyId));
        RulesEnginePolicyFacet(address(red)).openPolicy(policyId);
        assertFalse(RulesEnginePolicyFacet(address(red)).isClosedPolicy(policyId));
    }

    function testRulesEngine_Unit_ApplyPolicy_OpenPolicy_NotSubscriber() public ifDeploymentTestsEnabled endWithStopPrank {
        
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankSignatures, blankFunctionSignatureIds, blankRuleIds, PolicyType.OPEN_POLICY);
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        ExampleUserContract potentialSubscriber = new ExampleUserContract();
        potentialSubscriber.setRulesEngineAddress(address(red));
        potentialSubscriber.setCallingContractAdmin(callingContractAdmin);
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(potentialSubscriber), policyIds);
    }

    function testRulesEngine_Unit_ApplyPolicy_ClosedPolicy_Subscriber() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankSignatures, blankFunctionSignatureIds, blankRuleIds, PolicyType.CLOSED_POLICY);
        RulesEngineComponentFacet(address(red)).addClosedPolicySubscriber(policyId, callingContractAdmin);
        assertTrue(RulesEngineComponentFacet(address(red)).isClosedPolicySubscriber(policyId, callingContractAdmin));
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(userContract), policyIds);
    }

    function testRulesEngine_Unit_UpdatePolicy_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankSignatures, blankFunctionSignatureIds, blankRuleIds, PolicyType.CLOSED_POLICY);
    }

    function testRulesEngine_Unit_DeletePolicy_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEnginePolicyFacet(address(red)).deletePolicy(policyId);
    }

    function testRulesEngine_Unit_ApplyPolicy_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankSignatures, blankFunctionSignatureIds, blankRuleIds, PolicyType.OPEN_POLICY);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function testRulesEngine_Unit_CreateForeignCall_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankSignatures, blankFunctionSignatureIds, blankRuleIds, PolicyType.OPEN_POLICY);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);

        ForeignCall memory fc;
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256)");
    }


    function testRulesEngine_Unit_DeleteForeignCall_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {

        // set up the ERC20
        uint256 policyId = _setup_checkRule_ForeignCall_Positive(ruleValue);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).deleteForeignCall(policyId,0);
    }

    function testRulesEngine_unit_UpdateForeignCall_Negative_CementedPolicy()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        ForeignCall memory fc;
        fc = _setUpForeignCallSimple(policyID);

        uint256 foreignCallId = RulesEngineComponentFacet(address(red)).createForeignCall(policyID, fc, "simpleCheck(uint256)");
        fc.foreignCallAddress = address(userContractAddress);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyID);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).updateForeignCall(policyID, foreignCallId, fc);
    }

    function testRulesEngine_unit_CreateTracker_Negative_CementedPolicy()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = PT.ADDR;
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyID);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");
    }

    function testRulesEngine_unit_DeleteTracker_Negative_CementedPolicy()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = PT.ADDR;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyID);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).deleteTracker(policyID, trackerId);
    }

    function testRulesEngine_Unit_createFunctionSignature_Negative_CementedPolicy()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyID = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyID);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).createFunctionSignature(
            policyID, 
            bytes4(keccak256(bytes(functionSignature))), 
            pTypes,
            functionSignature,
            "");
    }

    function testRulesEngine_Unit_updateFunctionSignature_Negative_CementedPolicy()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create rule and set rule to user contract 
        (uint256 policyID, uint256 ruleID) = setUpRuleSimple();
        ruleID;
        RulesEngineComponentFacet(address(red)).getFunctionSignature(1, 1);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyID);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).updateFunctionSignature(1, 1, bytes4(keccak256(bytes(functionSignature))), new PT[](3));
    }

    function testRulesEngine_Unit_deleteFunctionSignature_Negative_CementedPolicy()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        uint256 functionSignatureId = _addFunctionSignatureToPolicy(policyId);
        assertEq(functionSignatureId, 1);
        FunctionSignatureStorageSet memory matchingSignature = RulesEngineComponentFacet(address(red)).getFunctionSignature(policyId, functionSignatureId);
        assertEq(matchingSignature.signature, bytes4(keccak256(bytes(functionSignature))));

        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).deleteFunctionSignature(policyId, functionSignatureId); 
    }

    function testRulesEngine_Unit_updateRule_Negative_CementedPolicy()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;

        // Instruction set: LC.PLH, 0, LC.PLH, 1, LC.GT, 0, 1
        rule.instructionSet = _createInstructionSet(0, 1);

        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].trackerValue = true;
        rule.placeHolders[1].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;

        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyId, rule);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEnginePolicyFacet(address(red)).updateRule(policyId, ruleId, rule);
    }

    function testRulesEngine_Unit_createRule_Negative_CementedPolicy()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;

        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEnginePolicyFacet(address(red)).createRule(policyId, rule);
    }

    function testRulesEngine_Unit_RemoveClosedPolicy_Subscriber_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankSignatures, blankFunctionSignatureIds, blankRuleIds, PolicyType.CLOSED_POLICY);
        RulesEngineComponentFacet(address(red)).addClosedPolicySubscriber(policyId, address(1));
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).removeClosedPolicySubscriber(policyId, address(1));
    }

    function testRulesEngine_Unit_CreateCallingContractAdmin_ThroughCallingContract_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.expectEmit(true, true, false, false);
        emit CallingContractAdminRoleGranted(newUserContractAddress, callingContractAdmin); 
        newUserContract.setCallingContractAdmin(callingContractAdmin);
        assertTrue(RulesEngineAdminRolesFacet(address(red)).isCallingContractAdmin(newUserContractAddress, callingContractAdmin));
    }

    function testRulesEngine_Unit_CreateCallingContractAdmin_ThroughCallingContract_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        newUserContract.setCallingContractAdmin(policyAdmin);
        assertFalse(RulesEngineAdminRolesFacet(address(red)).isCallingContractAdmin(newUserContractAddress, callingContractAdmin));
    }

        function testRulesEngine_Unit_ProposeAndConfirm_CallingContractAdmin_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        newUserContract.setCallingContractAdmin(callingContractAdmin);
        assertTrue(RulesEngineAdminRolesFacet(address(red)).isCallingContractAdmin(newUserContractAddress, callingContractAdmin));
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEngineAdminRolesFacet(address(red)).proposeNewCallingContractAdmin(newUserContractAddress, user1);
        vm.stopPrank();
        vm.startPrank(user1);
        RulesEngineAdminRolesFacet(address(red)).confirmNewCallingContractAdmin(newUserContractAddress); 

        assertTrue(RulesEngineAdminRolesFacet(address(red)).isCallingContractAdmin(newUserContractAddress, user1));
        assertFalse(RulesEngineAdminRolesFacet(address(red)).isCallingContractAdmin(newUserContractAddress, callingContractAdmin));
    }

    function testRulesEngine_Unit_ProposeAndConfirm_CallingContractAdmin_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        newUserContract.setCallingContractAdmin(callingContractAdmin);
        assertTrue(RulesEngineAdminRolesFacet(address(red)).isCallingContractAdmin(newUserContractAddress, callingContractAdmin));
        vm.stopPrank();
        vm.startPrank(user1);
        vm.expectRevert("Not Calling Contract Admin");
        RulesEngineAdminRolesFacet(address(red)).proposeNewCallingContractAdmin(newUserContractAddress, user1);
    }

    function testRulesEngine_Unit_CreateCallingContractAdmin_ThroughEngineOwnable_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        ExampleUserOwnableContract ownableUserContract = new ExampleUserOwnableContract(callingContractAdmin);
        address ownableUserContractAddress = address(ownableUserContract);
        ownableUserContract.setRulesEngineAddress(address(red));
        vm.expectEmit(true, true, false, false);
        emit CallingContractAdminRoleGranted(ownableUserContractAddress, callingContractAdmin); 
        RulesEngineAdminRolesFacet(address(red)).grantCallingContractRoleOwnable(ownableUserContractAddress, callingContractAdmin);
        assertTrue(RulesEngineAdminRolesFacet(address(red)).isCallingContractAdmin(ownableUserContractAddress, callingContractAdmin));
    }

    function testRulesEngine_Unit_CreateCallingContractAdmin_ThroughEngineOwnable_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        ExampleUserOwnableContract ownableUserContract = new ExampleUserOwnableContract(policyAdmin);
        address ownableUserContractAddress = address(ownableUserContract);
        ownableUserContract.setRulesEngineAddress(address(red));
        vm.expectRevert("Calling Contract Admin Role Not Granted From Calling Contract");
        RulesEngineAdminRolesFacet(address(red)).grantCallingContractRoleOwnable(ownableUserContractAddress, callingContractAdmin);
        assertFalse(RulesEngineAdminRolesFacet(address(red)).isCallingContractAdmin(ownableUserContractAddress, callingContractAdmin));
    }

    function testRulesEngine_Unit_CreateCallingContractAdmin_ThroughEngine_NonSupportedType_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        ExampleUserOwnableContract ownableUserContract = new ExampleUserOwnableContract(policyAdmin);
        address ownableUserContractAddress = address(ownableUserContract);
        ownableUserContract.setRulesEngineAddress(address(red));
        vm.expectRevert(); // results in evmError: revert since the function is not inside contract 
        RulesEngineAdminRolesFacet(address(red)).grantCallingContractRoleAccessControl(ownableUserContractAddress, callingContractAdmin);
        assertFalse(RulesEngineAdminRolesFacet(address(red)).isCallingContractAdmin(ownableUserContractAddress, callingContractAdmin));
    }

    function testRulesEngine_Unit_CreateCallingContractAdmin_ThroughEngineAccessControl_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        ExampleUserAccessControl acUserContract = new ExampleUserAccessControl(callingContractAdmin);
        address acUserContractAddress = address(acUserContract);
        acUserContract.setRulesEngineAddress(address(red));
        vm.expectEmit(true, true, false, false);
        emit CallingContractAdminRoleGranted(acUserContractAddress, callingContractAdmin); 
        RulesEngineAdminRolesFacet(address(red)).grantCallingContractRoleAccessControl(acUserContractAddress, callingContractAdmin);
        assertTrue(RulesEngineAdminRolesFacet(address(red)).isCallingContractAdmin(acUserContractAddress, callingContractAdmin));
    }

    function testRulesEngine_Unit_CreateCallingContractAdmin_ThroughEngineAccessControl_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        ExampleUserAccessControl acUserContract = new ExampleUserAccessControl(policyAdmin);
        address acUserContractAddress = address(acUserContract);
        acUserContract.setRulesEngineAddress(address(red));
        vm.expectRevert("Calling Contract Admin Role Not Granted From Calling Contract");
        RulesEngineAdminRolesFacet(address(red)).grantCallingContractRoleAccessControl(acUserContractAddress, callingContractAdmin);
        assertFalse(RulesEngineAdminRolesFacet(address(red)).isCallingContractAdmin(acUserContractAddress, callingContractAdmin));
    }

    ///////////////////////////// Event Emission Tests 
    function testRulesEngine_Unit_CreatePolicyEvent() public ifDeploymentTestsEnabled endWithStopPrank {
        FunctionSignatureStorageSet[] memory functionSignatures = new FunctionSignatureStorageSet[](0); 
        Rule[] memory rules = new Rule[](0); 
        uint256 policyId = 1;
        vm.expectEmit(true, false, false, false);
        emit PolicyCreated(policyId); 
        emit PolicyAdminRoleGranted(policyAdmin, policyId);
        RulesEnginePolicyFacet(address(red)).createPolicy(functionSignatures, rules, PolicyType.CLOSED_POLICY);
    }

    function testRulesEngine_Unit_UpdatePolicy_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        (uint256 policyId, uint256 ruleId) = setUpRuleSimple();
        ruleId;
        vm.expectEmit(true, false, false, false);
        emit PolicyUpdated(policyId); 
        RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyId,
                signatures,
                functionSignatureIds,
                ruleIds,
                PolicyType.CLOSED_POLICY
            );
    }

    function testRulesEngine_Unit_DeletePolicy_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        vm.expectEmit(true, false, false, false);
        emit PolicyDeleted(policyId); 
        RulesEnginePolicyFacet(address(red)).deletePolicy(policyId);
    }

    function testRulesEngine_Unit_AppliedPolicy_Event() public ifDeploymentTestsEnabled endWithStopPrank { 
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankSignatures, blankFunctionSignatureIds, blankRuleIds, PolicyType.OPEN_POLICY);

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        vm.expectEmit(true, false, false, false);
        emit PolicyApplied(policyIds, userContractAddress);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function testRulesEngine_Unit_CementedPolicy_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        vm.expectEmit(true, false, false, false);
        emit PolicyCemented(policyId); 
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
    }

    function testRulesEngine_Unit_OpenPolicy_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        vm.expectEmit(true, false, false, false);
        emit PolicyOpened(policyId); 
        RulesEnginePolicyFacet(address(red)).openPolicy(policyId);
    }

    function testRulesEngine_Unit_ClosePolicy_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        vm.expectEmit(true, false, false, false);
        emit PolicyClosed(policyId); 
        RulesEnginePolicyFacet(address(red)).closePolicy(policyId);
    }

    function testRulesEngine_Unit_ClosedPolicySubscriber_AddRemove_Events() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankSignatures, blankFunctionSignatureIds, blankRuleIds, PolicyType.CLOSED_POLICY);
        vm.expectEmit(true, false, false, false);
        emit PolicySubsciberAdded(policyId, callingContractAdmin);
        RulesEngineComponentFacet(address(red)).addClosedPolicySubscriber(policyId, callingContractAdmin);

        vm.expectEmit(true, false, false, false);
        emit PolicySubsciberRemoved(policyId, callingContractAdmin);
        RulesEngineComponentFacet(address(red)).removeClosedPolicySubscriber(policyId, callingContractAdmin);
    }

    function testRulesEngine_Unit_createFunctionSignature_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        uint256 functionSignatureId = 1;
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        vm.expectEmit(true, false, false, false);
        emit FunctionSignatureCreated(policyId, functionSignatureId);
        RulesEngineComponentFacet(address(red)).createFunctionSignature(
            policyId, 
            bytes4(bytes4(keccak256(bytes(functionSignature)))), 
            pTypes,
            functionSignature,
            ""
        );
    }

    function testRulesEngine_Unit_updateFunctionSignature_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        uint256 functionSignatureId = _addFunctionSignatureToPolicy(policyId);
        PT[] memory pTypes2 = new PT[](4);
        pTypes2[0] = PT.ADDR;
        pTypes2[1] = PT.UINT;
        pTypes2[2] = PT.ADDR;
        pTypes2[3] = PT.UINT;
        vm.expectEmit(true, false, false, false);
        emit FunctionSignatureUpdated(policyId, functionSignatureId);
        RulesEngineComponentFacet(address(red)).updateFunctionSignature(policyId, functionSignatureId, bytes4(keccak256(bytes(functionSignature))), pTypes2);
    }

    function testRulesEngine_Unit_deleteFunctionSignature_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        uint256 functionSignatureId = _addFunctionSignatureToPolicy(policyId);
        vm.expectEmit(true, false, false, false);
        emit FunctionSignatureDeleted(policyId, functionSignatureId);
        RulesEngineComponentFacet(address(red)).deleteFunctionSignature(policyId, functionSignatureId); 

    }

    function testRulesEngine_Unit_deleteRule_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;
        // Instruction set: LC.PLH, 0, LC.NUM, 4, LC.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder 
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).updateRule(policyId, 0, rule);
        vm.expectEmit(true, false, false, false);
        emit RuleDeleted(policyId, ruleId);
        RulesEnginePolicyFacet(address(red)).deleteRule(policyId, ruleId); 

    }

    function testRulesEngine_unit_CreateTracker_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        uint256 trackerId = 1;
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = PT.ADDR;
        vm.expectEmit(true, false, false, false);
        emit TrackerCreated(policyID, trackerId);
        RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");
    }

    function testRulesEngine_unit_UpdateTracker_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = PT.ADDR;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");
        tracker.trackerValue = abi.encode(address(userContractAddress));
        vm.expectEmit(true, false, false, false);
        emit TrackerUpdated(policyID, trackerId);
        RulesEngineComponentFacet(address(red)).updateTracker(policyID, trackerId, tracker);
    }

    function testRulesEngine_unit_DeleteTracker_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = PT.ADDR;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");

        vm.expectEmit(true, false, false, false);
        emit TrackerDeleted(policyID, trackerId);
        RulesEngineComponentFacet(address(red)).deleteTracker(policyID, trackerId);
    }

        function testRulesEngine_unit_adminRoles_CreateForeignCall_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        uint256 foreignCallId = 1; 
        ForeignCall memory fc;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.UINT;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 1;
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;
        vm.expectEmit(true, false, false, false);
        emit ForeignCallCreated(policyID, foreignCallId);
        RulesEngineComponentFacet(address(red)).createForeignCall(policyID, fc, "simpleCheck(uint256)");
    }


    function testRulesEngine_unit_adminRoles_UpdateForeignCall_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        ForeignCall memory fc;
        fc = _setUpForeignCallSimple(policyID);
        uint256 foreignCallId = RulesEngineComponentFacet(address(red)).createForeignCall(policyID, fc, "simpleCheck(uint256)");
        fc.foreignCallAddress = address(userContractAddress);
        vm.expectEmit(true, false, false, false);
        emit ForeignCallUpdated(policyID, foreignCallId);
        RulesEngineComponentFacet(address(red)).updateForeignCall(policyID, foreignCallId, fc);
    }

    
    function testRulesEngine_unit_adminRoles_DeleteForeignCall_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        uint256 foreignCallId;
        ForeignCall memory fc;
        (fc, foreignCallId) = _setUpForeignCallSimpleReturnID(policyID);
        vm.expectEmit(true, false, false, false);
        emit ForeignCallDeleted(policyID, foreignCallId);
        RulesEngineComponentFacet(address(red)).deleteForeignCall(policyID, foreignCallId);
    }

    function testRulesEngine_Unit_CreateRule_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();
        uint256 ruleId = 1;
        Rule memory rule;
        vm.expectEmit(true, false, false, false);
        emit RuleCreated(policyId, ruleId);
        RulesEnginePolicyFacet(address(red)).createRule(policyId, rule);
    }

    function testRulesEngine_Unit_UpdateRule_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyId, rule);
        vm.expectEmit(true, false, false, false);
        emit RuleUpdated(policyId, ruleId);
        RulesEnginePolicyFacet(address(red)).updateRule(policyId, 0, rule);
    }

    /////////////////////////////// additional data encoding tests 
    function testRulesEngine_Unit_TestContractEncoding_AdditionalParamsEncoded_UintRuleValue() public ifDeploymentTestsEnabled endWithStopPrank {
        // encode additional datas with the calling contract call into rules engine 
        //deploy ExampleUserContractEncoding  
        encodingContract = new ExampleUserContractEncoding(); 
        encodingContract.setRulesEngineAddress(address(red)); 
        encodingContract.setCallingContractAdmin(callingContractAdmin); 
        address encodingContractAddress = address(encodingContract); 
        // write data to encode: 
        encodingContract.writeNewUintData(74);
        // create rule that will handle additional params 
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        /// Build the function signature to include additional pTypes to match the data being passed in
        PT[] memory pTypes = new PT[](3);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.UINT;
        // Save the function signature
        uint256 functionSignatureId = RulesEngineComponentFacet(address(red))
            .createFunctionSignature(
                policyIds[0], 
                bytes4(bytes4(keccak256(bytes(functionSignature)))), 
                pTypes,
                functionSignature,
                ""
            );
        // Save the Policy
        signatures.push(bytes4(keccak256(bytes(functionSignature))));
        functionSignatureIds.push(functionSignatureId);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            signatures,
            functionSignatureIds,
            blankRuleIds,
            PolicyType.CLOSED_POLICY
        );

        // create Rule - cannot use existing helper functions since rule is unique to test scenario 
        // Rule: amount > 100 -> OR -> transferDataValue > 75 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        // IF amount is greater than 100 or transfer value is greater than 75 -> checkPolicy returns false 
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();

        rule.instructionSet = new uint256[](14);
        rule.instructionSet[0] = uint(LC.PLH);
        rule.instructionSet[1] = 1; //0
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = 100; // 1
        rule.instructionSet[4] = uint(LC.GT);
        rule.instructionSet[5] = 1;
        rule.instructionSet[6] = 0; // 2   
        rule.instructionSet[7] = uint(LC.PLH);
        rule.instructionSet[8] = 2; // 3
        rule.instructionSet[9] = uint(LC.NUM);
        rule.instructionSet[10] = 75; // 4 
        rule.instructionSet[11] = uint(LC.GT);
        rule.instructionSet[12] = 4;
        rule.instructionSet[13] = 3; // 5 

    
        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = PT.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = PT.UINT;
        rule.placeHolders[2].typeSpecificIndex = 2; // Additional uint 


        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);

        uint256 ruleID = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleID;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);

        // test rule processing 
        bool response = encodingContract.transfer(address(0xacdc), 99);
        assertTrue(response); 

    }

    function testRulesEngine_Unit_TestContractEncoding_AdditionalParamsEncoded_AddressRuleValue() public ifDeploymentTestsEnabled endWithStopPrank {
        // encode additional datas with the calling contract call into rules engine 
        //deploy ExampleUserContractEncoding  
        encodingContract = new ExampleUserContractEncoding(); 
        encodingContract.setRulesEngineAddress(address(red)); 
        encodingContract.setCallingContractAdmin(callingContractAdmin); 
        address encodingContractAddress = address(encodingContract); 

        encodingContract.writeNewAddressData(address(0x1234567));

        // create rule that will handle additional params 
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Set up some effects.
        _setupEffectProcessor();
        /// Build the function signature to include additional pTypes to match the data being passed in
        PT[] memory pTypes = new PT[](4);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.ADDR;
        pTypes[3] = PT.ADDR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = uint256(uint160(address(0x1234567)));
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.rawData.argumentTypes = new PT[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = PT.ADDR;
        rule.rawData.dataValues[0] = abi.encode(0x1234567);
        rule.rawData.instructionSetIndex[0] = 3;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = PT.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = PT.ADDR;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional address param 

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);
        // Save the function signature
        uint256 functionSignatureId = RulesEngineComponentFacet(address(red)).createFunctionSignature(
            policyIds[0], 
            bytes4(bytes4(keccak256(bytes(functionSignature3)))), 
            pTypes,
            functionSignature3,
            ""    
        );


        // Save the Policy
        signatures.push(bytes4(keccak256(bytes(functionSignature3))));
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], signatures, functionSignatureIds, ruleIds, PolicyType.CLOSED_POLICY);    
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);    
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);
        // // test rule processing 
        // transferFrom in this contract is transferFrom(address,amount) != transferFrom(from,to,amount)
        bool response1 = encodingContract.transferFrom(address(0x1234567), 99);
        assertTrue(response1); 
         
        bool response2 = encodingContract.transferFrom(address(0x31337), 75);
        assertTrue(response2);

    }

    function testRulesEngine_Unit_TestContractEncoding_AdditionalParamsEncoded_ForeignCallValue() public ifDeploymentTestsEnabled endWithStopPrank {
        // encode additional datas with the calling contract call into rules engine 
        //deploy ExampleUserContractEncoding  
        encodingContract = new ExampleUserContractEncoding(); 
        encodingContract.setRulesEngineAddress(address(red)); 
        encodingContract.setCallingContractAdmin(callingContractAdmin); 
        address encodingContractAddress = address(encodingContract); 

        encodingContract.writeNewAddressData(address(0x1234567));
        testContract2 = new ForeignCallTestContractOFAC();
        testContract2.addToNaughtyList(address(0x1234567));

        // create rule that will handle additional params 
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Set up some effects.
        _setupEffectProcessor();
        /// Build the function signature to include additional pTypes to match the data being passed in
        PT[] memory pTypes = new PT[](4);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.ADDR;
        pTypes[3] = PT.ADDR;

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.ADDR;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 2; // set the placeholder index to retrieve value 
        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract2);
        fc.signature = bytes4(keccak256(bytes("getNaughty(address)")));
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 1;
        uint256 foreignCallId = RulesEngineComponentFacet(address(red)).createForeignCall(policyIds[0], fc, "getNaughty(address)");

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.rawData.argumentTypes = new PT[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = PT.ADDR;
        rule.rawData.dataValues[0] = abi.encode(0x1234567);
        rule.rawData.instructionSetIndex[0] = 3;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = PT.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = PT.ADDR;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional address param 
        rule.placeHolders[2].foreignCall = true;
        rule.placeHolders[2].typeSpecificIndex = uint128(foreignCallId);

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);

        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);
        // Save the function signature
        uint256 functionSignatureId = RulesEngineComponentFacet(address(red)).createFunctionSignature(
            policyIds[0], 
            bytes4(bytes4(keccak256(bytes(functionSignature3)))), 
            pTypes,
            functionSignature3,
            ""
        );

        // Save the Policy
        signatures.push(bytes4(keccak256(bytes(functionSignature3))));
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], signatures, functionSignatureIds, ruleIds, PolicyType.CLOSED_POLICY);    
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);    
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);

        // // test rule processing 
        // transferFrom in this contract is transferFrom(address,amount) != transferFrom(from,to,amount)
        bool response3 = encodingContract.transferFrom(address(0x1234567), 99);
        assertTrue(response3); 
         
        bool response4 = encodingContract.transferFrom(address(0x31337), 75);
        assertTrue(response4);
        
    }

    /// Expanded Variable Tests 
    // Test that and additional bool value will be processed by the rules engine 
    function testRulesEngine_Unit_TestContractEncoding_AdditionalParamsEncoded_BoolRuleValue() public ifDeploymentTestsEnabled endWithStopPrank {
       // encode additional datas with the calling contract call into rules engine 
        //deploy ExampleUserContractEncoding  
        encodingContract = new ExampleUserContractEncoding(); 
        encodingContract.setRulesEngineAddress(address(red)); 
        encodingContract.setCallingContractAdmin(callingContractAdmin); 
        address encodingContractAddress = address(encodingContract); 

        encodingContract.writeNewBoolData(true);

        // create rule that will handle additional params 
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Set up some effects.
        _setupEffectProcessor();
        /// Build the function signature to include additional pTypes to match the data being passed in
        PT[] memory pTypes = new PT[](4);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.BOOL;
        pTypes[3] = PT.ADDR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = uint256(1);
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = PT.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = PT.BOOL;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional bytes32 param 

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);
        // Save the function signature
        uint256 functionSignatureId = RulesEngineComponentFacet(address(red)).createFunctionSignature(
            policyIds[0], 
            bytes4(bytes4(keccak256(bytes(functionSignatureBool)))), 
            pTypes,
            functionSignatureBool,
            ""
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        // Save the Policy
        signatures.push(bytes4(keccak256(bytes(functionSignatureBool))));
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], signatures, functionSignatureIds, ruleIds, PolicyType.CLOSED_POLICY);    
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);    
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);
        // test rule processing 
        bool response = encodingContract.transferBool(address(0x1234567), 99);
        assertTrue(response); 
    }

    // Bytes param test 
    // Test that the rules engine can accept bool params and process != and == operations 
    function testRulesEngine_Unit_TestContractEncoding_BytesRuleValue() public ifDeploymentTestsEnabled endWithStopPrank {
       // encode additional datas with the calling contract call into rules engine 
        //deploy ExampleUserContractEncoding  
        encodingContract = new ExampleUserContractEncoding(); 
        encodingContract.setRulesEngineAddress(address(red)); 
        encodingContract.setCallingContractAdmin(callingContractAdmin); 
        address encodingContractAddress = address(encodingContract); 
        bytes memory TEST = bytes("TEST");
        // create rule that will handle additional params 
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Set up some effects.
        _setupEffectProcessor();
        /// Build the function signature to include additional pTypes to match the data being passed in
        PT[] memory pTypes = new PT[](3);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.BYTES;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = uint256(keccak256(abi.encode(TEST)));
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = PT.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = PT.BYTES;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional bytes32 param 

        rule.rawData.argumentTypes = new PT[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = PT.BYTES;
        rule.rawData.dataValues[0] = abi.encode(TEST);
        rule.rawData.instructionSetIndex[0] = 3;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);
        // Save the function signature
        uint256 functionSignatureId = RulesEngineComponentFacet(address(red)).createFunctionSignature(
            policyIds[0], 
            bytes4(bytes4(keccak256(bytes(functionSignatureWithBytes)))), 
            pTypes,
            functionSignatureWithBytes,
            ""
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        // Save the Policy
        signatures.push(bytes4(keccak256(bytes(functionSignatureWithBytes))));
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], signatures, functionSignatureIds, ruleIds, PolicyType.CLOSED_POLICY);    
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);    
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);
        // test rule processing 
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(functionSignatureWithBytes))), address(0x7654321), 99, TEST);
        RulesEngineProcessorFacet(address(red)).checkPolicies(address(encodingContract), arguments);

        bool response = encodingContract.transferWithBytes(address(0x1234567), 99, TEST);
        assertTrue(response); 
        response = encodingContract.transferWithBytes(address(0x1234567), 99, bytes("BAD TEST"));
        assertFalse(response); 

    }

    function testRulesEngine_Unit_TestContractEncoding_AdditionalParamsEncoded_BytesRuleValue() public ifDeploymentTestsEnabled endWithStopPrank {
       // encode additional datas with the calling contract call into rules engine 
        //deploy ExampleUserContractEncoding  
        encodingContract = new ExampleUserContractEncoding(); 
        encodingContract.setRulesEngineAddress(address(red)); 
        encodingContract.setCallingContractAdmin(callingContractAdmin); 
        address encodingContractAddress = address(encodingContract); 
        bytes memory TEST = bytes("TEST");

        encodingContract.writeNewBytesData(TEST);
        // create rule that will handle additional params 
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Set up some effects.
        _setupEffectProcessor();
        /// Build the function signature to include additional pTypes to match the data being passed in
        PT[] memory pTypes = new PT[](4);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.BYTES;
        pTypes[3] = PT.ADDR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = uint256(keccak256(abi.encode(TEST)));
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = PT.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = PT.BYTES;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional bytes32 param 

        rule.rawData.argumentTypes = new PT[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = PT.BYTES;
        rule.rawData.dataValues[0] = abi.encode(TEST);
        rule.rawData.instructionSetIndex[0] = 3;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);
        // Save the function signature
        uint256 functionSignatureId = RulesEngineComponentFacet(address(red)).createFunctionSignature(
            policyIds[0], 
            bytes4(bytes4(keccak256(bytes(functionSignatureBytes)))), 
            pTypes,
            functionSignatureBytes,
            ""
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        // Save the Policy
        signatures.push(bytes4(keccak256(bytes(functionSignatureBytes))));
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], signatures, functionSignatureIds, ruleIds, PolicyType.CLOSED_POLICY);    
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);    
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);
        // test rule processing 
        bool response = encodingContract.transferBytes(address(0x1234567), 99);
        assertTrue(response); 

        encodingContract.writeNewBytesData(bytes("BAD TEST INFO"));
        response = encodingContract.transferBytes(address(0x1234567), 99);
        assertFalse(response); 

    }

    function testRulesEngine_Unit_TestContractEncoding_AdditionalParamsEncoded_StringRuleValue() public ifDeploymentTestsEnabled endWithStopPrank {
       // encode additional datas with the calling contract call into rules engine 
        //deploy ExampleUserContractEncoding  
        encodingContract = new ExampleUserContractEncoding(); 
        encodingContract.setRulesEngineAddress(address(red)); 
        encodingContract.setCallingContractAdmin(callingContractAdmin); 
        address encodingContractAddress = address(encodingContract); 
        string memory testString = "TEST"; 

        // create rule that will handle additional params 
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Set up some effects.
        _setupEffectProcessor();
        /// Build the function signature to include additional pTypes to match the data being passed in
        PT[] memory pTypes = new PT[](3);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.STR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = uint256(keccak256(abi.encode(testString)));
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = PT.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = PT.STR;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional string param 

        rule.rawData.argumentTypes = new PT[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = PT.STR;
        rule.rawData.dataValues[0] = abi.encode(testString);
        rule.rawData.instructionSetIndex[0] = 3;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);
        // Save the function signature
        uint256 functionSignatureId = RulesEngineComponentFacet(address(red)).createFunctionSignature(
            policyIds[0], 
            bytes4(bytes4(keccak256(bytes(functionSignatureWithString)))), 
            pTypes,
            functionSignatureWithString,
            ""
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        // Save the Policy
        signatures.push(bytes4(keccak256(bytes(functionSignatureWithString))));
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], signatures, functionSignatureIds, ruleIds, PolicyType.CLOSED_POLICY);    
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);    
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);
        // test rule processing 
        bool response = encodingContract.transferWithString(address(0x1234567), 99, testString);
        assertTrue(response); 
        response = encodingContract.transferWithString(address(0x1234567), 99, "bad string");
        assertFalse(response); 

    }

    // Bytes param test 
    function testRulesEngine_Unit_TestContractEncoding_AdditionalParamsEncoded_StaticArrayRuleValue() public ifDeploymentTestsEnabled endWithStopPrank {
       // encode additional datas with the calling contract call into rules engine 
        //deploy ExampleUserContractEncoding  
        encodingContract = new ExampleUserContractEncoding(); 
        encodingContract.setRulesEngineAddress(address(red)); 
        encodingContract.setCallingContractAdmin(callingContractAdmin); 
        address encodingContractAddress = address(encodingContract); 

        // create new uint array for transfer data 
        uint256[] memory testUintArray = new uint256[](3); 
        testUintArray[0] = 1; 
        testUintArray[1] = 2; 
        testUintArray[2] = 3; 
        encodingContract.writeNewStaticArrayData(testUintArray);

        // create rule that will handle additional params 
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Set up some effects.
        _setupEffectProcessor();
        /// Build the function signature to include additional pTypes to match the data being passed in
        PT[] memory pTypes = new PT[](4);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.STATIC_TYPE_ARRAY;
        pTypes[3] = PT.ADDR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = uint256(3); // uint length of array to test that rule retreives uint array length correctly 
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = PT.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = PT.STATIC_TYPE_ARRAY;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional bytes32 param 

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);
        // Save the function signature
        uint256 functionSignatureId = RulesEngineComponentFacet(address(red)).createFunctionSignature(
            policyIds[0], 
            bytes4(bytes4(keccak256(bytes(functionSignatureArrayStatic)))), 
            pTypes,
            functionSignatureArrayStatic,
            ""  
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        // Save the Policy
        signatures.push(bytes4(keccak256(bytes(functionSignatureArrayStatic))));
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], signatures, functionSignatureIds, ruleIds, PolicyType.CLOSED_POLICY);    
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);    
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);
        // test rule processing 
        bool response = encodingContract.transferArray(address(0x1234567), 99);
        assertTrue(response); 

    }

    function testRulesEngine_Unit_TestContractEncoding_AdditionalParamsEncoded_DynamicArrayRuleValue() public ifDeploymentTestsEnabled endWithStopPrank {
       // encode additional datas with the calling contract call into rules engine 
        //deploy ExampleUserContractEncoding  
        encodingContract = new ExampleUserContractEncoding(); 
        encodingContract.setRulesEngineAddress(address(red)); 
        encodingContract.setCallingContractAdmin(callingContractAdmin); 
        address encodingContractAddress = address(encodingContract); 

        // create new uint array for transfer data 
        bytes[] memory array = new bytes[](5);
        array[0] = bytes("super");
        array[1] = bytes("superduper");
        array[2] = bytes("superduperduper");
        array[3] = bytes("superduperduperduper");
        array[4] = bytes("superduperduperduperduper");

        encodingContract.writeNewDynamicArrayData(array);

        // create rule that will handle additional params 
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Set up some effects.
        _setupEffectProcessor();

        /// Build the function signature to include additional pTypes to match the data being passed in
        PT[] memory pTypes = new PT[](4);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.STATIC_TYPE_ARRAY;
        pTypes[3] = PT.ADDR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = uint256(5); // uint length of array to test that rule retreives uint array length correctly 
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = PT.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = PT.DYNAMIC_TYPE_ARRAY;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional bytes32 param 

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);
        // Save the function signature
        uint256 functionSignatureId = RulesEngineComponentFacet(address(red)).createFunctionSignature(
            policyIds[0], 
            bytes4(bytes4(keccak256(bytes(functionSignatureArrayDynamic)))), 
            pTypes,
            functionSignatureArrayDynamic,
            ""    
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        // Save the Policy
        signatures.push(bytes4(keccak256(bytes(functionSignatureArrayDynamic))));
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], signatures, functionSignatureIds, ruleIds, PolicyType.CLOSED_POLICY);    
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);    
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);
        // test rule processing 
        bool response = encodingContract.transferDynamicArray(address(0x1234567), 99);
        assertTrue(response); 

    }

    function testRulesEngine_Unit_TestContractEncoding_AdditionalParamsEncoded_DynamicArrayRuleValue_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
       // encode additional datas with the calling contract call into rules engine 
        //deploy ExampleUserContractEncoding  
        encodingContract = new ExampleUserContractEncoding(); 
        encodingContract.setRulesEngineAddress(address(red)); 
        encodingContract.setCallingContractAdmin(callingContractAdmin); 
        address encodingContractAddress = address(encodingContract); 

        // create new uint array for transfer data 
        bytes[] memory array = new bytes[](5);
        array[0] = bytes("super");
        array[1] = bytes("superduper");
        array[2] = bytes("superduperduper");
        array[3] = bytes("superduperduperduper");
        array[4] = bytes("superduperduperduperduper");

        encodingContract.writeNewDynamicArrayData(array);

        // create rule that will handle additional params 
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Set up some effects.
        _setupEffectProcessor();

        /// Build the function signature to include additional pTypes to match the data being passed in
        PT[] memory pTypes = new PT[](4);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.STATIC_TYPE_ARRAY;
        pTypes[3] = PT.ADDR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = uint256(3); // uint length of array to test that rule retreives uint array length correctly 
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = PT.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = PT.DYNAMIC_TYPE_ARRAY;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional bytes32 param 

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);
        // Save the function signature
        uint256 functionSignatureId = RulesEngineComponentFacet(address(red)).createFunctionSignature(
            policyIds[0], 
            bytes4(bytes4(keccak256(bytes(functionSignatureArrayDynamic)))), 
            pTypes,
            functionSignatureArrayDynamic,
            ""    
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        // Save the Policy
        signatures.push(bytes4(keccak256(bytes(functionSignatureArrayDynamic))));
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], signatures, functionSignatureIds, ruleIds, PolicyType.CLOSED_POLICY);    
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);    
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);
        // test rule processing 
        bool response = encodingContract.transferDynamicArray(address(0x1234567), 99);
        assertFalse(response); 

    }

    function testPolicyExecutionOrder() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](5);
        // create 5 separate policies
        uint256 policy1 = _createBlankPolicy();
        uint256 policy2 = _createBlankPolicy();
        uint256 policy3 = _createBlankPolicy();
        uint256 policy4 = _createBlankPolicy();
        uint256 policy5 = _createBlankPolicy();
        policyIds[0] = policy1;
        policyIds[1] = policy2;
        policyIds[2] = policy3;
        policyIds[3] = policy4;
        policyIds[4] = policy5;
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        uint256[] memory appliedPolicyIds = RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(userContractAddress);
        // make sure that the policies applied were saved in the correct order
        assertEq(appliedPolicyIds.length, policyIds.length);
        assertEq(policyIds[0], appliedPolicyIds[0]);
        assertEq(policyIds[1], appliedPolicyIds[1]);
        assertEq(policyIds[2], appliedPolicyIds[2]);
        assertEq(policyIds[3], appliedPolicyIds[3]);
        assertEq(policyIds[4], appliedPolicyIds[4]);
        // reverse the policy order
        policyIds[0] = policy5;
        policyIds[1] = policy4;
        policyIds[2] = policy3;
        policyIds[3] = policy2;
        policyIds[4] = policy1;
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        appliedPolicyIds = RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(userContractAddress);
        // make sure that the policies applied were saved in the correct order
        assertEq(appliedPolicyIds.length, policyIds.length);
        assertEq(policyIds[0], appliedPolicyIds[0]);
        assertEq(policyIds[1], appliedPolicyIds[1]);
        assertEq(policyIds[2], appliedPolicyIds[2]);
        assertEq(policyIds[3], appliedPolicyIds[3]);
        assertEq(policyIds[4], appliedPolicyIds[4]);
        // change it to a single policy and ensure that the rest are removed.
        policyIds = new uint256[](1);
        policyIds[0] = 1;
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        appliedPolicyIds = RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(userContractAddress);
        assertEq(appliedPolicyIds.length, policyIds.length);
    }

    function testRulesEngine_Unit_PauseRuleRecreation() public ifDeploymentTestsEnabled resetsGlobalVariables {
        exampleERC20 = new ExampleERC20("Token Name", "SYMB");
        exampleERC20.mint(callingContractAdmin, 1_000_000 * ATTO);
        exampleERC20.setRulesEngineAddress(address(red));
        exampleERC20.setCallingContractAdmin(callingContractAdmin);
        
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](6);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.ADDR;
        pTypes[3] = PT.UINT;
        pTypes[4] = PT.UINT;
        pTypes[5] = PT.UINT;

        uint256 functionSignatureId = RulesEngineComponentFacet(address(red))
            .createFunctionSignature(
                policyIds[0],
                bytes4(bytes4(keccak256(bytes("transfer(address,uint256)")))), 
                pTypes,
                "transfer(address,uint256)",
                "address,uint256"   
            );
        // Save the Policy
        signatures.push(bytes4(keccak256(bytes("transfer(address,uint256)"))));
        functionSignatureIds.push(functionSignatureId);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            signatures,
            functionSignatureIds,
            blankRuleIds,
            PolicyType.CLOSED_POLICY
        );

        // Rule:uintTracker BlockTime > currentBlockTime -> revert -> transfer(address _to, uint256 amount) returns (bool)
        Rule memory rule;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.instructionSet = new uint256[](15);
        rule.instructionSet[0] = uint(LC.PLH);
        rule.instructionSet[1] = 0; //r0 tracker 1
        rule.instructionSet[2] = uint(LC.PLH);
        rule.instructionSet[3] = 2; //r1 blocktime 
        rule.instructionSet[4] = uint(LC.LT);
        rule.instructionSet[5] = 1; 
        rule.instructionSet[6] = 0; //r2 check that blocktime is less than tracker 1  
        rule.instructionSet[7] = uint(LC.PLH);
        rule.instructionSet[8] = 1; //r3 second tracker 
        rule.instructionSet[9] = uint(LC.GT);
        rule.instructionSet[10] = 1; // use register 1
        rule.instructionSet[11] = 3; //r4 check that blocktime is greater than second tracker 
        rule.instructionSet[12] = uint(LC.OR);
        rule.instructionSet[13] = 2;
        rule.instructionSet[14] = 4;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].trackerValue = true;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].trackerValue = true;
        rule.placeHolders[1].typeSpecificIndex = 2;
        rule.placeHolders[2].pType = PT.UINT;
        rule.placeHolders[2].typeSpecificIndex = 5;

        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = PT.UINT;
        tracker.trackerValue = abi.encode(1000000000);
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName");

        //build second tracker
        Trackers memory tracker2;
        /// build the members of the struct:
        tracker2.pType = PT.UINT;
        tracker2.trackerValue = abi.encode(2000000000);
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker2, "trName");

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
    
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(exampleERC20), policyIds);


        vm.warp(1000000001);
        vm.expectRevert(); 
        exampleERC20.transfer(address(0x7654321), 3);

        //warp out of pause window 
        vm.warp(2000000001);

        bool response = exampleERC20.transfer(address(0x7654321), 7);
        assertTrue(response);

    }


}
