/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "test/utils/ExampleUserContractEncoding.sol";
import "src/example/ExampleUserContract.sol";
import "src/example/ExampleUserOwnableContract.sol";
import "src/example/ExampleUserAccessControl.sol";
import "src/engine/facets/RulesEngineComponentFacet.sol";
import "src/example/ExampleERC20.sol";
import "src/engine/facets/RulesEngineProcessorFacet.sol";

abstract contract RulesEngineUnitTestsCommon is RulesEngineCommon {

    ExampleUserContract userContract;
    ExampleUserContract newUserContract;
    ExampleUserContractExtraParams userContract2;
    ExampleUserContractEncoding encodingContract; 
    ExampleERC20 exampleERC20; 

    bytes internal testArgs;

    /*uint8 constant FLAG_FOREIGN_CALL = 0x01;
    uint8 constant FLAG_TRACKER_VALUE = 0x02;
    uint8 constant SHIFT_GLOBAL_VAR = 2;
    uint8 constant MASK_GLOBAL_VAR = 0x1C;*/

    // Global variable type constants
    uint8 constant GLOBAL_NONE = 0;
    uint8 constant GLOBAL_MSG_SENDER = 1;
    uint8 constant GLOBAL_BLOCK_TIMESTAMP = 2;
    uint8 constant GLOBAL_MSG_DATA = 3;
    uint8 constant GLOBAL_BLOCK_NUMBER = 4;
    uint8 constant GLOBAL_TX_ORIGIN = 5;
    
    /// TestRulesEngine: 
    // Test attempt to add a policy with no calling functions saved.
    function testRulesEngine_Unit_UpdatePolicy_InvalidRule()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        (uint256 policyId, uint256 ruleId) = setUpRuleSimple();
        ruleId; 
        // Save the calling Function
        uint256 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = 1;
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        vm.expectRevert("Invalid Rule");
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            callingFunctionIds,
            ruleIds,
            PolicyType.CLOSED_POLICY
        );
    }

    // Test attempt to add a policy with no callingFunctions saved.
    function testRulesEngine_Unit_UpdatePolicy_InvalidCallingFunction()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // setUpRuleSimple helper not used as test does not set the calling Function ID intentionally
        uint256 policyId = _createBlankPolicy();
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction))));
        callingFunctionIds.push(1);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = 1;
        vm.expectRevert("Invalid Signature");
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            callingFunctionIds,
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
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        assertGt(
            RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyId,
                callingFunctions,
                callingFunctionIds,
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
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
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
        setupRuleWithForeignCall(4, EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), transferValue);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
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
        setupRuleWithForeignCall(ruleValue, EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), transferValue);
        vm.startPrank(address(userContract));
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
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

    function testRulesEngine_Unit_createRule_ForeignCall_TrackerValuesUsed_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithForeignCallSquaringReferencedTrackerVals(8, EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 3);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);
    }

        function testRulesEngine_Unit_createRule_ForeignCall_TrackerValuesUsed_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithForeignCallSquaringReferencedTrackerVals(0, EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 3);
        vm.startPrank(address(userContract));
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_createRule_ForeignCall_ForeignCallReferenced_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithForeignCallWithSquaredFCValues(EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 3);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);
    }


    function testRulesEngine_Unit_createRule_ForeignCall_ForeignCallReferenced_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithForeignCallWithSquaredFCValues(EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 0);
        vm.startPrank(address(userContract));
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_CheckPolicies_Explicit_StringComparison_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithStringComparison();
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction2))), address(0x7654321), "Bad Info");
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_CheckPolicies_Explicit_StringComparison_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithStringComparison();
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction2))), address(0x7654321), "test");
        vm.startPrank(address(userContract));
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 0);
    }

    function testRulesEngine_Unit_RetrieveRawStringFromInstructionSet()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 ruleId = setupRuleWithStringComparison();
        StringVerificationStruct memory retVal = RulesEngineInitialFacet(address(red)).retrieveRawStringFromInstructionSet(1, ruleId, 3);
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
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction2))), address(0x1234567), "test");
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_CheckPolicies_Explicit_AddressComparison_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithAddressComparison();
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction2))), address(0x7654321), "test");
        vm.startPrank(address(userContract));
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 0);
    }

    function testRulesEngine_Unit_RetrieveRawAddressFromInstructionSet()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 ruleId = setupRuleWithAddressComparison();
        AddressVerificationStruct memory retVal = RulesEngineInitialFacet(address(red)).retrieveRawAddressFromInstructionSet(1, ruleId, 3);
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
        setupRuleWithForeignCall(4, EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithForeignCallEffect()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithForeignCall(4, EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.startPrank(address(userContract));
        // The Foreign call will be placed during the effect for the single rule in this policy.
        // The value being set in the foreign contract is then polled to verify that it has been udpated.
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
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
        tracker.pType = ParamTypes.ADDR;
        tracker.set = true;
        tracker.trackerValue = abi.encode(0xD00D);
        setupRuleWithTrackerAddr(policyId, tracker);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5, address(0x7654321));
        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the third parameter
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
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
        tracker.pType = ParamTypes.BOOL;
        tracker.set = true;
        tracker.trackerValue = abi.encode(bool(false));
        setupRuleWithTrackerBool(policyId, tracker);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5, bool(true));
        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the third parameter
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
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
        tracker.pType = ParamTypes.UINT;
        tracker.set = true;
        tracker.trackerValue = abi.encode(uint256(13));
        setupRuleWithTrackerUint(policyId, tracker);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5, 99);
        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the third parameter
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
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
        tracker.pType = ParamTypes.BYTES;
        tracker.set = true;
        tracker.trackerValue = bytes("initial");
        setupRuleWithTracker2(policyId, tracker);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5, bytes("post"));
        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the third parameter
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
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
        tracker.pType = ParamTypes.BYTES;
        tracker.set = true;
        tracker.trackerValue = "initial";
        setupRuleWithTracker2(policyId, tracker);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5, "post");
        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the third parameter
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory comparison = abi.encode("post");
        assertEq(tracker.trackerValue, comparison);
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithForeignCallNegative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithForeignCall(4, EffectTypes.REVERT, false);
        vm.startPrank(address(userContract));
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 3);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
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
        _setupRuleWithPosEventParams(eventParam, ParamTypes.UINT);
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
        _setupRuleWithPosEventParams(eventParam, ParamTypes.STR);
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
        _setupRuleWithPosEventParams(eventParam, ParamTypes.ADDR);
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
        _setupRuleWithPosEventParams(eventParam, ParamTypes.BOOL);
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
        _setupRuleWithPosEventParams(eventParam, ParamTypes.BYTES);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, bytes32("Bytes32 Test"));
        userContract.transfer(address(0x7654321), 5);
    }

    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event_DynamicParams_Uint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        _setupRuleWithPosEventDynamicParamsFromCallingFunctionParams(ParamTypes.UINT);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, 100);
        userContract.transfer(address(0x7654321), 100);
    }


    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event_DynamicParams_Address()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        _setupRuleWithPosEventDynamicParamsFromCallingFunctionParams(ParamTypes.ADDR);
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
        vm.stopPrank();
        vm.startPrank(policyAdmin);
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

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), transferValue);

        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_createRule_Tracker_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        setupRuleWithTracker(15);
        transferValue = 10;

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), transferValue);
        vm.startPrank(address(userContract));
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
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
        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[1].typeSpecificIndex = 1;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyIds[0], 0, rule);

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
        _addCallingFunctionToPolicy(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.PLH, 1, LogicalOp.GT, 0, 1
        rule.instructionSet = _createInstructionSet(0, 1);

        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[1].typeSpecificIndex = 1;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyIds[0], 0, rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        vm.expectRevert("Tracker referenced in rule not set");
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
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
        tracker.pType = ParamTypes.ADDR;

        RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");
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
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, newPolicyAdmin);
        assertFalse(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = ParamTypes.ADDR;

        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");
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
        tracker.pType = ParamTypes.ADDR;

        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");

        tracker.trackerValue = abi.encode(address(userContractAddress));
        RulesEngineComponentFacet(address(red)).updateTracker(policyID, trackerId, tracker);
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
        tracker.pType = ParamTypes.ADDR;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, newPolicyAdmin);
        assertFalse(hasAdminRole);
        tracker.trackerValue = abi.encode(address(userContractAddress));
        tracker.pType = ParamTypes.ADDR;

        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).updateTracker(policyID, trackerId, tracker);
    }

    function testRulesEngine_Unit_createCallingFunction_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        uint256 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        assertEq(callingFunctionId, 1);
        CallingFunctionStorageSet memory sig = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId);
        assertEq(sig.set, true);
        assertEq(sig.signature, bytes4(keccak256(bytes(callingFunction))));
        assertEq(uint8(sig.parameterTypes[0]), uint8(ParamTypes.ADDR));
        assertEq(uint8(sig.parameterTypes[1]), uint8(ParamTypes.UINT));
    }

    function testRulesEngine_Unit_createCallingFunction_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        vm.startPrank(newPolicyAdmin);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).createCallingFunction(policyId, 
            bytes4(keccak256(bytes(callingFunction))), 
            pTypes,
            callingFunction,
            "");
    }

    function testRulesEngine_Unit_updateCallingFunction_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        uint256 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        ParamTypes[] memory pTypes2 = new ParamTypes[](4);
        pTypes2[0] = ParamTypes.ADDR;
        pTypes2[1] = ParamTypes.UINT;
        pTypes2[2] = ParamTypes.ADDR;
        pTypes2[3] = ParamTypes.UINT;
        RulesEngineComponentFacet(address(red)).updateCallingFunction(policyId, callingFunctionId, bytes4(keccak256(bytes(callingFunction))), pTypes2);
        CallingFunctionStorageSet memory sig = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId);
        assertEq(sig.set, true);
        assertEq(sig.signature, bytes4(keccak256(bytes(callingFunction))));
        for (uint256 i = 0; i < pTypes2.length; i++) {
            assertEq(uint8(sig.parameterTypes[i]), uint8(pTypes2[i]));
        }
    }

    function testRulesEngine_Unit_deleteCallingFunction_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        uint256 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        assertEq(callingFunctionId, 1);
        CallingFunctionStorageSet memory matchingCallingFunction = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId);
        assertEq(matchingCallingFunction.signature, bytes4(keccak256(bytes(callingFunction))));

        RulesEngineComponentFacet(address(red)).deleteCallingFunction(policyId, callingFunctionId); 
        CallingFunctionStorageSet memory cf = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId);
        assertEq(cf.set, false);
        assertEq(cf.signature, bytes4(""));
    }

    function testRulesEngine_Unit_deleteCallingFunctionMultiple_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory _callingFunctions;
        uint256[] memory _callingFunctionIds;
        uint256[][] memory _ruleIds;
        // This test does not utilize helper _addCallingFunctionToPolicy(policyId) because it needs to individually set the function callingFunctions for deletion 
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId, 
            bytes4(keccak256(bytes(callingFunction))), 
            pTypes,
            callingFunction,
            ""
        );
        assertEq(callingFunctionId, 1);
        uint256 callingFunctionId2 = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId, 
            bytes4(keccak256(bytes(callingFunction2))), 
            pTypes,
            callingFunction2,
            ""
        );
        assertEq(callingFunctionId2, 2);
        CallingFunctionStorageSet memory matchingCallingFunction = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId);
        assertEq(matchingCallingFunction.signature, bytes4(keccak256(bytes(callingFunction))));

        CallingFunctionStorageSet memory matchingCallingFunction2 = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId2);
        assertEq(matchingCallingFunction2.signature, bytes4(keccak256(bytes(callingFunction2))));

        RulesEngineComponentFacet(address(red)).deleteCallingFunction(policyId, callingFunctionId); 
        CallingFunctionStorageSet memory cf = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId);
        assertEq(cf.set, false);
        assertEq(cf.signature, bytes4(""));

        CallingFunctionStorageSet memory matchingCallingFunction3 = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId2);
        assertEq(matchingCallingFunction3.signature, bytes4(keccak256(bytes(callingFunction2))));

        //check that policy callingFunctions array is resized to 1 
        (_callingFunctions, _callingFunctionIds, _ruleIds) = RulesEnginePolicyFacet(address(red)).getPolicy(policyId);
        assertEq(_callingFunctions.length, 1);
        assertEq(_callingFunctions[0], bytes4(keccak256(bytes(callingFunction2))));

    }

    function testRulesEngine_Unit_deleteCallingFunction_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        uint256 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        assertEq(callingFunctionId, 1);

        vm.startPrank(newPolicyAdmin);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).deleteCallingFunction(policyId, callingFunctionId); 
    }

    function testRulesEngine_Unit_deleteCallingFunctionWithRuleCheck_Positive()
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
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        RulesEngineComponentFacet(address(red)).getCallingFunction(1, 0);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEngineComponentFacet(address(red)).deleteCallingFunction(1, 1); 
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
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder 
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyId, 0, rule);

        RulesEngineRuleFacet(address(red)).deleteRule(policyId, ruleId); 
        RuleStorageSet memory sig = RulesEngineRuleFacet(address(red)).getRule(policyId, ruleId);
        assertEq(sig.set, false);
    }

    function testRulesEngine_Unit_deleteRule_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder 
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyId, 0, rule);

        vm.startPrank(newPolicyAdmin);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineRuleFacet(address(red)).deleteRule(policyId, ruleId); 
    }

    function testRulesEngine_Unit_updateCallingFunction_Negative_NewParameterTypesNotSameLength()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        uint256 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        ParamTypes[] memory pTypes2 = new ParamTypes[](1);
        pTypes2[0] = ParamTypes.ADDR;
        vm.expectRevert("New parameter types must be of greater or equal length to the original");
        RulesEngineComponentFacet(address(red)).updateCallingFunction(policyId, callingFunctionId, bytes4(keccak256(bytes(callingFunction))), pTypes2);
    }

    function testRulesEngine_Unit_updateCallingFunction_Negative_NewParameterTypesNotSameType()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        uint256 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        ParamTypes[] memory pTypes2 = new ParamTypes[](2);
        pTypes2[0] = ParamTypes.UINT;
        pTypes2[1] = ParamTypes.UINT;
        vm.expectRevert("New parameter types must be of the same type as the original");
        RulesEngineComponentFacet(address(red)).updateCallingFunction(policyId, callingFunctionId, bytes4(keccak256(bytes(callingFunction))), pTypes2);
    }

    function testRulesEngine_Unit_updateCallingFunction_Negative_NewCallingFunctionNotSame()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        uint256 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        vm.expectRevert("Delete calling function before updating to a new one");
        RulesEngineComponentFacet(address(red)).updateCallingFunction(policyId, callingFunctionId, bytes4(keccak256(bytes(callingFunction2))), pTypes);
    }

    function testRulesEngine_Unit_updateCallingFunction_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        uint256 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        vm.startPrank(newPolicyAdmin);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).updateCallingFunction(policyId, callingFunctionId, bytes4(keccak256(bytes(callingFunction2))), pTypes);
    }

    function testRulesEngine_Unit_updateCallingFunctionWithRuleCheck_Positive()
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
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        CallingFunctionStorageSet memory sig = RulesEngineComponentFacet(address(red)).getCallingFunction(1, 1);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEngineComponentFacet(address(red)).updateCallingFunction(1, 1, bytes4(keccak256(bytes(callingFunction))), pTypes);
        assertEq(sig.set, true);
        // ensure orignal contract rule check works 
        bool ruleCheck = userContract.transfer(address(0x7654321), 47);
        assertTrue(ruleCheck);
        // test new contract rule check works 
        bool secondRuleCheck = userContract.transfer(address(0x7654321), 47);
        assertTrue(secondRuleCheck);
    }

    function testRulesEngine_Unit_updateCallingFunctionWithRuleCheck_Negative()
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
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        CallingFunctionStorageSet memory sig = RulesEngineComponentFacet(address(red)).getCallingFunction(1, 1);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEngineComponentFacet(address(red)).updateCallingFunction(1, 1, bytes4(keccak256(bytes(callingFunction))), pTypes);
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
        tracker.pType = ParamTypes.ADDR;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        RulesEngineComponentFacet(address(red)).deleteTracker(policyID, trackerId);

        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyID, trackerId);
        assertEq(tracker.set, false);
        assertEq(uint8(tracker.pType), uint8(ParamTypes.ADDR));
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
        tracker.pType = ParamTypes.ADDR;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trkName");
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, newPolicyAdmin);
        assertFalse(hasAdminRole);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).deleteTracker(policyID, trackerId);
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
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, newPolicyAdmin);
        assertFalse(hasAdminRole);

        vm.expectRevert("Not Authorized To Policy");
        _setUpForeignCallSimple(policyID);
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
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        uint256 foreignCallId;
        ForeignCall memory fc;
        (fc, foreignCallId) = _setUpForeignCallSimpleReturnID(policyID);

        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, newPolicyAdmin);
        assertFalse(hasAdminRole);
        fc.foreignCallAddress = address(userContractAddress);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).updateForeignCall(policyID, foreignCallId, fc);
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
        assertEq(uint8(fc2.returnType), uint8(ParamTypes.ADDR));
        assertEq(fc2.foreignCallIndex, 0);
    }

    function testRulesEngine_unit_adminRoles_DeleteForeignCall_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        uint256 foreignCallId;
        ForeignCall memory fc;
        (fc, foreignCallId) = _setUpForeignCallSimpleReturnID(policyID);
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, newPolicyAdmin);
        assertFalse(hasAdminRole);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).deleteForeignCall(policyID, foreignCallId);
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
            tracker.pType = ParamTypes.UINT;
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

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);
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
        // RulesEngineRuleFacet(address(red)).updateRule(policyId, 0, rule);
    }

    function testRulesEngine_Unit_ApplyPolicy_ClosedPolicy_NotSubscriber() public ifDeploymentTestsEnabled endWithStopPrank {
        // TODO add back after admin roles are returned 
        // uint256 policyId = _createBlankPolicy();
        // bytes4[] memory blankcallingFunctions = new bytes4[](0);
        // uint256[] memory blankcallingFunctionIds = new uint256[](0);
        // uint256[][] memory blankRuleIds = new uint256[][](0);
        // RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankcallingFunctions, blankcallingFunctionIds, blankRuleIds, PolicyType.CLOSED_POLICY);
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
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankcallingFunctions, blankcallingFunctionIds, blankRuleIds, PolicyType.OPEN_POLICY);
        ExampleUserContract potentialSubscriber = new ExampleUserContract();
        potentialSubscriber.setRulesEngineAddress(address(red));
        potentialSubscriber.setCallingContractAdmin(callingContractAdmin);
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(potentialSubscriber), policyIds);
        assertEq(RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(address(potentialSubscriber)).length, 1);
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankcallingFunctions, blankcallingFunctionIds, blankRuleIds, PolicyType.CLOSED_POLICY);
        assertEq(RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(address(potentialSubscriber)).length, 0);
    }

    function testRulesEngine_Unit_ClosePolicy_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankcallingFunctions, blankcallingFunctionIds, blankRuleIds, PolicyType.OPEN_POLICY);
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

    function testRulesEngine_Unit_DisablePolicy_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        assertFalse(RulesEnginePolicyFacet(address(red)).isDisabledPolicy(policyId));
        RulesEnginePolicyFacet(address(red)).disablePolicy(policyId);
        assertTrue(RulesEnginePolicyFacet(address(red)).isDisabledPolicy(policyId));
    }

    function testRulesEngine_Unit_ApplyPolicy_OpenPolicy_NotSubscriber() public ifDeploymentTestsEnabled endWithStopPrank {
        
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankcallingFunctions, blankcallingFunctionIds, blankRuleIds, PolicyType.OPEN_POLICY);
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
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankcallingFunctions, blankcallingFunctionIds, blankRuleIds, PolicyType.CLOSED_POLICY);
        RulesEngineComponentFacet(address(red)).addClosedPolicySubscriber(policyId, callingContractAdmin);
        assertTrue(RulesEngineComponentFacet(address(red)).isClosedPolicySubscriber(policyId, callingContractAdmin));
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(userContract), policyIds);
    }

    function testRulesEngine_Unit_UpdatePolicy_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankcallingFunctions, blankcallingFunctionIds, blankRuleIds, PolicyType.CLOSED_POLICY);
    }

    function testRulesEngine_Unit_DeletePolicy_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEnginePolicyFacet(address(red)).deletePolicy(policyId);
    }

    function testRulesEngine_Unit_DisablePolicy_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEnginePolicyFacet(address(red)).disablePolicy(policyId);
    }

    function testRulesEngine_Unit_ApplyPolicy_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankcallingFunctions, blankcallingFunctionIds, blankRuleIds, PolicyType.OPEN_POLICY);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

        function testRulesEngine_Unit_UnapplyPolicy_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankSignatures, blankFunctionSignatureIds, blankRuleIds, PolicyType.OPEN_POLICY);
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        RulesEnginePolicyFacet(address(red)).unapplyPolicy(address(userContract), policyIds);
        assertEq(RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(userContractAddress).length,0);
    }

    function testRulesEngine_Unit_UnapplyPolicyMultiple_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](2);
        
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankSignatures, blankFunctionSignatureIds, blankRuleIds, PolicyType.OPEN_POLICY);
        
        uint256 policyId2 = _createBlankPolicy();
        bytes4[] memory blankSignatures2 = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds2 = new uint256[](0);
        uint256[][] memory blankRuleIds2 = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId2, blankSignatures2, blankFunctionSignatureIds2, blankRuleIds2, PolicyType.OPEN_POLICY);
        policyIds[0] = policyId;
        policyIds[1] = policyId2;
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        RulesEnginePolicyFacet(address(red)).unapplyPolicy(address(userContract), policyIds);
        assertEq(RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(userContractAddress).length,0);
    }

    function testRulesEngine_Unit_UnapplyPolicy_Multiple_OnlyRemoveOne_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankSignatures, blankFunctionSignatureIds, blankRuleIds, PolicyType.OPEN_POLICY);
        uint256[] memory policyIds = new uint256[](2);
        uint256 policyId2 = _createBlankPolicy();
        bytes4[] memory blankSignatures2 = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds2 = new uint256[](0);
        uint256[][] memory blankRuleIds2 = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId2, blankSignatures2, blankFunctionSignatureIds2, blankRuleIds2, PolicyType.OPEN_POLICY);
        policyIds[0] = policyId;
        policyIds[1] = policyId2;
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        policyIds = new uint256[](1);
        policyIds[0] = policyId;
        RulesEnginePolicyFacet(address(red)).unapplyPolicy(address(userContract), policyIds);
        policyIds = RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(userContractAddress);
        assertEq(policyIds.length,1);
        assertEq(policyIds[0], policyId2);
    }

    function testRulesEngine_Unit_UnapplyPolicy_Negative_NotCallingContractAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankSignatures, blankFunctionSignatureIds, blankRuleIds, PolicyType.CLOSED_POLICY);
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        vm.startPrank(policyAdmin);
        vm.expectRevert("Not Authorized Admin");
        RulesEnginePolicyFacet(address(red)).unapplyPolicy(address(userContract), policyIds);
    }

    function testRulesEngine_Unit_CreateForeignCall_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankcallingFunctions, blankcallingFunctionIds, blankRuleIds, PolicyType.OPEN_POLICY);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);

        ForeignCall memory fc;
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256)");
    }


    function testRulesEngine_Unit_DeleteForeignCall_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {

        // set up the ERC20
        uint256 policyId = _setup_checkRule_ForeignCall_Positive(ruleValue);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
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
        tracker.pType = ParamTypes.ADDR;
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
        tracker.pType = ParamTypes.ADDR;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyID);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).deleteTracker(policyID, trackerId);
    }

    function testRulesEngine_Unit_createCallingFunction_Negative_CementedPolicy()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyID = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyID);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyID, 
            bytes4(keccak256(bytes(callingFunction))), 
            pTypes,
            callingFunction,
            "");
    }

    function testRulesEngine_Unit_updateCallingFunction_Negative_CementedPolicy()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create rule and set rule to user contract 
        (uint256 policyID, uint256 ruleID) = setUpRuleSimple();
        ruleID;
        RulesEngineComponentFacet(address(red)).getCallingFunction(1, 1);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyID);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).updateCallingFunction(1, 1, bytes4(keccak256(bytes(callingFunction))), new ParamTypes[](3));
    }

    function testRulesEngine_Unit_deleteCallingFunction_Negative_CementedPolicy()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        uint256 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        assertEq(callingFunctionId, 1);
        CallingFunctionStorageSet memory matchingCallingFunction = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId);
        assertEq(matchingCallingFunction.signature, bytes4(keccak256(bytes(callingFunction))));

        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).deleteCallingFunction(policyId, callingFunctionId); 
    }

    function testRulesEngine_Unit_updateRule_Negative_CementedPolicy()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;

        // Instruction set: LogicalOp.PLH, 0, LogicalOp.PLH, 1, LogicalOp.GT, 0, 1
        rule.instructionSet = _createInstructionSet(0, 1);

        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[1].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineRuleFacet(address(red)).updateRule(policyId, ruleId, rule);
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
        RulesEngineRuleFacet(address(red)).createRule(policyId, rule);
    }

    function testRulesEngine_Unit_RemoveClosedPolicy_Subscriber_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankcallingFunctions, blankcallingFunctionIds, blankRuleIds, PolicyType.CLOSED_POLICY);
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
        uint256 policyId = 1;
        vm.expectEmit(true, false, false, false);
        emit PolicyCreated(policyId); 
        emit PolicyAdminRoleGranted(policyAdmin, policyId);
        RulesEnginePolicyFacet(address(red)).createPolicy(PolicyType.CLOSED_POLICY);
    }

    function testRulesEngine_Unit_UpdatePolicy_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        (uint256 policyId, uint256 ruleId) = setUpRuleSimple();
        ruleId;
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        vm.expectEmit(true, false, false, false);
        emit PolicyUpdated(policyId); 
        RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyId,
                callingFunctions,
                callingFunctionIds,
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
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankcallingFunctions, blankcallingFunctionIds, blankRuleIds, PolicyType.OPEN_POLICY);

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

    function testRulesEngine_Unit_DisablePolicy_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        vm.expectEmit(true, false, false, false);
        emit PolicyDisabled(policyId); 
        RulesEnginePolicyFacet(address(red)).disablePolicy(policyId);
    }

    function testRulesEngine_Unit_ClosedPolicySubscriber_AddRemove_Events() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, blankcallingFunctions, blankcallingFunctionIds, blankRuleIds, PolicyType.CLOSED_POLICY);
        vm.expectEmit(true, false, false, false);
        emit PolicySubsciberAdded(policyId, callingContractAdmin);
        RulesEngineComponentFacet(address(red)).addClosedPolicySubscriber(policyId, callingContractAdmin);

        vm.expectEmit(true, false, false, false);
        emit PolicySubsciberRemoved(policyId, callingContractAdmin);
        RulesEngineComponentFacet(address(red)).removeClosedPolicySubscriber(policyId, callingContractAdmin);
    }

    function testRulesEngine_Unit_createCallingFunction_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        uint256 callingFunctionId = 1;
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        vm.expectEmit(true, false, false, false);
        emit CallingFunctionCreated(policyId, callingFunctionId);
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId, 
            bytes4(bytes4(keccak256(bytes(callingFunction)))), 
            pTypes,
            callingFunction,
            ""
        );
    }

    function testRulesEngine_Unit_updateCallingFunction_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        uint256 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        ParamTypes[] memory pTypes2 = new ParamTypes[](4);
        pTypes2[0] = ParamTypes.ADDR;
        pTypes2[1] = ParamTypes.UINT;
        pTypes2[2] = ParamTypes.ADDR;
        pTypes2[3] = ParamTypes.UINT;
        vm.expectEmit(true, false, false, false);
        emit CallingFunctionUpdated(policyId, callingFunctionId);
        RulesEngineComponentFacet(address(red)).updateCallingFunction(policyId, callingFunctionId, bytes4(keccak256(bytes(callingFunction))), pTypes2);
    }

    function testRulesEngine_Unit_deleteCallingFunction_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        uint256 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        vm.expectEmit(true, false, false, false);
        emit CallingFunctionDeleted(policyId, callingFunctionId);
        RulesEngineComponentFacet(address(red)).deleteCallingFunction(policyId, callingFunctionId); 

    }

    function testRulesEngine_Unit_deleteRule_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder 
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyId, 0, rule);
        vm.expectEmit(true, false, false, false);
        emit RuleDeleted(policyId, ruleId);
        RulesEngineRuleFacet(address(red)).deleteRule(policyId, ruleId); 

    }

    function testRulesEngine_unit_CreateTracker_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        uint256 trackerId = 1;
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = ParamTypes.ADDR;
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
        tracker.pType = ParamTypes.ADDR;
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
        tracker.pType = ParamTypes.ADDR;
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
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.UINT;
        fc.typeSpecificIndices = new int8[](1);
        fc.typeSpecificIndices[0] = 1;
        fc.returnType = ParamTypes.UINT;
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
        RulesEngineRuleFacet(address(red)).createRule(policyId, rule);
    }

    function testRulesEngine_Unit_UpdateRule_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule);
        vm.expectEmit(true, false, false, false);
        emit RuleUpdated(policyId, ruleId);
        RulesEngineRuleFacet(address(red)).updateRule(policyId, 0, rule);
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
        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.UINT;
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red))
            .createCallingFunction(
                policyIds[0], 
                bytes4(bytes4(keccak256(bytes(callingFunction)))), 
                pTypes,
                callingFunction,
                ""
            );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction))));
        callingFunctionIds.push(callingFunctionId);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            callingFunctionIds,
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
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 1; //0
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 100; // 1
        rule.instructionSet[4] = uint(LogicalOp.GT);
        rule.instructionSet[5] = 1;
        rule.instructionSet[6] = 0; // 2   
        rule.instructionSet[7] = uint(LogicalOp.PLH);
        rule.instructionSet[8] = 2; // 3
        rule.instructionSet[9] = uint(LogicalOp.NUM);
        rule.instructionSet[10] = 75; // 4 
        rule.instructionSet[11] = uint(LogicalOp.GT);
        rule.instructionSet[12] = 4;
        rule.instructionSet[13] = 3; // 5 

    
        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = ParamTypes.UINT;
        rule.placeHolders[2].typeSpecificIndex = 2; // Additional uint 


        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);

        uint256 ruleID = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule);
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
        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        pTypes[3] = ParamTypes.ADDR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(uint160(address(0x1234567)));
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.rawData.argumentTypes = new ParamTypes[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = ParamTypes.ADDR;
        rule.rawData.dataValues[0] = abi.encode(0x1234567);
        rule.rawData.instructionSetIndex[0] = 3;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = ParamTypes.ADDR;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional address param 

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule);
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0], 
            bytes4(bytes4(keccak256(bytes(callingFunction3)))), 
            pTypes,
            callingFunction3,
            ""    
        );


        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction3))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], callingFunctions, callingFunctionIds, ruleIds, PolicyType.CLOSED_POLICY);    
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
        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        pTypes[3] = ParamTypes.ADDR;

        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.ADDR;
        int8[] memory typeSpecificIndices = new int8[](1);
        typeSpecificIndices[0] = 2; // set the placeholder index to retrieve value 
        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract2);
        fc.signature = bytes4(keccak256(bytes("getNaughty(address)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 1;
        uint256 foreignCallId = RulesEngineComponentFacet(address(red)).createForeignCall(policyIds[0], fc, "getNaughty(address)");

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.rawData.argumentTypes = new ParamTypes[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = ParamTypes.ADDR;
        rule.rawData.dataValues[0] = abi.encode(0x1234567);
        rule.rawData.instructionSetIndex[0] = 3;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = ParamTypes.ADDR;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional address param 
        rule.placeHolders[2].flags = FLAG_FOREIGN_CALL; 
        rule.placeHolders[2].typeSpecificIndex = uint128(foreignCallId);

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule);
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0], 
            bytes4(bytes4(keccak256(bytes(callingFunction3)))), 
            pTypes,
            callingFunction3,
            ""
        );

        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction3))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], callingFunctions, callingFunctionIds, ruleIds, PolicyType.CLOSED_POLICY);    
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
        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.BOOL;
        pTypes[3] = ParamTypes.ADDR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(1);
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = ParamTypes.BOOL;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional bytes32 param 

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule);
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0], 
            bytes4(bytes4(keccak256(bytes(callingFunctionBool)))), 
            pTypes,
            callingFunctionBool,
            ""
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunctionBool))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], callingFunctions, callingFunctionIds, ruleIds, PolicyType.CLOSED_POLICY);    
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
        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.BYTES;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(keccak256(abi.encode(TEST)));
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = ParamTypes.BYTES;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional bytes32 param 

        rule.rawData.argumentTypes = new ParamTypes[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = ParamTypes.BYTES;
        rule.rawData.dataValues[0] = abi.encode(TEST);
        rule.rawData.instructionSetIndex[0] = 3;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule);
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0], 
            bytes4(bytes4(keccak256(bytes(callingFunctionWithBytes)))), 
            pTypes,
            callingFunctionWithBytes,
            ""
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunctionWithBytes))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], callingFunctions, callingFunctionIds, ruleIds, PolicyType.CLOSED_POLICY);    
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);    
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);
        // test rule processing 
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunctionWithBytes))), address(0x7654321), 99, TEST);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

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
        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.BYTES;
        pTypes[3] = ParamTypes.ADDR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(keccak256(abi.encode(TEST)));
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = ParamTypes.BYTES;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional bytes32 param 

        rule.rawData.argumentTypes = new ParamTypes[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = ParamTypes.BYTES;
        rule.rawData.dataValues[0] = abi.encode(TEST);
        rule.rawData.instructionSetIndex[0] = 3;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule);
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0], 
            bytes4(bytes4(keccak256(bytes(callingFunctionBytes)))), 
            pTypes,
            callingFunctionBytes,
            ""
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunctionBytes))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], callingFunctions, callingFunctionIds, ruleIds, PolicyType.CLOSED_POLICY);    
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
        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.STR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(keccak256(abi.encode(testString)));
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = ParamTypes.STR;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional string param 

        rule.rawData.argumentTypes = new ParamTypes[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = ParamTypes.STR;
        rule.rawData.dataValues[0] = abi.encode(testString);
        rule.rawData.instructionSetIndex[0] = 3;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule);
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0], 
            bytes4(bytes4(keccak256(bytes(callingFunctionWithString)))), 
            pTypes,
            callingFunctionWithString,
            ""
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunctionWithString))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], callingFunctions, callingFunctionIds, ruleIds, PolicyType.CLOSED_POLICY);    
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
        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.STATIC_TYPE_ARRAY;
        pTypes[3] = ParamTypes.ADDR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(3); // uint length of array to test that rule retreives uint array length correctly 
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = ParamTypes.STATIC_TYPE_ARRAY;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional bytes32 param 

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule);
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0], 
            bytes4(bytes4(keccak256(bytes(callingFunctionArrayStatic)))), 
            pTypes,
            callingFunctionArrayStatic,
            ""  
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunctionArrayStatic))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], callingFunctions, callingFunctionIds, ruleIds, PolicyType.CLOSED_POLICY);    
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

        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.STATIC_TYPE_ARRAY;
        pTypes[3] = ParamTypes.ADDR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(5); // uint length of array to test that rule retreives uint array length correctly 
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = ParamTypes.DYNAMIC_TYPE_ARRAY;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional bytes32 param 

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule);
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0], 
            bytes4(bytes4(keccak256(bytes(callingFunctionArrayDynamic)))), 
            pTypes,
            callingFunctionArrayDynamic,
            ""    
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunctionArrayDynamic))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], callingFunctions, callingFunctionIds, ruleIds, PolicyType.CLOSED_POLICY);    
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

        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.STATIC_TYPE_ARRAY;
        pTypes[3] = ParamTypes.ADDR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(3); // uint length of array to test that rule retreives uint array length correctly 
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR; 
        rule.placeHolders[0].typeSpecificIndex = 0; // to address 
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount 
        rule.placeHolders[2].pType = ParamTypes.DYNAMIC_TYPE_ARRAY;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional bytes32 param 

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule);
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0], 
            bytes4(bytes4(keccak256(bytes(callingFunctionArrayDynamic)))), 
            pTypes,
            callingFunctionArrayDynamic,
            ""    
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunctionArrayDynamic))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], callingFunctions, callingFunctionIds, ruleIds, PolicyType.CLOSED_POLICY);    
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

        ParamTypes[] memory pTypes = new ParamTypes[](6);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        pTypes[3] = ParamTypes.UINT;
        pTypes[4] = ParamTypes.UINT;
        pTypes[5] = ParamTypes.UINT;

        uint256 callingFunctionId = RulesEngineComponentFacet(address(red))
            .createCallingFunction(
                policyIds[0],
                bytes4(bytes4(keccak256(bytes("transfer(address,uint256)")))), 
                pTypes,
                "transfer(address,uint256)",
                "address,uint256"   
            );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes("transfer(address,uint256)"))));
        callingFunctionIds.push(callingFunctionId);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            callingFunctionIds,
            blankRuleIds,
            PolicyType.CLOSED_POLICY
        );

        // Rule:uintTracker BlockTime > currentBlockTime -> revert -> transfer(address _to, uint256 amount) returns (bool)
        Rule memory rule;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.instructionSet = new uint256[](15);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0; //r0 tracker 1
        rule.instructionSet[2] = uint(LogicalOp.PLH);
        rule.instructionSet[3] = 2; //r1 blocktime 
        rule.instructionSet[4] = uint(LogicalOp.LT);
        rule.instructionSet[5] = 1; 
        rule.instructionSet[6] = 0; //r2 check that blocktime is less than tracker 1  
        rule.instructionSet[7] = uint(LogicalOp.PLH);
        rule.instructionSet[8] = 1; //r3 second tracker 
        rule.instructionSet[9] = uint(LogicalOp.GT);
        rule.instructionSet[10] = 1; // use register 1
        rule.instructionSet[11] = 3; //r4 check that blocktime is greater than second tracker 
        rule.instructionSet[12] = uint(LogicalOp.OR);
        rule.instructionSet[13] = 2;
        rule.instructionSet[14] = 4;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[1].typeSpecificIndex = 2;
        rule.placeHolders[2].pType = ParamTypes.UINT;
        rule.placeHolders[2].typeSpecificIndex = 5;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule);

        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = ParamTypes.UINT;
        tracker.trackerValue = abi.encode(1000000000);
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName");

        //build second tracker
        Trackers memory tracker2;
        /// build the members of the struct:
        tracker2.pType = ParamTypes.UINT;
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

    //// Mapped Trackers 

    /// trackers as a rule conditional 

    /// uint to uint trackers 
    function testRulesEngine_Unit_MappedTrackerAsConditional_Uint_Positive() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.UINT; 
        tracker.trackerKeyType = ParamTypes.UINT;

        ParamTypes ruleParamType = ParamTypes.UINT;

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(1000000000); // value 1
        trackerValues[1] = abi.encode(2000000000); // value 

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.UINT, // pType for the mapped tracker
            ruleParamType, 
            1 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1)); 
        assertEq(value, abi.encode(1000000000)); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);

    }

    function testRulesEngine_Unit_MappedTrackerAsConditional_Uint_Negative() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.UINT; 
        tracker.trackerKeyType = ParamTypes.UINT;

        ParamTypes ruleParamType = ParamTypes.UINT;

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(1000000000); // value 1
        trackerValues[1] = abi.encode(2000000000); // value 

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.UINT, // pType for the mapped tracker
            ruleParamType,
            1 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1)); 
        assertEq(value, abi.encode(1000000000)); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 2000000000);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// uint to address 
    function testRulesEngine_Unit_MappedTrackerAsConditional_UintToAddress_Positive() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR; 
        tracker.trackerKeyType = ParamTypes.ADDR;

        ParamTypes ruleParamType = ParamTypes.ADDR;

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(address(0x7654321)); // value 1
        trackerValues[1] = abi.encode(address(0x1234567)); // value 2

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.UINT, // pType for the mapped tracker
            ruleParamType,
            0 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1)); 
        assertEq(value, abi.encode(address(0x7654321))); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);

    }

    function testRulesEngine_Unit_MappedTrackerAsConditional_UintToAddress_Negative() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR; 
        tracker.trackerKeyType = ParamTypes.UINT;

        ParamTypes ruleParamType = ParamTypes.ADDR;

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(address(0x7654321)); // value 1
        trackerValues[1] = abi.encode(address(0x1234567)); // value 2

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.UINT, // pType for the mapped tracker
            ruleParamType,
            0 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1)); 
        assertEq(value, abi.encode(address(0x7654321))); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// address to uint 
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToUint_Positive() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.UINT; // set the ParamType for the tracker value to be decoded as 
        tracker.trackerKeyType = ParamTypes.ADDR;

        ParamTypes ruleParamType = ParamTypes.UINT; // set the ParamTypes for the rule placeholder 

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(1); // value 1
        trackerValues[1] = abi.encode(2); // value 2

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.UINT, // pType for the mapped tracker
            ruleParamType,
            1 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321))); 
        assertEq(value, abi.encode(1)); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        // address to uint mapped tracker (is the amount to allowed for address)
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);

    }

    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToUint_Negative() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.UINT; // set the ParamType for the tracker value to be decoded as 
        tracker.trackerKeyType = ParamTypes.ADDR;

        ParamTypes ruleParamType = ParamTypes.UINT; // set the ParamTypes for the rule placeholder 

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(1); // value 1
        trackerValues[1] = abi.encode(2); // value 2

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.UINT, // pType for the mapped tracker
            ruleParamType,
            1 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321))); 
        assertEq(value, abi.encode(1)); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// address to Address  
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToAddress_Positive() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR; // set the ParamType for the tracker value to be decoded as 
        tracker.trackerKeyType = ParamTypes.ADDR;

        ParamTypes ruleParamType = ParamTypes.ADDR; // set the ParamTypes for the rule placeholder 

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(address(0x7654321)); // value 1
        trackerValues[1] = abi.encode(address(0x7654321)); // value 2

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.UINT, // pType for the mapped tracker
            ruleParamType,
            0 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321))); 
        assertEq(value, abi.encode(address(0x7654321))); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        // address to Address mapped tracker (Tracked addresses can only transfer to address(0x7654321)); 
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);

    }

    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToAddress_Negative() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR; // set the ParamType for the tracker value to be decoded as 
        tracker.trackerKeyType = ParamTypes.ADDR;

        ParamTypes ruleParamType = ParamTypes.ADDR; // set the ParamTypes for the rule placeholder 

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(address(0x7654321)); // value 1
        trackerValues[1] = abi.encode(address(0x7654321)); // value 2

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.UINT, // pType for the mapped tracker
            ruleParamType,
            0 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321))); 
        assertEq(value, abi.encode(address(0x7654321))); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        // address to Address mapped tracker (Tracked addresses can only transfer to address(0x7654321)); 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    // Uint to Bool 
    function testRulesEngine_Unit_MappedTrackerAsConditional_UintToBool_Negative() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.BOOL; 
        tracker.trackerKeyType = ParamTypes.UINT;

        ParamTypes ruleParamType = ParamTypes.BOOL;

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(true); // value 1
        trackerValues[1] = abi.encode(false); // value 2

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.BOOL, // pType for the mapped tracker
            ruleParamType,
            2 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1)); 
        assertEq(value, abi.encode(true)); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000, false);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// uint to bool 
    function testRulesEngine_Unit_MappedTrackerAsConditional_UintToBool_Positive() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.BOOL; 
        tracker.trackerKeyType = ParamTypes.UINT;

        ParamTypes ruleParamType = ParamTypes.BOOL;

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(true); // value 1
        trackerValues[1] = abi.encode(false); // value 2

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.BOOL, // pType for the mapped tracker
            ruleParamType,
            2 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1)); 
        assertEq(value, abi.encode(true)); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1, true);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);
    }

    // Bool to Uint 
    function testRulesEngine_Unit_MappedTrackerAsConditional_BoolToUint_Negative() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.UINT; 
        tracker.trackerKeyType = ParamTypes.BOOL;

        ParamTypes ruleParamType = ParamTypes.BOOL;

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(true); // value 1
        trackerValues[1] = abi.encode(false); // value 2

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.BOOL, // pType for the mapped tracker
            ruleParamType,
            2 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1)); 
        assertEq(value, abi.encode(true)); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000, false);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// bool to uint 
    function testRulesEngine_Unit_MappedTrackerAsConditional_BoolToUint_Positive() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.BOOL; 
        tracker.trackerKeyType = ParamTypes.UINT;

        ParamTypes ruleParamType = ParamTypes.UINT;

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(true); // key 1
        trackerKeys[1] = abi.encode(false); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(1); // value 1
        trackerValues[1] = abi.encode(2); // value 2

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.BOOL, // pType for the mapped tracker
            ruleParamType,
            2 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1)); 
        assertEq(value, abi.encode(true)); 
        assertEq(trackerIndex, 1);
        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1, true);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);
    }

    // address to bool 
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToBool_Negative() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR; 
        tracker.trackerKeyType = ParamTypes.ADDR;

        ParamTypes ruleParamType = ParamTypes.ADDR;

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(true); // value 1
        trackerValues[1] = abi.encode(false); // value 2

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.ADDR, // pType for the mapped tracker
            ruleParamType,
            2 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321))); 
        assertEq(value, abi.encode(true)); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000, false);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// Address to Bool 
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToBool_Positive() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR; 
        tracker.trackerKeyType = ParamTypes.ADDR;

        ParamTypes ruleParamType = ParamTypes.ADDR;

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(true); // value 1
        trackerValues[1] = abi.encode(false); // value 2

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.ADDR, // pType for the mapped tracker
            ruleParamType,
            2 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321))); 
        assertEq(value, abi.encode(true)); 
        assertEq(trackerIndex, 1);
        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1, true);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);
    }

    // Bool To Address
    function testRulesEngine_Unit_MappedTrackerAsConditional_BoolToAddress_Negative() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR; 
        tracker.trackerKeyType = ParamTypes.BOOL;

        ParamTypes ruleParamType = ParamTypes.ADDR;

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(true); // key 1
        trackerKeys[1] = abi.encode(false); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(address(0x7654321)); // value 1
        trackerValues[1] = abi.encode(address(0x1234567)); // value 2

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.ADDR, // pType for the mapped tracker
            ruleParamType,
            2 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(true)); 
        assertEq(value, abi.encode(address(0x7654321))); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000, false);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// Bool To Address
    function testRulesEngine_Unit_MappedTrackerAsConditional_BoolToAddress_Positive() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR; 
        tracker.trackerKeyType = ParamTypes.ADDR;

        ParamTypes ruleParamType = ParamTypes.ADDR;

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(true); // value 1
        trackerValues[1] = abi.encode(false); // value 2

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.ADDR, // pType for the mapped tracker
            ruleParamType,
            2 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321))); 
        assertEq(value, abi.encode(true)); 
        assertEq(trackerIndex, 1);
        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1, true);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);
    }

    // Address to String 
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToString_Negative() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.STR; 
        tracker.trackerKeyType = ParamTypes.ADDR;

        ParamTypes ruleParamType = ParamTypes.STR;

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode("trackerValue1"); // value 1
        trackerValues[1] = abi.encode("trackerValue2"); // value 2

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.STR, // pType for the mapped tracker
            ruleParamType,
            2 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321))); 
        assertEq(value, abi.encode("trackerValue1")); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000, "trackerValue2");
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// Address to String 
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToString_Positive() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.STR; 
        tracker.trackerKeyType = ParamTypes.ADDR;

        ParamTypes ruleParamType = ParamTypes.STR;

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode("trackerValue1"); // value 1
        trackerValues[1] = abi.encode("trackerValue2"); // value 2

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.STR, // pType for the mapped tracker
            ruleParamType,
            2 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321))); 
        assertEq(value, abi.encode("trackerValue1")); 
        assertEq(trackerIndex, 1);
        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1, "trackerValue1");
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);
    }

    // string to address 
    // Address to String 
    function testRulesEngine_Unit_MappedTrackerAsConditional_StringToAddress_Negative() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR; 
        tracker.trackerKeyType = ParamTypes.STR;

        ParamTypes ruleParamType = ParamTypes.ADDR;

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(string("trackerValue1")); // key 1
        trackerKeys[1] = abi.encode(string("trackerValue2")); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(address(0x7654321)); // value 1
        trackerValues[1] = abi.encode(address(0x1234567)); // value 2

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.ADDR, // pType for the mapped tracker
            ruleParamType,
            0 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(string("trackerValue1"))); 
        assertEq(value, abi.encode(address(0x7654321))); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000, "trackerValue2");
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// Address to String 
    function testRulesEngine_Unit_MappedTrackerAsConditional_StringToAddress_Positive() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR; 
        tracker.trackerKeyType = ParamTypes.STR;

        ParamTypes ruleParamType = ParamTypes.ADDR;

        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(string("trackerValue1")); // key 1
        trackerKeys[1] = abi.encode(string("trackerValue2")); // key 2

        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(address(0x7654321)); // value 1
        trackerValues[1] = abi.encode(address(0x1234567)); // value 2

        /// create tracker name
        string memory trackerName = "tracker1"; 

        /// set up rule 
        uint256 trackerIndex = _setUpRuleWithMappedTracker(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerName, 
            ParamTypes.ADDR, // pType for the mapped tracker
            ruleParamType,
            0 //type specific index for the placeholders 
        );
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(string("trackerValue1"))); 
        assertEq(value, abi.encode(address(0x7654321))); 
        assertEq(trackerIndex, 1);
        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1, string("trackerValue1"));
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);
    }


    /// tracker updated from effects 

    // uint to uint tracker updates 
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_UintToUint_Positive() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.UINT; 
        tracker.trackerKeyType = ParamTypes.UINT;
        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2
        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(1000000000); // value 1
        trackerValues[1] = abi.encode(2000000000); // value 2
        /// create tracker name
        string memory trackerName = "tracker1"; 

        ParamTypes trackerKeyTypes = ParamTypes.UINT; 

        /// set up rule 
        uint256 trackerIndex = _setupRuleWithMappedTrackerUpdatedFromEffect(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerKeyTypes,
            trackerName
        );

        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1)); 
        assertEq(value, abi.encode(1000000000)); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, 100);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(updatedValue, abi.encode(100)); 
    }

    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_UintToUint_Negative() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.UINT; 
        tracker.trackerKeyType = ParamTypes.UINT;
        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2
        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(1000000000); // value 1
        trackerValues[1] = abi.encode(2000000000); // value 2
        /// create tracker name
        string memory trackerName = "tracker1"; 

        ParamTypes trackerKeyTypes = ParamTypes.UINT; 

        /// set up rule 
        uint256 trackerIndex = _setupRuleWithMappedTrackerUpdatedFromEffect(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerKeyTypes,
            trackerName
        );

        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1)); 
        assertEq(value, abi.encode(1000000000)); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, 100);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertNotEq(updatedValue, abi.encode(200)); 
    }

    // uint to address tracker updates 
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_UintToAddress_Positive() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR; 
        tracker.trackerKeyType = ParamTypes.UINT;
        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2
        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(address(0x1234567)); // value 1
        trackerValues[1] = abi.encode(address(0x7654321)); // value 2
        /// create tracker name
        string memory trackerName = "tracker1"; 

        ParamTypes trackerKeyTypes = ParamTypes.UINT; 

        /// set up rule 
        uint256 trackerIndex = _setupRuleWithMappedTrackerUpdatedFromEffect(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerKeyTypes,
            trackerName
        );

        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1)); 
        assertEq(value, abi.encode(address(0x1234567))); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, address(0x7654321));
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(updatedValue, abi.encode(address(0x7654321))); 
    }

    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_UintToAddress_Negative() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR; 
        tracker.trackerKeyType = ParamTypes.UINT;
        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1); // key 1
        trackerKeys[1] = abi.encode(2); // key 2
        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(address(0x1234567)); // value 1
        trackerValues[1] = abi.encode(address(0x7654321)); // value 2
        /// create tracker name
        string memory trackerName = "tracker1"; 

        ParamTypes trackerKeyTypes = ParamTypes.UINT; 

        /// set up rule 
        uint256 trackerIndex = _setupRuleWithMappedTrackerUpdatedFromEffect(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerKeyTypes,
            trackerName
        );

        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1)); 
        assertEq(value, abi.encode(address(0x1234567))); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, address(0x7654321));
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertNotEq(updatedValue, abi.encode(address(0x1234567))); 
    }

    // address to Uint tracker updates 
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToUint_Positive() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.UINT; 
        tracker.trackerKeyType = ParamTypes.ADDR;
        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2
        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(1000); // value 1
        trackerValues[1] = abi.encode(2000); // value 2
        /// create tracker name
        string memory trackerName = "tracker1"; 
        /// set up rule 
        ParamTypes trackerKeyTypes = ParamTypes.ADDR; 

        /// set up rule 
        uint256 trackerIndex = _setupRuleWithMappedTrackerUpdatedFromEffect(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerKeyTypes,
            trackerName
        );
        
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321))); 
        assertEq(value, abi.encode(1000)); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, 20000);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertEq(updatedValue, abi.encode(20000)); 
    }

    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToUint_Negative() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.UINT; 
        tracker.trackerKeyType = ParamTypes.ADDR;
        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321)); // key 1
        trackerKeys[1] = abi.encode(address(0x1234567)); // key 2
        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(1000); // value 1
        trackerValues[1] = abi.encode(2000); // value 2
        /// create tracker name
        string memory trackerName = "tracker1"; 
        /// set up rule 
        ParamTypes trackerKeyTypes = ParamTypes.ADDR; 

        /// set up rule 
        uint256 trackerIndex = _setupRuleWithMappedTrackerUpdatedFromEffect(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerKeyTypes,
            trackerName
        );
        
        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321))); 
        assertEq(value, abi.encode(1000)); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, 20000);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertNotEq(updatedValue, abi.encode(1000)); 
    }

    // address to Address tracker updates 
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToAddress_Positive() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR; 
        tracker.trackerKeyType = ParamTypes.ADDR;
        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x1234567)); // key 1
        trackerKeys[1] = abi.encode(address(0x7654321)); // key 2
        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(address(0x9999999)); // value 1
        trackerValues[1] = abi.encode(address(0x8888888)); // value 2
        /// create tracker name
        string memory trackerName = "tracker1"; 

        ParamTypes trackerKeyTypes = ParamTypes.ADDR; 

        /// set up rule 
        uint256 trackerIndex = _setupRuleWithMappedTrackerUpdatedFromEffect(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerKeyTypes,
            trackerName
        );

        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        assertEq(uint256(returnedTracker.trackerKeyType), uint256(ParamTypes.ADDR));
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321))); 
        assertEq(value, abi.encode(address(0x8888888))); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, address(0x7777));
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertEq(updatedValue, abi.encode(address(0x7777))); 
    }

    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToAddress_Negative() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR; 
        tracker.trackerKeyType = ParamTypes.ADDR;
        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x1234567)); // key 1
        trackerKeys[1] = abi.encode(address(0x7654321)); // key 2
        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(address(0x9999999)); // value 1
        trackerValues[1] = abi.encode(address(0x8888888)); // value 2
        /// create tracker name
        string memory trackerName = "tracker1"; 

        ParamTypes trackerKeyTypes = ParamTypes.ADDR; 
        /// set up rule 
        uint256 trackerIndex = _setupRuleWithMappedTrackerUpdatedFromEffect(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerKeyTypes,
            trackerName
        );

        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321))); 
        assertEq(value, abi.encode(address(0x8888888))); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, address(0x7777));
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertNotEq(updatedValue, abi.encode(address(0x8888888))); 
    }

    // address to bool tracker updates 
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToBool_Positive() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.BOOL; 
        tracker.trackerKeyType = ParamTypes.ADDR;
        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x1234567)); // key 1
        trackerKeys[1] = abi.encode(address(0x7654321)); // key 2
        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(false); // value 1
        trackerValues[1] = abi.encode(false); // value 2
        /// create tracker name
        string memory trackerName = "tracker1"; 

        ParamTypes trackerKeyTypes = ParamTypes.ADDR; 
        /// set up rule 
        uint256 trackerIndex = _setupRuleWithMappedTrackerUpdatedFromEffect(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerKeyTypes,
            trackerName
        );

        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        assertEq(uint256(returnedTracker.trackerKeyType), uint256(ParamTypes.ADDR));
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321))); 
        assertEq(value, abi.encode(false)); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, true);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertEq(updatedValue, abi.encode(true)); 
    }

    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToBool_Negative() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct 
        Trackers memory tracker;
        tracker.pType = ParamTypes.BOOL; 
        tracker.trackerKeyType = ParamTypes.ADDR;
        /// create tracker key arrays 
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x1234567)); // key 1
        trackerKeys[1] = abi.encode(address(0x7654321)); // key 2
        /// create tracker value arrays 
        bytes[] memory trackerValues = new bytes[](2); 
        trackerValues[0] = abi.encode(false); // value 1
        trackerValues[1] = abi.encode(false); // value 2
        /// create tracker name
        string memory trackerName = "tracker1"; 

        ParamTypes trackerKeyTypes = ParamTypes.ADDR; 
        /// set up rule 
        uint256 trackerIndex = _setupRuleWithMappedTrackerUpdatedFromEffect(
            policyId,
            tracker, 
            trackerKeys, 
            trackerValues, 
            trackerKeyTypes,
            trackerName
        );

        // validate tracker 
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex); 
        assertTrue(returnedTracker.mapped); 
        assertEq(uint256(returnedTracker.trackerKeyType), uint256(ParamTypes.ADDR));
        
        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321))); 
        assertEq(value, abi.encode(false)); 
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional 
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, true);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertNotEq(updatedValue, abi.encode(false)); 
    }

    function test_initialize_onlyOnce_negative() public ifDeploymentTestsEnabled{
        vm.expectRevert("Already initialized");
        RulesEngineInitialFacet(address(red)).initialize(
            address(this)
        );
        
    }

    function test_GrantCallingContractRole() public ifDeploymentTestsEnabled{
        vm.startPrank(address(0x1337));
        vm.expectRevert("Only Calling Contract Can Create Admin");
        RulesEngineAdminRolesFacet(address(red)).grantCallingContractRole(address(0x1337), callingContractAdmin);
    }

    function testRulesEngine_Unit_GlobalVariable_BlockTimestamp() public ifDeploymentTestsEnabled resetsGlobalVariables {
        // Create policy
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();
    
        // Create rule that checks if block.timestamp > 1000
        Rule memory rule;
    
        // Set up instruction set: 
        // Register 0: global block.timestamp
        // Register 1: constant (1000)
        // Register 2: check if r0 > r1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;         // r0: placeholder 0 (global block.timestamp)
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1000;      // r1: constant 1000
        rule.instructionSet[4] = uint(LogicalOp.GTEQL);
        rule.instructionSet[5] = 0;         // block.timestamp
        rule.instructionSet[6] = 1;         // constant 1000
    
        // Create placeholders - first one for global block.timestamp
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        // Flag bits are shifted by 2 (SHIFT_GLOBAL_VAR = 2)
        rule.placeHolders[0].flags = uint8(GLOBAL_BLOCK_TIMESTAMP << SHIFT_GLOBAL_VAR);
    
        // Add effects - rule fails if timestamp <= 1000
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;
    
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule);
    
        // Set up calling function
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId, 
            bytes4(keccak256(bytes(callingFunction))), 
            pTypes,
            callingFunction,
            ""
        );
    
        // Update policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            callingFunctionIds,
            ruleIds,
            PolicyType.CLOSED_POLICY
        );

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
    
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    
        // block.timestamp < 1000 should fail
        vm.warp(900);
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))), 
            address(0x7654321), 
            5
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // block.timestamp == 1000 should pass
        vm.warp(1000);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);
    
        // block.timestamp > 1000 should pass
        vm.warp(1100);
        response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_GlobalVariable_BlockNumber() public ifDeploymentTestsEnabled resetsGlobalVariables {
        // Create policy
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();

        // Create rule that checks if block.number >= 1000
        Rule memory rule;

        // Set up instruction set: 
        // Register 0: global block.number
        // Register 1: constant (1000)
        // Register 2: check if r0 >= r1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;         // r0: placeholder 0 (global block.number)
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1000;      // r1: constant 1000
        rule.instructionSet[4] = uint(LogicalOp.GTEQL);
        rule.instructionSet[5] = 0;         // block.number
        rule.instructionSet[6] = 1;         // constant 1000

        // Create placeholders - first one for global block.number
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        // Flag bits are shifted by 2 
        rule.placeHolders[0].flags = uint8(GLOBAL_BLOCK_NUMBER << SHIFT_GLOBAL_VAR);

        // Add effects - rule fails if block.number < 1000
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;

        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule);

        // Set up calling function
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId, 
            bytes4(keccak256(bytes(callingFunction))), 
            pTypes,
            callingFunction,
            ""
        );

        // Update policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            callingFunctionIds,
            ruleIds,
            PolicyType.CLOSED_POLICY
        );

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        // block.number < 1000 should fail
        vm.roll(900);
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))), 
            address(0x7654321), 
            5
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // block.number == 1000 should pass
        vm.roll(1000);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);

        // block.number > 1000 should pass
        vm.roll(1100);
        response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_GlobalVariable_MsgSender() public ifDeploymentTestsEnabled resetsGlobalVariables {
        // Create policy
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();

        // Create rule that checks if msg.sender == expectedAddress
        address expectedAddress = address(0x1337);
        Rule memory rule;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;         // r0: placeholder 0 (global msg.sender)
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(uint160(expectedAddress)); // r1: expected address
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;         // msg.sender
        rule.instructionSet[6] = 1;         // expected address

        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].flags = uint8(GLOBAL_MSG_SENDER << SHIFT_GLOBAL_VAR);

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule);

        // Set up calling function
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId, 
            bytes4(keccak256(bytes(callingFunction))), 
            pTypes,
            callingFunction,
            ""
        );

        // Update policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            callingFunctionIds,
            ruleIds,
            PolicyType.CLOSED_POLICY
        );

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        // Call from incorrect address - should fail
        vm.stopPrank();
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))), 
            address(0x7654321), 
            5
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // Call from correct address - should pass
        vm.stopPrank();
        vm.startPrank(expectedAddress);
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_GlobalVariable_TxOrigin() public ifDeploymentTestsEnabled resetsGlobalVariables {
        // Create policy
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();

        // Create rule that checks if tx.origin == expectedAddress
        address expectedAddress = address(0x1337);
        Rule memory rule;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0;                                  // r0: placeholder 0 (global tx.origin)
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(uint160(expectedAddress));  // r1: expected address
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;                                  // tx.origin
        rule.instructionSet[6] = 1;                                  // expected address

        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].flags = uint8(GLOBAL_TX_ORIGIN << SHIFT_GLOBAL_VAR);

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule);

        // Set up calling function
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId, 
            bytes4(keccak256(bytes(callingFunction))), 
            pTypes,
            callingFunction,
            ""
        );

        // Update policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            callingFunctions,
            callingFunctionIds,
            ruleIds,
            PolicyType.CLOSED_POLICY
        );

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        // Call from incorrect tx.origin - should fail
        vm.stopPrank();
        vm.startPrank(userContractAddress, address(0x9999));  // Second parameter is tx.origin
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))), 
            address(0x7654321), 
            5
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // Call from correct tx.origin - should pass
        vm.stopPrank();
        vm.startPrank(userContractAddress, expectedAddress);  // Second parameter is tx.origin
        uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_ForeignCall_Bytes_Param() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId;
        uint256 ruleId;
        uint256 callingFunctionId;

        {
            vm.startPrank(policyAdmin);

            policyId = _createBlankPolicy();

            address foreignCallTarget = userContractAddress;
            bytes4 setMsgDataSelector = ExampleUserContract.setMsgData.selector;

            uint256 foreignCallId;
            {
                ParamTypes[] memory fcParamTypes = new ParamTypes[](1);
                fcParamTypes[0] = ParamTypes.BYTES;
                int8[] memory fcTypeSpecificIndices = new int8[](1);
                fcTypeSpecificIndices[0] = 2;
                ForeignCall memory fc;
                fc.foreignCallAddress = foreignCallTarget;
                fc.signature = setMsgDataSelector;
                fc.returnType = ParamTypes.BOOL;
                fc.parameterTypes = fcParamTypes;
                fc.typeSpecificIndices = fcTypeSpecificIndices;
                foreignCallId = RulesEngineComponentFacet(address(red)).createForeignCall(policyId, fc, "setMsgData(bytes)");
            }

            // Effect for the foreign call
            Effect memory effect;
            effect.valid = true;
            effect.dynamicParam = false;
            effect.effectType = EffectTypes.EXPRESSION;
            effect.pType = ParamTypes.VOID;
            effect.param = abi.encodePacked(foreignCallId);
            effect.text = "";
            effect.errorMessage = "";
            effect.instructionSet = new uint256[](0);

            Rule memory rule;
            rule.instructionSet = new uint256[](2);
            rule.instructionSet[0] = uint(LogicalOp.PLH);
            rule.instructionSet[1] = 1;

            rule.placeHolders = new Placeholder[](2);
            // Placeholder 0: msg.data
            rule.placeHolders[0].pType = ParamTypes.BYTES;
            rule.placeHolders[0].typeSpecificIndex = 2;
            //rule.placeHolders[0].flags = uint8(GLOBAL_MSG_DATA << SHIFT_GLOBAL_VAR);

            // Placeholder 1: foreign call
            rule.placeHolders[1].pType = ParamTypes.BOOL;
            rule.placeHolders[1].typeSpecificIndex = uint128(foreignCallId);
            rule.placeHolders[1].flags = uint8(FLAG_FOREIGN_CALL);

        
            rule.effectPlaceHolders = new Placeholder[](1);
            rule.effectPlaceHolders[0].pType = ParamTypes.BYTES;
            rule.effectPlaceHolders[0].typeSpecificIndex = 0; 
            rule.effectPlaceHolders[0].flags = 0;

            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            rule.posEffects = new Effect[](1);
            rule.posEffects[0] = effectId_event;

            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule);

            {
                bytes4 transferSelector = ExampleUserContract.transferFrom.selector;
                ParamTypes[] memory pTypes = new ParamTypes[](3);
                pTypes[0] = ParamTypes.ADDR;
                pTypes[1] = ParamTypes.UINT;
                pTypes[2] = ParamTypes.BYTES;
                callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
                    policyId,
                    transferSelector,
                    pTypes,
                    "transferFrom(address,uint256,bytes)",
                    ""
                );

                bytes4[] memory selectors = new bytes4[](1);
                selectors[0] = transferSelector;
                uint256[] memory functionIds = new uint256[](1);
                functionIds[0] = callingFunctionId;
                uint256[][] memory ruleIdsArr = new uint256[][](1);
                ruleIdsArr[0] = new uint256[](1);
                ruleIdsArr[0][0] = ruleId;
                RulesEnginePolicyFacet(address(red)).updatePolicy(
                    policyId,
                    selectors,
                    functionIds,
                    ruleIdsArr,
                    PolicyType.CLOSED_POLICY
                );
            }

            {
                uint256[] memory policyIds = new uint256[](1);
                policyIds[0] = policyId;
                vm.stopPrank();
                vm.startPrank(callingContractAdmin);
                RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
                vm.stopPrank();
            }
        }

        {
            vm.startPrank(userContractAddress);
            address to = address(0xBEEF);
            uint256 value = 42;
            bytes memory transferCalldata = abi.encodeWithSelector(ExampleUserContract.transferFrom.selector, to, value, abi.encode("TESTER"));

            RulesEngineProcessorFacet(address(red)).checkPolicies(transferCalldata);

            bytes memory actualMsgData = ExampleUserContract(userContractAddress).msgData();
            bytes memory expectedTesterData = abi.encode("TESTER");
            assertEq(actualMsgData, expectedTesterData, "Foreign call should set msgData to the encoded TESTER string");
            vm.stopPrank();
        }
    }

    function testRulesEngine_Unit_ForeignCall_Bytes_MsgData() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId;
        uint256 ruleId;
        uint256 callingFunctionId;

        {
            vm.startPrank(policyAdmin);

            policyId = _createBlankPolicy();

            address foreignCallTarget = userContractAddress;
            bytes4 setMsgDataSelector = ExampleUserContract.setMsgData.selector;

            uint256 foreignCallId;
            {
                ParamTypes[] memory fcParamTypes = new ParamTypes[](1);
                fcParamTypes[0] = ParamTypes.BYTES;
                int8[] memory fcTypeSpecificIndices = new int8[](1);
                fcTypeSpecificIndices[0] = -100;
                ForeignCall memory fc;
                fc.foreignCallAddress = foreignCallTarget;
                fc.signature = setMsgDataSelector;
                fc.returnType = ParamTypes.BOOL;
                fc.parameterTypes = fcParamTypes;
                fc.typeSpecificIndices = fcTypeSpecificIndices;
                foreignCallId = RulesEngineComponentFacet(address(red)).createForeignCall(policyId, fc, "setMsgData(bytes)");
            }

            // Effect for the foreign call
            Effect memory effect;
            effect.valid = true;
            effect.dynamicParam = false;
            effect.effectType = EffectTypes.EXPRESSION;
            effect.pType = ParamTypes.VOID;
            effect.param = abi.encodePacked(foreignCallId);
            effect.text = "";
            effect.errorMessage = "";
            effect.instructionSet = new uint256[](0);

            Rule memory rule;
            rule.instructionSet = new uint256[](2);
            rule.instructionSet[0] = uint(LogicalOp.PLH);
            rule.instructionSet[1] = 1;

            rule.placeHolders = new Placeholder[](2);
            // Placeholder 0: msg.data
            rule.placeHolders[0].pType = ParamTypes.BYTES;
            rule.placeHolders[0].flags = uint8(GLOBAL_MSG_DATA << SHIFT_GLOBAL_VAR);

            // Placeholder 1: foreign call
            rule.placeHolders[1].pType = ParamTypes.BOOL;
            rule.placeHolders[1].typeSpecificIndex = uint128(foreignCallId);
            rule.placeHolders[1].flags = uint8(FLAG_FOREIGN_CALL);

        
            rule.effectPlaceHolders = new Placeholder[](1);
            rule.effectPlaceHolders[0].pType = ParamTypes.BYTES;
            rule.effectPlaceHolders[0].typeSpecificIndex = 0; 
            rule.effectPlaceHolders[0].flags = 0;

            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            rule.posEffects = new Effect[](1);
            rule.posEffects[0] = effectId_event;

            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule);

            {
                bytes4 transferSelector = ExampleUserContract.transferFrom.selector;
                ParamTypes[] memory pTypes = new ParamTypes[](3);
                pTypes[0] = ParamTypes.ADDR;
                pTypes[1] = ParamTypes.UINT;
                pTypes[2] = ParamTypes.BYTES;
                callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
                    policyId,
                    transferSelector,
                    pTypes,
                    "transferFrom(address,uint256,bytes)",
                    ""
                );

                bytes4[] memory selectors = new bytes4[](1);
                selectors[0] = transferSelector;
                uint256[] memory functionIds = new uint256[](1);
                functionIds[0] = callingFunctionId;
                uint256[][] memory ruleIdsArr = new uint256[][](1);
                ruleIdsArr[0] = new uint256[](1);
                ruleIdsArr[0][0] = ruleId;
                RulesEnginePolicyFacet(address(red)).updatePolicy(
                    policyId,
                    selectors,
                    functionIds,
                    ruleIdsArr,
                    PolicyType.CLOSED_POLICY
                );
            }

            {
                uint256[] memory policyIds = new uint256[](1);
                policyIds[0] = policyId;
                vm.stopPrank();
                vm.startPrank(callingContractAdmin);
                RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
                vm.stopPrank();
            }
        }
        {
            vm.startPrank(userContractAddress);
            address to = address(0xBEEF);
            uint256 value = 42;
            bytes memory transferCalldata = abi.encodeWithSelector(
                ExampleUserContract.transferFrom.selector, to, value, abi.encode("TESTER")
            );

            RulesEngineProcessorFacet(address(red)).checkPolicies(transferCalldata);

            bytes memory actualMsgData = ExampleUserContract(userContractAddress).msgData();

            bytes4 checkPoliciesSelector = RulesEngineProcessorFacet(address(red)).checkPolicies.selector;
            bytes memory expectedMsgData = abi.encodeWithSelector(
                checkPoliciesSelector, transferCalldata
            );
            assertEq(
                actualMsgData,
                expectedMsgData,
                "Foreign call should set msgData to the ABI-encoded checkPolicies(bytes) calldata"
            );
            vm.stopPrank();
        }
    }

    function testRulesEngine_Unit_ForeignCall_Address_MsgSender() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId;
        uint256 ruleId;
        uint256 callingFunctionId;

        {
            vm.startPrank(policyAdmin);

            policyId = _createBlankPolicy();

            address foreignCallTarget = userContractAddress;
            bytes4 setUserAddressSelector = ExampleUserContract.setUserAddress.selector;

            uint256 foreignCallId;
            {
                ParamTypes[] memory fcParamTypes = new ParamTypes[](1);
                fcParamTypes[0] = ParamTypes.ADDR;
                int8[] memory fcTypeSpecificIndices = new int8[](1);
                fcTypeSpecificIndices[0] = -101; // GLOBAL_MSG_SENDER_INDEX
                ForeignCall memory fc;
                fc.foreignCallAddress = foreignCallTarget;
                fc.signature = setUserAddressSelector;
                fc.returnType = ParamTypes.BOOL;
                fc.parameterTypes = fcParamTypes;
                fc.typeSpecificIndices = fcTypeSpecificIndices;
                foreignCallId = RulesEngineComponentFacet(address(red)).createForeignCall(policyId, fc, "setUserAddress(address)");
            }

            Rule memory rule;
            rule.instructionSet = new uint256[](2);
            rule.instructionSet[0] = uint(LogicalOp.PLH);
            rule.instructionSet[1] = 1; // Use placeholder 1 (foreign call) for evaluation

            rule.placeHolders = new Placeholder[](2);
            // Placeholder 0: msg.sender (global variable)
            rule.placeHolders[0].pType = ParamTypes.ADDR;
            rule.placeHolders[0].flags = uint8(GLOBAL_MSG_SENDER << SHIFT_GLOBAL_VAR);

            // Placeholder 1: foreign call
            rule.placeHolders[1].pType = ParamTypes.BOOL;
            rule.placeHolders[1].typeSpecificIndex = uint128(foreignCallId);
            rule.placeHolders[1].flags = uint8(FLAG_FOREIGN_CALL);

            rule.effectPlaceHolders = new Placeholder[](0);

            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            rule.posEffects = new Effect[](1);
            rule.posEffects[0] = effectId_event;

            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule);

            {
                bytes4 transferSelector = ExampleUserContract.transferFrom.selector;
                ParamTypes[] memory pTypes = new ParamTypes[](3);
                pTypes[0] = ParamTypes.ADDR;
                pTypes[1] = ParamTypes.UINT;
                pTypes[2] = ParamTypes.BYTES;
                callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
                    policyId,
                    transferSelector,
                    pTypes,
                    "transferFrom(address,uint256,bytes)",
                    ""
                );

                bytes4[] memory selectors = new bytes4[](1);
                selectors[0] = transferSelector;
                uint256[] memory functionIds = new uint256[](1);
                functionIds[0] = callingFunctionId;
                uint256[][] memory ruleIdsArr = new uint256[][](1);
                ruleIdsArr[0] = new uint256[](1);
                ruleIdsArr[0][0] = ruleId;
                RulesEnginePolicyFacet(address(red)).updatePolicy(
                    policyId,
                    selectors,
                    functionIds,
                    ruleIdsArr,
                    PolicyType.CLOSED_POLICY
                );
            }

            {
                uint256[] memory policyIds = new uint256[](1);
                policyIds[0] = policyId;
                vm.stopPrank();
                vm.startPrank(callingContractAdmin);
                RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
                vm.stopPrank();
            }
        }

        {
            vm.startPrank(userContractAddress);
            address to = address(0xBEEF);
            uint256 value = 42;
            bytes memory transferCalldata = abi.encodeWithSelector(
                ExampleUserContract.transferFrom.selector, to, value, abi.encode("TESTER")
            );

            RulesEngineProcessorFacet(address(red)).checkPolicies(transferCalldata);

            address actualUserAddress = ExampleUserContract(userContractAddress).userAddress();
            assertEq(actualUserAddress, userContractAddress, "Foreign call should set userAddress to msg.sender");
            vm.stopPrank();
        }
    }

    function testRulesEngine_Unit_ForeignCall_Uint_BlockTimestamp() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId;
        uint256 ruleId;
        uint256 callingFunctionId;

        {
            vm.startPrank(policyAdmin);

            policyId = _createBlankPolicy();

            address foreignCallTarget = userContractAddress;
            bytes4 setNumberSelector = ExampleUserContract.setNumber.selector;

            uint256 foreignCallId;
            {
                ParamTypes[] memory fcParamTypes = new ParamTypes[](1);
                fcParamTypes[0] = ParamTypes.UINT;
                int8[] memory fcTypeSpecificIndices = new int8[](1);
                fcTypeSpecificIndices[0] = -102; // GLOBAL_BLOCK_TIMESTAMP_INDEX
                ForeignCall memory fc;
                fc.foreignCallAddress = foreignCallTarget;
                fc.signature = setNumberSelector;
                fc.returnType = ParamTypes.BOOL;
                fc.parameterTypes = fcParamTypes;
                fc.typeSpecificIndices = fcTypeSpecificIndices;
                foreignCallId = RulesEngineComponentFacet(address(red)).createForeignCall(policyId, fc, "setNumber(uint256)");
            }

            Rule memory rule;
            rule.instructionSet = new uint256[](2);
            rule.instructionSet[0] = uint(LogicalOp.PLH);
            rule.instructionSet[1] = 1; // Use placeholder 1 (foreign call) for evaluation

            rule.placeHolders = new Placeholder[](2);
            // Placeholder 0: block.timestamp (global variable)
            rule.placeHolders[0].pType = ParamTypes.UINT;
            rule.placeHolders[0].flags = uint8(GLOBAL_BLOCK_TIMESTAMP << SHIFT_GLOBAL_VAR);

            // Placeholder 1: foreign call
            rule.placeHolders[1].pType = ParamTypes.BOOL;
            rule.placeHolders[1].typeSpecificIndex = uint128(foreignCallId);
            rule.placeHolders[1].flags = uint8(FLAG_FOREIGN_CALL);

            rule.effectPlaceHolders = new Placeholder[](0);

            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            rule.posEffects = new Effect[](1);
            rule.posEffects[0] = effectId_event;

            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule);

            {
                bytes4 transferSelector = ExampleUserContract.transferFrom.selector;
                ParamTypes[] memory pTypes = new ParamTypes[](3);
                pTypes[0] = ParamTypes.ADDR;
                pTypes[1] = ParamTypes.UINT;
                pTypes[2] = ParamTypes.BYTES;
                callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
                    policyId,
                    transferSelector,
                    pTypes,
                    "transferFrom(address,uint256,bytes)",
                    ""
                );

                bytes4[] memory selectors = new bytes4[](1);
                selectors[0] = transferSelector;
                uint256[] memory functionIds = new uint256[](1);
                functionIds[0] = callingFunctionId;
                uint256[][] memory ruleIdsArr = new uint256[][](1);
                ruleIdsArr[0] = new uint256[](1);
                ruleIdsArr[0][0] = ruleId;
                RulesEnginePolicyFacet(address(red)).updatePolicy(
                    policyId,
                    selectors,
                    functionIds,
                    ruleIdsArr,
                    PolicyType.CLOSED_POLICY
                );
            }

            {
                uint256[] memory policyIds = new uint256[](1);
                policyIds[0] = policyId;
                vm.stopPrank();
                vm.startPrank(callingContractAdmin);
                RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
                vm.stopPrank();
            }
        }

        {
            // Set the block timestamp
            uint256 testTimestamp = 12345;
            vm.warp(testTimestamp);
        
            vm.startPrank(userContractAddress);
            address to = address(0xBEEF);
            uint256 value = 42;
            bytes memory transferCalldata = abi.encodeWithSelector(
                ExampleUserContract.transferFrom.selector, to, value, abi.encode("TESTER")
            );

            RulesEngineProcessorFacet(address(red)).checkPolicies(transferCalldata);

            // The number should now be set to the current block timestamp
            uint256 actualNumber = ExampleUserContract(userContractAddress).number();
            assertEq(actualNumber, testTimestamp, "Foreign call should set number to block.timestamp");
            vm.stopPrank();
        }
    }

    function testRulesEngine_Unit_ForeignCall_Uint_BlockNumber() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId;
        uint256 ruleId;
        uint256 callingFunctionId;

        {
            vm.startPrank(policyAdmin);

            policyId = _createBlankPolicy();

            address foreignCallTarget = userContractAddress;
            bytes4 setNumberSelector = ExampleUserContract.setNumber.selector;

            uint256 foreignCallId;
            {
                ParamTypes[] memory fcParamTypes = new ParamTypes[](1);
                fcParamTypes[0] = ParamTypes.UINT;
                int8[] memory fcTypeSpecificIndices = new int8[](1);
                fcTypeSpecificIndices[0] = -103; // GLOBAL_BLOCK_NUMBER_INDEX
                ForeignCall memory fc;
                fc.foreignCallAddress = foreignCallTarget;
                fc.signature = setNumberSelector;
                fc.returnType = ParamTypes.BOOL;
                fc.parameterTypes = fcParamTypes;
                fc.typeSpecificIndices = fcTypeSpecificIndices;
                foreignCallId = RulesEngineComponentFacet(address(red)).createForeignCall(policyId, fc, "setNumber(uint256)");
            }

            Rule memory rule;
            rule.instructionSet = new uint256[](2);
            rule.instructionSet[0] = uint(LogicalOp.PLH);
            rule.instructionSet[1] = 1; // Use placeholder 1 (foreign call) for evaluation

            rule.placeHolders = new Placeholder[](2);
            // Placeholder 0: block.number (global variable)
            rule.placeHolders[0].pType = ParamTypes.UINT;
            rule.placeHolders[0].flags = uint8(GLOBAL_BLOCK_NUMBER << SHIFT_GLOBAL_VAR);

            // Placeholder 1: foreign call
            rule.placeHolders[1].pType = ParamTypes.BOOL;
            rule.placeHolders[1].typeSpecificIndex = uint128(foreignCallId);
            rule.placeHolders[1].flags = uint8(FLAG_FOREIGN_CALL);

            rule.effectPlaceHolders = new Placeholder[](0);

            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            rule.posEffects = new Effect[](1);
            rule.posEffects[0] = effectId_event;

            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule);

            {
                bytes4 transferSelector = ExampleUserContract.transferFrom.selector;
                ParamTypes[] memory pTypes = new ParamTypes[](3);
                pTypes[0] = ParamTypes.ADDR;
                pTypes[1] = ParamTypes.UINT;
                pTypes[2] = ParamTypes.BYTES;
                callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
                    policyId,
                    transferSelector,
                    pTypes,
                    "transferFrom(address,uint256,bytes)",
                    ""
                );

                bytes4[] memory selectors = new bytes4[](1);
                selectors[0] = transferSelector;
                uint256[] memory functionIds = new uint256[](1);
                functionIds[0] = callingFunctionId;
                uint256[][] memory ruleIdsArr = new uint256[][](1);
                ruleIdsArr[0] = new uint256[](1);
                ruleIdsArr[0][0] = ruleId;
                RulesEnginePolicyFacet(address(red)).updatePolicy(
                    policyId,
                    selectors,
                    functionIds,
                    ruleIdsArr,
                    PolicyType.CLOSED_POLICY
                );
            }

            {
                uint256[] memory policyIds = new uint256[](1);
                policyIds[0] = policyId;
                vm.stopPrank();
                vm.startPrank(callingContractAdmin);
                RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
                vm.stopPrank();
            }
        }

        {
            // Set the block number
            uint256 testBlockNumber = 9876;
            vm.roll(testBlockNumber);
        
            vm.startPrank(userContractAddress);
            address to = address(0xBEEF);
            uint256 value = 42;
            bytes memory transferCalldata = abi.encodeWithSelector(
                ExampleUserContract.transferFrom.selector, to, value, abi.encode("TESTER")
            );

            RulesEngineProcessorFacet(address(red)).checkPolicies(transferCalldata);

            // The number should now be set to the current block number
            uint256 actualNumber = ExampleUserContract(userContractAddress).number();
            assertEq(actualNumber, testBlockNumber, "Foreign call should set number to block.number");
            vm.stopPrank();
        }
    }

    function testRulesEngine_Unit_ForeignCall_Address_TxOrigin() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId;
        uint256 ruleId;
        uint256 callingFunctionId;

        {
            vm.startPrank(policyAdmin);

            policyId = _createBlankPolicy();

            address foreignCallTarget = userContractAddress;
            bytes4 setUserAddressSelector = ExampleUserContract.setUserAddress.selector;

            uint256 foreignCallId;
            {
                ParamTypes[] memory fcParamTypes = new ParamTypes[](1);
                fcParamTypes[0] = ParamTypes.ADDR;
                int8[] memory fcTypeSpecificIndices = new int8[](1);
                fcTypeSpecificIndices[0] = -104; // GLOBAL_TX_ORIGIN_INDEX
                ForeignCall memory fc;
                fc.foreignCallAddress = foreignCallTarget;
                fc.signature = setUserAddressSelector;
                fc.returnType = ParamTypes.BOOL;
                fc.parameterTypes = fcParamTypes;
                fc.typeSpecificIndices = fcTypeSpecificIndices;
                foreignCallId = RulesEngineComponentFacet(address(red)).createForeignCall(policyId, fc, "setUserAddress(address)");
            }

            Rule memory rule;
            rule.instructionSet = new uint256[](2);
            rule.instructionSet[0] = uint(LogicalOp.PLH);
            rule.instructionSet[1] = 1; // Use placeholder 1 (foreign call) for evaluation

            rule.placeHolders = new Placeholder[](2);
            // Placeholder 0: tx.origin (global variable)
            rule.placeHolders[0].pType = ParamTypes.ADDR;
            rule.placeHolders[0].flags = uint8(GLOBAL_TX_ORIGIN << SHIFT_GLOBAL_VAR);

            // Placeholder 1: foreign call
            rule.placeHolders[1].pType = ParamTypes.BOOL;
            rule.placeHolders[1].typeSpecificIndex = uint128(foreignCallId);
            rule.placeHolders[1].flags = uint8(FLAG_FOREIGN_CALL);

            rule.effectPlaceHolders = new Placeholder[](0);

            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = effectId_revert;
            rule.posEffects = new Effect[](1);
            rule.posEffects[0] = effectId_event;

            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule);

            {
                bytes4 transferSelector = ExampleUserContract.transferFrom.selector;
                ParamTypes[] memory pTypes = new ParamTypes[](3);
                pTypes[0] = ParamTypes.ADDR;
                pTypes[1] = ParamTypes.UINT;
                pTypes[2] = ParamTypes.BYTES;
                callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
                    policyId,
                    transferSelector,
                    pTypes,
                    "transferFrom(address,uint256,bytes)",
                    ""
                );

                bytes4[] memory selectors = new bytes4[](1);
                selectors[0] = transferSelector;
                uint256[] memory functionIds = new uint256[](1);
                functionIds[0] = callingFunctionId;
                uint256[][] memory ruleIdsArr = new uint256[][](1);
                ruleIdsArr[0] = new uint256[](1);
                ruleIdsArr[0][0] = ruleId;
                RulesEnginePolicyFacet(address(red)).updatePolicy(
                    policyId,
                    selectors,
                    functionIds,
                    ruleIdsArr,
                    PolicyType.CLOSED_POLICY
                );
            }

            {
                uint256[] memory policyIds = new uint256[](1);
                policyIds[0] = policyId;
                vm.stopPrank();
                vm.startPrank(callingContractAdmin);
                RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
                vm.stopPrank();
            }
        }

        {
            // Set the tx.origin
            address txOriginAddress = address(0xABCD);
        
            vm.startPrank(userContractAddress, txOriginAddress);
            address to = address(0xBEEF);
            uint256 value = 42;
            bytes memory transferCalldata = abi.encodeWithSelector(
                ExampleUserContract.transferFrom.selector, to, value, abi.encode("TESTER")
            );

            RulesEngineProcessorFacet(address(red)).checkPolicies(transferCalldata);

            // The userAddress should now be set to the tx.origin address
            address actualUserAddress = ExampleUserContract(userContractAddress).userAddress();
            assertEq(actualUserAddress, txOriginAddress, "Foreign call should set userAddress to tx.origin");
            vm.stopPrank();
        }
    }
}
