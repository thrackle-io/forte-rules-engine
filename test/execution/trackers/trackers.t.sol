/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract trackers is RulesEngineCommon {
    /**
     *
     *
     * Execution tests for trackers within the rules engine
     *
     *
     */

    function testRulesEngine_Unit_CheckRules_Explicit_WithTrackerUpdateEffectAddress() public ifDeploymentTestsEnabled endWithStopPrank {
        // create a blank policy
        uint256 policyId = _createBlankPolicy();
        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = ParamTypes.ADDR;
        tracker.set = true;
        tracker.trackerValue = abi.encode(0xD00D);
        setupRuleWithTrackerAddr(policyId, tracker);

        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            5,
            address(0x7654321)
        );
        vm.startPrank(address(userContract));
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the third parameter
        vm.startSnapshotGas("CheckRules_Explicit_WithTrackerUpdateEffectAddress");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        assertEq(tracker.trackerValue, abi.encode(0x7654321));
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithTrackerUpdateEffectBool() public ifDeploymentTestsEnabled endWithStopPrank {
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
        vm.startSnapshotGas("CheckRules_Explicit_WithTrackerUpdateEffectBool");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        assertEq(tracker.trackerValue, abi.encode(bool(true)));
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithTrackerUpdateEffectUint() public ifDeploymentTestsEnabled endWithStopPrank {
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
        vm.startSnapshotGas("CheckRules_Explicit_WithTrackerUpdateEffectUint");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        assertEq(tracker.trackerValue, abi.encode(uint256(99)));
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithTrackerUpdateEffectBytes() public ifDeploymentTestsEnabled endWithStopPrank {
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
        vm.startSnapshotGas("CheckRules_Explicit_WithTrackerUpdateEffectBytes");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory comparison = abi.encode("post");
        assertEq(tracker.trackerValue, comparison);
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithTrackerUpdateEffectString() public ifDeploymentTestsEnabled endWithStopPrank {
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
        vm.startSnapshotGas("CheckRules_Explicit_WithTrackerUpdateEffectString");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
        tracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        bytes memory comparison = abi.encode("post");
        assertEq(tracker.trackerValue, comparison);
    }

    function testRulesEngine_Unit_CheckRules_WithTrackerValue() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithTracker(2);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        vm.startSnapshotGas("CheckRules_WithTrackerValue");
        bool retVal = userContract.transfer(address(0x7654321), 3);
        vm.stopSnapshotGas();
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.UINT, // value type
            ParamTypes.UINT, // tracker type
            2, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
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

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000000000, 1);
        vm.startSnapshotGas("MappedTrackerAsConditional_Uint_Positive");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.UINT, // value type
            ParamTypes.UINT, // tracker type
            0, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
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
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 2000000000);
        vm.expectRevert(abi.encodePacked(revert_text));
        vm.startSnapshotGas("MappedTrackerAsConditional_UintToUint");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    /// uint to address
    function testRulesEngine_Unit_MappedTrackerAsConditional_UintToAddress_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.ADDR, // value type
            ParamTypes.ADDR, // tracker type
            1, // key type specific index
            0, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(value, abi.encode(address(0x7654321)));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1);
        vm.startSnapshotGas("MappedTrackerAsConditional_UintToAddress");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_MappedTrackerAsConditional_UintToAddress_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.ADDR, // value type
            ParamTypes.ADDR, // tracker type
            0, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
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
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToUint_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.ADDR, // key type
            ParamTypes.UINT, // value type
            ParamTypes.UINT, // tracker type
            0, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
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
        vm.startSnapshotGas("MappedTrackerAsConditional_AddressToUint");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToUint_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.ADDR, // value type
            ParamTypes.ADDR, // tracker type
            0, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
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
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToAddress_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.ADDR, // key type
            ParamTypes.ADDR, // value type
            ParamTypes.ADDR, // tracker type
            0, // key type specific index
            0, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
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
        vm.startSnapshotGas("MappedTrackerAsConditional_AddressToAddress");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToAddress_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.BOOL, // value type
            ParamTypes.BOOL, // tracker type
            0, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.BOOL, // value type
            ParamTypes.BOOL, // tracker type
            0, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.BOOL, // value type
            ParamTypes.BOOL, // tracker type
            1, // key type specific index
            2, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
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
        vm.startSnapshotGas("MappedTrackerAsConditional_UintToBool");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.BOOL, // value type
            ParamTypes.BOOL, // tracker type
            0, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.BOOL, // key type
            ParamTypes.UINT, // value type
            ParamTypes.UINT, // tracker type
            2, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
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
        vm.startSnapshotGas("MappedTrackerAsConditional_BoolToUint");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    // address to bool
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToBool_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.BOOL, // value type
            ParamTypes.BOOL, // tracker type
            0, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertEq(value, abi.encode(true));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 2000000000, true);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// Address to Bool
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToBool_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.BOOL, // value type
            ParamTypes.BOOL, // tracker type
            0, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertEq(value, abi.encode(true));
        assertEq(trackerIndex, 1);
        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1, false);
        vm.startSnapshotGas("MappedTrackerAsConditional_AddressToBool");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    // Bool To Address
    function testRulesEngine_Unit_MappedTrackerAsConditional_BoolToAddress_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.BOOL, // value type
            ParamTypes.BOOL, // tracker type
            0, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
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
    function testRulesEngine_Unit_MappedTrackerAsConditional_BoolToAddress_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // key type
            ParamTypes.BOOL, // value type
            ParamTypes.BOOL, // tracker type
            0, // key type specific index
            1, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
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
        vm.startSnapshotGas("MappedTrackerAsConditional_BoolToAddress");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    // Address to String
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToString_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.ADDR, // key type
            ParamTypes.STR, // value type
            ParamTypes.STR, // tracker type
            0, // key type specific index
            2, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x7654321)));
        assertEq(value, abi.encode("trackerValue1"));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x1234567),
            2000000000,
            "trackerValue1"
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// Address to String
    function testRulesEngine_Unit_MappedTrackerAsConditional_AddressToString_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.ADDR, // key type
            ParamTypes.STR, // value type
            ParamTypes.STR, // tracker type
            0, // key type specific index
            2, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
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
        vm.startSnapshotGas("MappedTrackerAsConditional_AddressToString");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    // string to address
    // Address to String
    function testRulesEngine_Unit_MappedTrackerAsConditional_StringToAddress_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.STR, // key type
            ParamTypes.ADDR, // value type
            ParamTypes.ADDR, // tracker type
            2, // key type specific index
            0, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(string("trackerValue1"))
        );
        assertEq(value, abi.encode(address(0x7654321)));
        assertEq(trackerIndex, 1);

        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x1234567),
            2000000000,
            "trackerValue1"
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    /// Address to String
    function testRulesEngine_Unit_MappedTrackerAsConditional_StringToAddress_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR;
        tracker.trackerKeyType = ParamTypes.STR;

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
        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.STR, // key type
            ParamTypes.ADDR, // value type
            ParamTypes.ADDR, // tracker type
            2, // key type specific index
            0, // value type specific index
            trackerKeys,
            trackerValues,
            trackerName
        );
        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(string("trackerValue1"))
        );
        assertEq(value, abi.encode(address(0x7654321)));
        assertEq(trackerIndex, 1);
        /// validate tracker is checked as conditional
        vm.startPrank(userContractAddress);

        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1,
            string("trackerValue1")
        );
        vm.startSnapshotGas("MappedTrackerAsConditional_StringToAddress");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    /// tracker updated from effects
    // uint to uint tracker updates
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_UintToUint_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        vm.startSnapshotGas("MappedTrackerUpdatedFromEffects_UintToUint");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(updatedValue, abi.encode(100));
    }

    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_UintToUint_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertNotEq(updatedValue, abi.encode(200));
    }

    // uint to address tracker updates
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_UintToAddress_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1000000000,
            address(0x7654321)
        );
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertEq(updatedValue, abi.encode(address(0x7654321)));
    }

    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_UintToAddress_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1000000000,
            address(0x7654321)
        );
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(1));
        assertNotEq(updatedValue, abi.encode(address(0x1234567)));
    }

    // address to Uint tracker updates
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToUint_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        vm.startSnapshotGas("MappedTrackerUpdatedFromEffects_AddressToUint");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertEq(updatedValue, abi.encode(20000));
    }

    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToUint_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertNotEq(updatedValue, abi.encode(1000));
    }

    // address to Address tracker updates
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToAddress_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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

        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1000000000,
            address(0x7777)
        );
        vm.startSnapshotGas("MappedTrackerUpdatedFromEffects_AddressToAddress");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertEq(updatedValue, abi.encode(address(0x7777)));
    }

    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToAddress_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            1000000000,
            address(0x7777)
        );
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertNotEq(updatedValue, abi.encode(address(0x8888888)));
    }

    // address to bool tracker updates
    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToBool_Positive()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        vm.startSnapshotGas("MappedTrackerUpdatedFromEffects_AddressToBool");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertEq(updatedValue, abi.encode(true));
    }

    function testRulesEngine_Unit_MappedTrackerUpdatedFromEffects_AddressToBool_Negative()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
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
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // check that the tracker was updated from the effect
        bytes memory updatedValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertNotEq(updatedValue, abi.encode(false));
    }

    function testRulesEngine_Unit_MappedTrackerInstructionSetCompare_AddressToUint() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.UINT;
        tracker.trackerKeyType = ParamTypes.ADDR;
        tracker.mapped = true;
        string memory trackerName = "tracker1";

        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x1234567)); // key 1
        trackerKeys[1] = abi.encode(address(0x7654321)); // key 2

        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(1000); // value 1
        trackerValues[1] = abi.encode(2000); // value 2

        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.UINT, // placeHolderValueType
            ParamTypes.ADDR, // placeHolderValueType2
            ParamTypes.UINT, // trackerValueType
            0, // typespecific index 1
            1, // typespecific index 2
            trackerKeys,
            trackerValues,
            trackerName
        );

        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);
        assertEq(uint256(returnedTracker.trackerKeyType), uint256(ParamTypes.ADDR));

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(policyId, 1, abi.encode(address(0x1234567)));
        assertEq(value, abi.encode(1000));
        assertEq(trackerIndex, 1);

        bytes memory trackerValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(address(0x7654321))
        );
        assertEq(trackerValue, abi.encode(2000));

        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 1000);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        bytes memory arguments2 = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 2000);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);

        bytes memory arguments3 = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1000);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments3);
    }

    function testRulesEngine_Unit_MappedTrackerInstructionSetCompare_Bytes() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.ADDR;
        tracker.trackerKeyType = ParamTypes.BYTES;
        tracker.mapped = true;
        string memory trackerName = "king of the hill";

        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(bytes("king of the hill")); // key 1
        trackerKeys[1] = abi.encode(bytes("regular player")); // key 2

        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x1234567)); // value 1
        trackerValues[1] = abi.encode(address(0x7654321)); // value 2

        uint256 trackerIndex = _setupRuleWithMappedTracker(
            policyId,
            tracker,
            ParamTypes.BYTES, // placeHolderValueType
            ParamTypes.ADDR, // placeHolderValueType2
            ParamTypes.ADDR, // trackerValueType
            2, // typespecific index 1
            0, // typespecific index 2
            trackerKeys,
            trackerValues,
            trackerName
        );

        // validate tracker
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerIndex);
        assertTrue(returnedTracker.mapped);
        assertEq(uint256(returnedTracker.trackerKeyType), uint256(ParamTypes.BYTES));

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(bytes("king of the hill"))
        );
        assertEq(value, abi.encode(address(0x1234567)));
        assertEq(trackerIndex, 1);

        bytes memory trackerValue = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyId,
            1,
            abi.encode(bytes("regular player"))
        );
        assertEq(trackerValue, abi.encode(address(0x7654321)));

        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x1234567),
            2000,
            bytes("king of the hill")
        );
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        bytes memory arguments2 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            2000,
            bytes("regular player")
        );
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments2);

        bytes memory arguments3 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x7654321),
            2000,
            bytes("king of the hill")
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments3);

        bytes memory arguments4 = abi.encodeWithSelector(
            bytes4(keccak256(bytes(callingFunction))),
            address(0x1234567),
            2000,
            bytes("regular player")
        );
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments4);
    }

    function testRulesEngine_Integration_TrackerUpdate() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId = _createBlankPolicy();

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        _addCallingFunctionToPolicy(policyIds[0]);
        /// create tracker struct
        Trackers memory tracker;
        tracker.pType = ParamTypes.UINT;
        tracker.trackerValue = abi.encode(1);
        string memory trackerName = "tracker1";

        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, trackerName);
        Trackers memory tracker2;
        tracker2.pType = ParamTypes.UINT;
        tracker2.trackerValue = abi.encode(2);
        string memory trackerName2 = "tracker2";
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker2, trackerName2);

        ForeignCallTestContract foreignCallTestContract = new ForeignCallTestContract();
        ForeignCall memory foreignCall;
        foreignCall.signature = bytes4(keccak256(bytes("testSig(uint256,uint256)")));
        foreignCall.foreignCallAddress = address(foreignCallTestContract);
        foreignCall.returnType = ParamTypes.UINT;
        foreignCall.parameterTypes = new ParamTypes[](2);
        foreignCall.parameterTypes[0] = ParamTypes.UINT;
        foreignCall.parameterTypes[1] = ParamTypes.UINT;
        foreignCall.encodedIndices = new ForeignCallEncodedIndex[](2);
        foreignCall.encodedIndices[0].eType = EncodedIndexType.TRACKER;
        foreignCall.encodedIndices[0].index = 1;
        foreignCall.encodedIndices[1].eType = EncodedIndexType.TRACKER;
        foreignCall.encodedIndices[1].index = 2;

        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], foreignCall, "testSig");

        ForeignCall memory foreignCall2;
        foreignCall2.signature = bytes4(keccak256(bytes("testSig(uint256,uint256)")));
        foreignCall2.foreignCallAddress = address(foreignCallTestContract);
        foreignCall2.returnType = ParamTypes.UINT;
        foreignCall2.parameterTypes = new ParamTypes[](2);
        foreignCall2.parameterTypes[0] = ParamTypes.UINT;
        foreignCall2.parameterTypes[1] = ParamTypes.UINT;
        foreignCall2.encodedIndices = new ForeignCallEncodedIndex[](2);
        foreignCall2.encodedIndices[0].eType = EncodedIndexType.TRACKER;
        foreignCall2.encodedIndices[0].index = 1;
        foreignCall2.encodedIndices[1].eType = EncodedIndexType.TRACKER;
        foreignCall2.encodedIndices[1].index = 2;

        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], foreignCall2, "testSig2");

        Rule memory rule;
        // PLH 2, NUM 1234, EQ 0, 1, PLH 3, NUM 1234, EQ 4, 5, AND 3, 6
        rule.instructionSet = new uint256[](17);
        rule.instructionSet[0] = uint256(LogicalOp.PLH);
        rule.instructionSet[1] = uint256(2);
        rule.instructionSet[2] = uint256(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(1234);
        rule.instructionSet[4] = uint256(LogicalOp.EQ);
        rule.instructionSet[5] = uint256(0);
        rule.instructionSet[6] = uint256(1);
        rule.instructionSet[7] = uint256(LogicalOp.PLH);
        rule.instructionSet[8] = uint256(3);
        rule.instructionSet[9] = uint256(LogicalOp.NUM);
        rule.instructionSet[10] = uint256(1234);
        rule.instructionSet[11] = uint256(LogicalOp.EQ);
        rule.instructionSet[12] = uint256(4);
        rule.instructionSet[13] = uint256(5);
        rule.instructionSet[14] = uint256(LogicalOp.AND);
        rule.instructionSet[15] = uint256(3);
        rule.instructionSet[16] = uint256(6);

        rule.placeHolders = new Placeholder[](4);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[0].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 2;
        rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[2].pType = ParamTypes.UINT;
        rule.placeHolders[2].typeSpecificIndex = 1;
        rule.placeHolders[2].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[3].pType = ParamTypes.UINT;
        rule.placeHolders[3].typeSpecificIndex = 2;
        rule.placeHolders[3].flags = FLAG_FOREIGN_CALL;

        rule.effectPlaceHolders = new Placeholder[](4);
        rule.effectPlaceHolders[0].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[0].typeSpecificIndex = 1;
        rule.effectPlaceHolders[0].flags = FLAG_TRACKER_VALUE;
        rule.effectPlaceHolders[1].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[1].typeSpecificIndex = 2;
        rule.effectPlaceHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.effectPlaceHolders[2].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[2].typeSpecificIndex = 1;
        rule.effectPlaceHolders[2].flags = FLAG_FOREIGN_CALL;
        rule.effectPlaceHolders[3].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[3].typeSpecificIndex = 2;
        rule.effectPlaceHolders[3].flags = FLAG_FOREIGN_CALL;

        uint256[] memory negInstructionSet = new uint256[](14);
        negInstructionSet[0] = uint256(LogicalOp.NUM);
        negInstructionSet[1] = uint256(0);
        negInstructionSet[2] = uint256(LogicalOp.TRU);
        negInstructionSet[3] = uint256(1);
        negInstructionSet[4] = uint256(0);
        negInstructionSet[5] = uint256(TrackerTypes.MEMORY);
        negInstructionSet[6] = uint256(LogicalOp.NUM);
        negInstructionSet[7] = uint256(47);
        negInstructionSet[8] = uint256(LogicalOp.TRU);
        negInstructionSet[9] = uint256(2);
        negInstructionSet[10] = uint256(2);
        negInstructionSet[11] = uint256(TrackerTypes.MEMORY);
        negInstructionSet[12] = uint256(LogicalOp.PLH);
        negInstructionSet[13] = uint256(0);

        rule.negEffects = new Effect[](1);
        rule.negEffects[0].instructionSet = negInstructionSet;
        rule.negEffects[0].effectType = EffectTypes.EXPRESSION;
        rule.negEffects[0].valid = true;

        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_revert;
        rule.posEffects[0].valid = true;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        vm.stopPrank();

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x1234567), 1000);
        vm.startPrank(userContractAddress);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        bytes memory trackerValue = RulesEngineComponentFacet(address(red)).getTracker(policyIds[0], 1).trackerValue;
        assertEq(trackerValue, abi.encode(0));
        trackerValue = RulesEngineComponentFacet(address(red)).getTracker(policyIds[0], 2).trackerValue;
        assertEq(trackerValue, abi.encode(47));
    }
}
