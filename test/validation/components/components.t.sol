/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "lib/diamond-std/core/DiamondCut/DiamondCutFacet.sol";

abstract contract components is RulesEngineCommon {
    /**
     *
     *
     * Validation tests for components of rules and policies within the rules engine
     * Validate CRUD operations for Trackers, Foreign Calls and Calling Functions
     *
     */

    // CRUD Functions: Compnents

    // CRUD: Calling Functions
    //Create Calling Functions
    function testRulesEngine_Unit_createCallingFunction_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        uint256 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        assertEq(callingFunctionId, 1);
        CallingFunctionStorageSet memory sig = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId);
        assertEq(sig.set, true);
        assertEq(sig.signature, bytes4(keccak256(bytes(callingFunction))));
        assertEq(uint8(sig.parameterTypes[0]), uint8(ParamTypes.ADDR));
        assertEq(uint8(sig.parameterTypes[1]), uint8(ParamTypes.UINT));
    }

    function testRulesEngine_Unit_createCallingFunction_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        vm.startPrank(newPolicyAdmin);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(keccak256(bytes(callingFunction))),
            pTypes,
            callingFunction,
            ""
        );
    }

    function testRulesEngine_Unit_createCallingFunction_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
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
            ""
        );
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

    // Update Calling Functions
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
        RulesEngineComponentFacet(address(red)).updateCallingFunction(
            policyId,
            callingFunctionId,
            bytes4(keccak256(bytes(callingFunction))),
            pTypes2
        );
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
        RulesEngineComponentFacet(address(red)).updateCallingFunction(
            policyId,
            callingFunctionId,
            bytes4(keccak256(bytes(callingFunction))),
            pTypes2
        );
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
        RulesEngineComponentFacet(address(red)).updateCallingFunction(
            policyId,
            callingFunctionId,
            bytes4(keccak256(bytes(callingFunction2))),
            pTypes
        );
    }

    function testRulesEngine_Unit_updateCallingFunction_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        uint256 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        vm.startPrank(newPolicyAdmin);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).updateCallingFunction(
            policyId,
            callingFunctionId,
            bytes4(keccak256(bytes(callingFunction2))),
            pTypes
        );
    }

    function testRulesEngine_Unit_updateCallingFunctionWithRuleCheck_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
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

    function testRulesEngine_Unit_updateCallingFunctionWithRuleCheck_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        // create rule and set rule to user contract
        setUpRuleSimple();
        // test rule works for user contract

        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.transfer(address(0x7654321), 3);
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
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.transfer(address(0x7654321), 3);
        // test new contract rule check works
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.transfer(address(0x7654321), 3);
    }

    function testRulesEngine_Unit_updateCallingFunction_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        uint256 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        ParamTypes[] memory pTypes2 = new ParamTypes[](4);
        pTypes2[0] = ParamTypes.ADDR;
        pTypes2[1] = ParamTypes.UINT;
        pTypes2[2] = ParamTypes.ADDR;
        pTypes2[3] = ParamTypes.UINT;
        RulesEngineComponentFacet(address(red)).updateCallingFunction(
            policyId,
            callingFunctionId,
            bytes4(keccak256(bytes(callingFunction))),
            pTypes2
        );
        CallingFunctionStorageSet memory sig = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId);
        assertEq(sig.set, true);
        assertEq(sig.signature, bytes4(keccak256(bytes(callingFunction))));
        for (uint256 i = 0; i < pTypes2.length; i++) {
            assertEq(uint8(sig.parameterTypes[i]), uint8(pTypes2[i]));
        }
    }

    function testRulesEngine_Unit_updateCallingFunction_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
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
        RulesEngineComponentFacet(address(red)).updateCallingFunction(
            policyId,
            callingFunctionId,
            bytes4(keccak256(bytes(callingFunction))),
            pTypes2
        );
    }

    // Delete Calling Functions

    function testRulesEngine_Unit_deleteCallingFunction_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        uint256 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        assertEq(callingFunctionId, 1);
        CallingFunctionStorageSet memory matchingCallingFunction = RulesEngineComponentFacet(address(red)).getCallingFunction(
            policyId,
            callingFunctionId
        );
        assertEq(matchingCallingFunction.signature, bytes4(keccak256(bytes(callingFunction))));

        RulesEngineComponentFacet(address(red)).deleteCallingFunction(policyId, callingFunctionId);
        CallingFunctionStorageSet memory cf = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId);
        assertEq(cf.set, false);
        assertEq(cf.signature, bytes4(""));
    }

    function testRulesEngine_Unit_deleteCallingFunctionMultiple_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
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
        CallingFunctionStorageSet memory matchingCallingFunction = RulesEngineComponentFacet(address(red)).getCallingFunction(
            policyId,
            callingFunctionId
        );
        assertEq(matchingCallingFunction.signature, bytes4(keccak256(bytes(callingFunction))));

        CallingFunctionStorageSet memory matchingCallingFunction2 = RulesEngineComponentFacet(address(red)).getCallingFunction(
            policyId,
            callingFunctionId2
        );
        assertEq(matchingCallingFunction2.signature, bytes4(keccak256(bytes(callingFunction2))));

        RulesEngineComponentFacet(address(red)).deleteCallingFunction(policyId, callingFunctionId);
        CallingFunctionStorageSet memory cf = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId);
        assertEq(cf.set, false);
        assertEq(cf.signature, bytes4(""));

        CallingFunctionStorageSet memory matchingCallingFunction3 = RulesEngineComponentFacet(address(red)).getCallingFunction(
            policyId,
            callingFunctionId2
        );
        assertEq(matchingCallingFunction3.signature, bytes4(keccak256(bytes(callingFunction2))));

        //check that policy callingFunctions array is resized to 1
        (_callingFunctions, _callingFunctionIds, _ruleIds) = RulesEnginePolicyFacet(address(red)).getPolicy(policyId);
        assertEq(_callingFunctions.length, 1);
        assertEq(_callingFunctions[0], bytes4(keccak256(bytes(callingFunction2))));
    }

    function testRulesEngine_Unit_deleteCallingFunction_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
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

    function testRulesEngine_Unit_deleteCallingFunctionWithRuleCheck_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // create rule and set rule to user contract
        setupRuleWithoutForeignCall();
        // test rule works for user contract
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.transfer(address(0x7654321), 3);
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

    function testRulesEngine_Unit_deleteCallingFunction_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        uint256 callingFunctionId = _addCallingFunctionToPolicy(policyId);
        assertEq(callingFunctionId, 1);
        CallingFunctionStorageSet memory matchingCallingFunction = RulesEngineComponentFacet(address(red)).getCallingFunction(
            policyId,
            callingFunctionId
        );
        assertEq(matchingCallingFunction.signature, bytes4(keccak256(bytes(callingFunction))));

        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).deleteCallingFunction(policyId, callingFunctionId);
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

    // CRUD: Foreign Calls
    // Create Foreign Calls
    function testRulesEngine_Unit_CreateForeignCall_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankcallingFunctionIds,
            blankRuleIds,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);

        ForeignCall memory fc;
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256)");
    }

    function testRulesEngine_Unit_CreateForeignCall_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankcallingFunctionIds,
            blankRuleIds,
            PolicyType.OPEN_POLICY,
            policyName,
            policyDescription
        );

        ForeignCall memory fc;
        // prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256)");
    }

    function testRulesEngine_unit_CreateForeignCall_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        uint256 foreignCallId = 1;
        ForeignCall memory fc;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.UINT;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        vm.expectEmit(true, false, false, false);
        emit ForeignCallCreated(policyID, foreignCallId);
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyID, fc, "simpleCheck(uint256)");
    }

    // Update Foreign Calls
    function testRulesEngine_unit_UpdateForeignCall_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        ForeignCall memory fc;
        fc = _setUpForeignCallSimple(policyID);

        uint256 foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyID, fc, "simpleCheck(uint256)");
        fc.foreignCallAddress = address(userContractAddress);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyID);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineForeignCallFacet(address(red)).updateForeignCall(policyID, foreignCallId, fc);
    }

    function testRulesEngine_unit_UpdateForeignCall_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        ForeignCall memory fc;
        fc = _setUpForeignCallSimple(policyID);

        uint256 foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyID, fc, "simpleCheck(uint256)");
        fc.foreignCallAddress = address(userContractAddress);

        //Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineForeignCallFacet(address(red)).updateForeignCall(policyID, foreignCallId, fc);
    }

    // Delete Foreign Calls
    function testRulesEngine_Unit_DeleteForeignCall_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        uint256 policyId = _setup_checkRule_ForeignCall_Positive(ruleValue, userContractAddress);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineForeignCallFacet(address(red)).deleteForeignCall(policyId, 0);
    }

    function testRulesEngine_Unit_DeleteForeignCall_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        uint256 policyId = _setup_checkRule_ForeignCall_Positive(ruleValue, userContractAddress);
        vm.stopPrank();

        // prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineForeignCallFacet(address(red)).deleteForeignCall(policyId, 0);
    }

    // Get Foreign Calls
    function testRulesEngine_Unit_GetAllForeignCallsTest() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        for (uint256 i = 0; i < 10; i++) {
            _setUpForeignCallSimpleReturnID(policyId);
        }

        ForeignCall[] memory foreignCalls = RulesEngineForeignCallFacet(address(red)).getAllForeignCalls(policyId);
        assertEq(foreignCalls.length, 10);
        RulesEngineForeignCallFacet(address(red)).deleteForeignCall(policyId, 3);

        foreignCalls = RulesEngineForeignCallFacet(address(red)).getAllForeignCalls(policyId);
        assertEq(foreignCalls.length, 10);

        for (uint256 i = 0; i < foreignCalls.length - 1; i++) {
            if (i >= 2) {
                assertEq(foreignCalls[i].foreignCallIndex, i + 2);
            } else {
                assertEq(foreignCalls[i].foreignCallIndex, i + 1);
            }
        }
    }

    // CRUD: Trackers
    // Create Trackers
    function testRulesEngine_unit_CreateTracker_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
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

    function testRulesEngine_unit_CreateTracker_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = ParamTypes.ADDR;

        // Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");
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

    // Get Trackers
    function testRulesEngine_Unit_GetTrackerValue() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = setupRuleWithTracker(2);
        bool retVal = userContract.transfer(address(0x7654321), 3);
        assertTrue(retVal);
        Trackers memory testTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, 1);
        assertTrue(abi.decode(testTracker.trackerValue, (uint256)) == 2);
        assertFalse(abi.decode(testTracker.trackerValue, (uint256)) == 3);
    }

    function testRulesEngine_Unit_GetAllTrackersTest() public ifDeploymentTestsEnabled endWithStopPrank {
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

    // Update Trackers
    function testRulesEngine_unit_UpdateTracker_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = ParamTypes.ADDR;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");
        tracker.trackerValue = abi.encode(address(userContractAddress));
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyID);

        // Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).updateTracker(policyID, trackerId, tracker);
    }

    function testRulesEngine_unit_UpdateTracker_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = ParamTypes.ADDR;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");
        tracker.trackerValue = abi.encode(address(userContractAddress));

        // Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).updateTracker(policyID, trackerId, tracker);
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

    // Delete Trackers
    function testRulesEngine_unit_DeleteTracker_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
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

    function testRulesEngine_unit_DeleteTracker_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = ParamTypes.ADDR;
        uint256 trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");

        // Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).deleteTracker(policyID, trackerId);
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

    function testRulesEngine_unit_RED_Non_Upgradable() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);

        // Get all current facet addresses to verify diamond state
        address[] memory facetAddresses = DiamondLoupeFacet(address(red)).facetAddresses();

        // Verify diamondCut function selector is NOT present in any facet
        bool diamondCutFound = false;
        bytes4 diamondCutSelector = DiamondCutFacet.diamondCut.selector;

        for (uint256 i = 0; i < facetAddresses.length; i++) {
            bytes4[] memory selectors = DiamondLoupeFacet(address(red)).facetFunctionSelectors(facetAddresses[i]);
            for (uint256 j = 0; j < selectors.length; j++) {
                if (selectors[j] == diamondCutSelector) {
                    diamondCutFound = true;
                    break;
                }
            }
            if (diamondCutFound) break;
        }

        //  Assert that diamondCut selector is not found
        assertFalse(diamondCutFound, "DiamondCut functionality should not be available");

        // Verify that calling diamondCut directly on the diamond reverts
        // Create dummy facet cut data for testing
        FacetCut[] memory cuts = new FacetCut[](1);
        cuts[0] = FacetCut({facetAddress: address(0x1337), action: FacetCutAction.Add, functionSelectors: new bytes4[](1)});
        cuts[0].functionSelectors[0] = bytes4(keccak256("dummyFunction()"));

        // Attempt to call diamondCut and expect it to fail
        vm.expectRevert("FunctionNotFound(0xc99346a4)");
        (bool success, ) = address(red).call(abi.encodeWithSelector(diamondCutSelector, cuts, address(0), ""));
        success; // This line is just to avoid compiler warning

        // Verify NativeFacet doesn't have diamondCut functionality
        // Check that NativeFacet only has DiamondLoupe and ERC173 functions
        address nativeFacetAddress = DiamondLoupeFacet(address(red)).facetAddress(DiamondLoupeFacet.facets.selector);

        bytes4[] memory nativeFacetSelectors = DiamondLoupeFacet(address(red)).facetFunctionSelectors(nativeFacetAddress);

        // Verify expected selectors are present (loupe + ownership)
        bool hasFacets = false;
        bool hasOwner = false;

        for (uint256 k = 0; k < nativeFacetSelectors.length; k++) {
            if (nativeFacetSelectors[k] == DiamondLoupeFacet.facets.selector) {
                hasFacets = true;
            }
            if (nativeFacetSelectors[k] == ERC173Facet.owner.selector) {
                hasOwner = true;
            }
            // Ensure no diamondCut selector
            assertFalse(nativeFacetSelectors[k] == diamondCutSelector, "NativeFacet should not have diamondCut functionality");
        }

        assertTrue(hasFacets, "NativeFacet should have diamond loupe functionality");
        assertTrue(hasOwner, "NativeFacet should have ownership functionality");

        vm.stopPrank();
    }

    function testRulesEngine_unit_RetreiveRuleMetadata_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        (uint256 policyId, uint256 ruleId) = setUpRuleSimple();
        RuleMetadata memory data = RulesEngineRuleFacet(address(red)).getRuleMetadata(policyId, ruleId);
        assertEq(data.ruleName, ruleName);
        assertEq(data.ruleDescription, ruleDescription);
    }

    function testRulesEngine_Unit_FC_PolicyAdmin_Interactions() public ifDeploymentTestsEnabled {
        // Tests that deleting a foreign call from one policy does not affect another policy's foreign calls
        // policy Admin 1 creates a policy with a foreign call
        uint256 policy1 = _createBlankPolicy();
        _setUpForeignCallSimpleReturnID(policy1);

        // Policy Admin 2 creates a policy with two foreign calls
        vm.stopPrank();
        vm.startPrank(address(0x12345678)); // Policy Admin 2
        uint256 policy2 = _createBlankPolicy();
        _setUpForeignCallSimpleReturnID(policy2);
        _setUpForeignCallSimpleReturnID(policy2);

        // Policy Admin 1 deletes FC
        vm.stopPrank();
        vm.startPrank(policyAdmin); // Policy Admin 1
        RulesEngineForeignCallFacet(address(red)).deleteForeignCall(policy1, 1);

        // ensure only that policy 1 is the only one deleted
        ForeignCall[] memory foreignCalls = RulesEngineForeignCallFacet(address(red)).getAllForeignCalls(policy2);
        assertEq(foreignCalls.length, 2);
    }
}
