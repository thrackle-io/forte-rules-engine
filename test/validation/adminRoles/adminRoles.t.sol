/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract adminRoles is RulesEngineCommon {
    /**
     *
     *
     * Validation tests for the admin roles within the rules engine
     *
     *
     */

    // Create, Renounce, Revoke Admin Roles: Policy Admin
    function testRulesEngine_unit_adminRoles_GeneratePolicyAdminRole_ThroughRulesEngine() public ifDeploymentTestsEnabled endWithStopPrank {
        // policy admin role bytes string for policy 0: 0x35f49fd04fdc3104e07cf8040d0ede098e2a5ac11af26093ebea3a88e5ef9e2c
        vm.startPrank(policyAdmin);
        _createBlankPolicyWithAdminRoleString();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(1, policyAdmin);
        assertTrue(hasAdminRole);
    }

    function testRulesEngine_unit_adminRoles_GeneratePolicyAdminRole_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, newPolicyAdmin);
        assertFalse(hasAdminRole);
        vm.expectRevert("Not Policy Admin");
        RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(newPolicyAdmin, policyID);
    }

    function testRulesEngine_unit_adminRoles_ProposePolicyAdminRoleZeroAddress_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicyWithAdminRoleString();
        vm.expectRevert("Zero Address Cannot Be Admin");
        RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(address(0x00), policyID);
    }

    function testRulesEngine_unit_adminRoles_GrantPolicyAdmin_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicyWithAdminRoleString();
        bytes32 roleTag = bytes32(
            abi.encodePacked(keccak256(bytes(string.concat(string(abi.encode(policyID)), string(abi.encode("Policy_Admin"))))))
        );
        vm.expectRevert("Function disabled");
        RulesEngineAdminRolesFacet(address(red)).grantRole(roleTag, user1);
    }

    function testRulesEngine_unit_adminRoles_ProposedPolicyAdminRole_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
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

    function testRulesEngine_unit_adminRoles_ProposedPolicyAdminRole_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicyWithAdminRoleString();
        RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(newPolicyAdmin, policyID);
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        vm.expectRevert("Not Policy Admin");
        RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(newPolicyAdmin, policyID);
    }

    function testRulesEngine_unit_adminRoles_RevokePolicyAdminRole_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicyWithAdminRoleString();
        bytes32 adminRole = bytes32(abi.encodePacked(keccak256(bytes(string.concat(string(abi.encode(1)), "TestString")))));
        vm.expectRevert("Below Min Admin Threshold");
        RulesEngineAdminRolesFacet(address(red)).revokeRole(adminRole, policyAdmin, policyId);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(1, policyAdmin);
        assertTrue(hasAdminRole);
    }

    function testRulesEngine_unit_adminRoles_RenouncePolicyAdminRole_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicyWithAdminRoleString();
        bytes32 adminRole = bytes32(abi.encodePacked(keccak256(bytes(string.concat(string(abi.encode(1)), "TestString")))));
        vm.expectRevert("Below Min Admin Threshold");
        RulesEngineAdminRolesFacet(address(red)).renounceRole(adminRole, policyAdmin, policyId);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(1, policyAdmin);
        assertTrue(hasAdminRole);
    }

    // Create, Renounce, Revoke Admin Roles: Calling Contract Admin
    function testRulesEngine_Unit_CreateCallingContractAdmin_ThroughCallingContract_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.expectEmit(true, true, false, false);
        emit CallingContractAdminRoleGranted(newUserContractAddress, callingContractAdmin);
        newUserContract.setCallingContractAdmin(callingContractAdmin);
        assertTrue(RulesEngineAdminRolesFacet(address(red)).isCallingContractAdmin(newUserContractAddress, callingContractAdmin));
    }

    function testRulesEngine_Unit_CreateCallingContractAdmin_ThroughCallingContract_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
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

    function testRulesEngine_Unit_Confirm_CallingContractAdmin_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        newUserContract.setCallingContractAdmin(callingContractAdmin);
        assertTrue(RulesEngineAdminRolesFacet(address(red)).isCallingContractAdmin(newUserContractAddress, callingContractAdmin));
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEngineAdminRolesFacet(address(red)).proposeNewCallingContractAdmin(newUserContractAddress, user1);
        vm.stopPrank();
        vm.startPrank(user1);
        // This expected error is due to getRoleMember - the argument address doesnt exist in _roleMembers
        vm.expectRevert("panic: array out-of-bounds access (0x32)");
        // Confirm with a non-proposed address
        RulesEngineAdminRolesFacet(address(red)).confirmNewCallingContractAdmin(address(0x1337));
    }

    function testRulesEngine_Unit_ProposeAndConfirm_CallingContractAdmin_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        newUserContract.setCallingContractAdmin(callingContractAdmin);
        assertTrue(RulesEngineAdminRolesFacet(address(red)).isCallingContractAdmin(newUserContractAddress, callingContractAdmin));
        vm.stopPrank();
        vm.startPrank(user1);
        vm.expectRevert("Not Calling Contract Admin");
        RulesEngineAdminRolesFacet(address(red)).proposeNewCallingContractAdmin(newUserContractAddress, user1);
    }

    function testRulesEngine_Unit_ProposeAndConfirm_CallingContractAdminZeroAddress_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.expectRevert("Zero Address Cannot Be Admin");
        newUserContract.setCallingContractAdmin(address(0x00));
    }

    function testRulesEngine_Unit_CreateCallingContractAdmin_ThroughEngineOwnable_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
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

    function testRulesEngine_Unit_CreateCallingContractAdmin_ThroughEngineOwnable_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        ExampleUserOwnableContract ownableUserContract = new ExampleUserOwnableContract(policyAdmin);
        address ownableUserContractAddress = address(ownableUserContract);
        ownableUserContract.setRulesEngineAddress(address(red));
        vm.expectRevert("Calling Contract Admin Role Not Granted From Calling Contract");
        RulesEngineAdminRolesFacet(address(red)).grantCallingContractRoleOwnable(ownableUserContractAddress, callingContractAdmin);
        assertFalse(RulesEngineAdminRolesFacet(address(red)).isCallingContractAdmin(ownableUserContractAddress, callingContractAdmin));
    }

    function testRulesEngine_Unit_CreateCallingContractAdmin_ThroughEngine_NonSupportedType_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        ExampleUserOwnableContract ownableUserContract = new ExampleUserOwnableContract(policyAdmin);
        address ownableUserContractAddress = address(ownableUserContract);
        ownableUserContract.setRulesEngineAddress(address(red));
        vm.expectRevert(); // results in evmError: revert since the function is not inside contract
        RulesEngineAdminRolesFacet(address(red)).grantCallingContractRoleAccessControl(ownableUserContractAddress, callingContractAdmin);
        assertFalse(RulesEngineAdminRolesFacet(address(red)).isCallingContractAdmin(ownableUserContractAddress, callingContractAdmin));
    }

    function testRulesEngine_Unit_CreateCallingContractAdmin_ThroughEngineAccessControl_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
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

    function testRulesEngine_Unit_CreateCallingContractAdmin_ThroughEngineAccessControl_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        ExampleUserAccessControl acUserContract = new ExampleUserAccessControl(policyAdmin);
        address acUserContractAddress = address(acUserContract);
        acUserContract.setRulesEngineAddress(address(red));
        vm.expectRevert("Calling Contract Admin Role Not Granted From Calling Contract");
        RulesEngineAdminRolesFacet(address(red)).grantCallingContractRoleAccessControl(acUserContractAddress, callingContractAdmin);
        assertFalse(RulesEngineAdminRolesFacet(address(red)).isCallingContractAdmin(acUserContractAddress, callingContractAdmin));
    }

    // Rules Engine CRUD Functions

    // CRUD: Trackers
    function testRulesEngine_unit_adminRoles_CreateTracker_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        Trackers memory tracker;
        tracker.trackerValue = abi.encode(address(testContract));
        tracker.pType = ParamTypes.ADDR;

        RulesEngineComponentFacet(address(red)).createTracker(policyID, tracker, "trName");
    }

    function testRulesEngine_unit_adminRoles_CreateTracker_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
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

    function testRulesEngine_unit_adminRoles_UpdateTracker_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
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

    function testRulesEngine_unit_adminRoles_UpdateTracker_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
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

    function testRulesEngine_unit_adminRoles_DeleteTracker_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
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

    function testRulesEngine_unit_adminRoles_DeleteTracker_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
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

    // CRUD: Foreign Calls
    function testRulesEngine_unit_adminRoles_CreateForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        _setUpForeignCallSimple(policyID);
    }

    function testRulesEngine_unit_adminRoles_CreateForeignCall_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, newPolicyAdmin);
        assertFalse(hasAdminRole);

        vm.expectRevert("Not Authorized To Policy");
        _setUpForeignCallSimple(policyID);
    }

    function testRulesEngine_unit_adminRoles_UpdateForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);
        ForeignCall memory fc;
        fc = _setUpForeignCallSimple(policyID);

        uint256 foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyID, fc, "simpleCheck(uint256)");
        fc.foreignCallAddress = address(userContractAddress);
        RulesEngineForeignCallFacet(address(red)).updateForeignCall(policyID, foreignCallId, fc);
    }

    function testRulesEngine_unit_adminRoles_UpdateForeignCall_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
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
        RulesEngineForeignCallFacet(address(red)).updateForeignCall(policyID, foreignCallId, fc);
    }

    function testRulesEngine_unit_adminRoles_DeleteForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        uint256 foreignCallId;
        bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(policyID, policyAdmin);
        assertTrue(hasAdminRole);

        ForeignCall memory fc;
        (fc, foreignCallId) = _setUpForeignCallSimpleReturnID(policyID);
        RulesEngineForeignCallFacet(address(red)).deleteForeignCall(policyID, foreignCallId);

        ForeignCall memory fc2 = RulesEngineForeignCallFacet(address(red)).getForeignCall(policyID, foreignCallId);
        assertEq(fc2.set, false);
        assertEq(fc2.foreignCallAddress, address(0));
        assertEq(fc2.signature, bytes4(0));
        assertEq(fc2.parameterTypes.length, 0);
        assertEq(fc2.encodedIndices.length, 0);
        assertEq(uint8(fc2.returnType), uint8(ParamTypes.ADDR));
        assertEq(fc2.foreignCallIndex, 0);
    }

    function testRulesEngine_unit_adminRoles_DeleteForeignCall_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
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
        RulesEngineForeignCallFacet(address(red)).deleteForeignCall(policyID, foreignCallId);
    }

    function testRulesEngine_unit_adminRoles_UpdateForeignCall_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        ForeignCall memory fc;
        fc = _setUpForeignCallSimple(policyID);
        uint256 foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyID, fc, "simpleCheck(uint256)");
        fc.foreignCallAddress = address(userContractAddress);
        vm.expectEmit(true, false, false, false);
        emit ForeignCallUpdated(policyID, foreignCallId);
        RulesEngineForeignCallFacet(address(red)).updateForeignCall(policyID, foreignCallId, fc);
    }

    function testRulesEngine_unit_adminRoles_DeleteForeignCall_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyID = _createBlankPolicy();
        uint256 foreignCallId;
        ForeignCall memory fc;
        (fc, foreignCallId) = _setUpForeignCallSimpleReturnID(policyID);
        vm.expectEmit(true, false, false, false);
        emit ForeignCallDeleted(policyID, foreignCallId);
        RulesEngineForeignCallFacet(address(red)).deleteForeignCall(policyID, foreignCallId);
    }

    // CRUD: Rules
    function testRulesEngine_Unit_UpdateRule_NotPolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyId = setupEffectWithTrackerUpdateUint();
        Rule memory rule;
        // Change to non policy admin user
        vm.startPrank(user1);
        vm.expectRevert("Not Authorized To Policy");
        // Attempt to Save the rule
        RulesEngineRuleFacet(address(red)).updateRule(policyId, 0, rule, ruleName, ruleDescription);
    }

    function testRulesEngine_Uint_GrantCallingContractRole() public ifDeploymentTestsEnabled {
        vm.startPrank(address(0x1337));
        vm.expectRevert("Only Calling Contract Can Create Admin");
        RulesEngineAdminRolesFacet(address(red)).grantCallingContractRole(address(0x1337), callingContractAdmin);
    }

    function testRulesEngine_Uint_GrantForeignCallAdminRole_ZeroAddress_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        vm.expectRevert("Zero Address Cannot Be Admin");
        RulesEngineAdminRolesFacet(address(red)).grantForeignCallAdminRole(pfcContractAddress, address(0x00), foreignCallSelector);
    }

    function testRulesEngine_Unit_ForeignCallAdmin_ListMagangement() public ifDeploymentTestsEnabled {
        /**
        // For a given Foreign contract and selector pair, the Foreign Call Admin 
        is the only one who can configure which Policy Admins may leverage the Foreign Call in their policies
        */

        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);
        assertTrue(
            RulesEngineAdminRolesFacet(address(red)).isForeignCallAdmin(
                address(permissionedForeignCallContract),
                address(0x55556666),
                foreignCallSelector
            )
        );

        // add second foreign call admin with different sig
        vm.stopPrank();
        vm.startPrank(address(0x66667777));
        bytes4 foreignCallSelector2 = PermissionedForeignCallTestContract.square.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x66667777), foreignCallSelector2);
        assertTrue(
            RulesEngineAdminRolesFacet(address(red)).isForeignCallAdmin(
                address(permissionedForeignCallContract),
                address(0x66667777),
                foreignCallSelector2
            )
        );

        // ensure only the FC admin can congifure list of policy admins
        vm.stopPrank();
        vm.startPrank(address(0x55556666));
        vm.expectRevert("Not An Authorized Foreign Call Admin");
        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(0x66666666), foreignCallSelector2);

        // check that the other admin cannot apply to the first foreign call selector
        vm.stopPrank();
        vm.startPrank(address(0x66667777));
        vm.expectRevert("Not An Authorized Foreign Call Admin");
        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(0x66666666), foreignCallSelector);

        // add policy admin to the permission list for the first foreign call selector
        vm.stopPrank();
        vm.startPrank(address(0x55556666));
        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(0x66666666), foreignCallSelector);
        // check that they cannot add another admin to the permission list
        vm.stopPrank();
        vm.startPrank(address(0x66666666));
        vm.expectRevert("Not An Authorized Foreign Call Admin");
        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(0x66667777), foreignCallSelector);
    }
}
