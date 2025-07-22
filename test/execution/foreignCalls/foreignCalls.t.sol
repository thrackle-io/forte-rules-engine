/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract foreignCalls is RulesEngineCommon {
    /**
     *
     *
     * Execution tests for foreign calls within the rules engine
     *
     *
     */
    function testRulesEngine_Unit_checkRule_ForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        _setup_checkRule_ForeignCall_Positive(ruleValue, userContractAddress);
        vm.startSnapshotGas("checkRule_ForeignCall");
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        bool response = userContract.transfer(address(0x7654321), transferValue);
        vm.stopSnapshotGas();
        assertTrue(response);
    }

    function testRulesEngine_Unit_checkRule_ForeignCall_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        // change values in order to violate rule
        ruleValue = 15;
        transferValue = 10;
        _setup_checkRule_ForeignCall_Negative(ruleValue, userContractAddress);
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.transfer(address(0x7654321), transferValue);
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithForeignCallNegative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCall(4, EffectTypes.REVERT, false);
        vm.startPrank(address(userContract));
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 3);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_createRule_ForeignCall_TrackerValuesUsed_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCallSquaringReferencedTrackerVals(2, EffectTypes.REVERT, false); // rule's lower limit is 2
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 3);
        vm.startSnapshotGas("checkRule_ForeignCall_TrackerValuesUsed");
        vm.startPrank(address(userContract));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_createRule_ForeignCall_TrackerValuesUsed_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCallSquaringReferencedTrackerVals(0, EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 3);
        vm.startPrank(address(userContract));
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_createRule_ForeignCall_ForeignCallReferenced_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCallWithSquaredFCValues(EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 2); // rule's lower limit is 2
        vm.startSnapshotGas("checkRule_ForeignCall_ForeignCallReferenced");
        vm.startPrank(address(userContract));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_createRule_ForeignCall_ForeignCallReferenced_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCallWithSquaredFCValues(EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 0);
        vm.startPrank(address(userContract));
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithForeignCall_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCall(4, EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 1);
        vm.startPrank(address(userContract));
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithForeignCallEffect() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCall(4, EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.startPrank(address(userContract));
        // The Foreign call will be placed during the effect for the single rule in this policy.
        // The value being set in the foreign contract is then polled to verify that it has been udpated.
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        assertEq(testContract.getInternalValue(), 5);
    }

    function testRulesEngine_Unit_ForeignCall_Bytes() public ifDeploymentTestsEnabled resetsGlobalVariables {
        vm.skip(true);
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
                ForeignCall memory fc;
                fc.encodedIndices = new ForeignCallEncodedIndex[](1);
                fc.encodedIndices[0].index = 0;
                fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
                fc.foreignCallAddress = foreignCallTarget;
                fc.signature = setMsgDataSelector;
                fc.returnType = ParamTypes.BOOL;
                fc.parameterTypes = fcParamTypes;
                foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "setMsgData(bytes)");
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

            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);

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
                    PolicyType.CLOSED_POLICY,
                    policyName,
                    policyDescription
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
                ExampleUserContract.transferFrom.selector,
                to,
                value,
                abi.encode("TESTER")
            );

            vm.startSnapshotGas("checkRule_ForeignCall_Bytes");
            RulesEngineProcessorFacet(address(red)).checkPolicies(transferCalldata);
            vm.stopSnapshotGas();

            bytes memory actualMsgData = ExampleUserContract(userContractAddress).msgData();
            assertEq(actualMsgData, transferCalldata, "Foreign call should set msgData to the transfer calldata");
            vm.stopPrank();
        }
    }

    function testRulesEngine_Unit_ForeignCall_MappedTrackerAsParam_MultipleMappedTrackerKeys_Positive() public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables {
        uint256 policyId;
        uint256 ruleId;
        uint256 callingFunctionId;

        {
            vm.startPrank(policyAdmin);

            policyId = _createBlankPolicy();

            ParamTypes[] memory fcArgs = new ParamTypes[](5);
            fcArgs[0] = ParamTypes.UINT;
            fcArgs[1] = ParamTypes.STR;
            fcArgs[2] = ParamTypes.UINT;
            fcArgs[3] = ParamTypes.STR;
            fcArgs[4] = ParamTypes.ADDR;

            uint256 foreignCallId;
            {
                ForeignCall memory fc;
                fc.encodedIndices = new ForeignCallEncodedIndex[](5);
                fc.encodedIndices[0].index = 1;
                fc.encodedIndices[0].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
                fc.encodedIndices[1].index = 1;
                fc.encodedIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
                fc.encodedIndices[2].index = 1;
                fc.encodedIndices[2].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
                fc.encodedIndices[3].index = 3;
                fc.encodedIndices[3].eType = EncodedIndexType.ENCODED_VALUES;
                fc.encodedIndices[4].index = 2;
                fc.encodedIndices[4].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
                fc.mappedTrackerKeyIndices = new ForeignCallEncodedIndex[](2);
                fc.mappedTrackerKeyIndices[0].index = 0;
                fc.mappedTrackerKeyIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
                fc.mappedTrackerKeyIndices[1].index = 2;
                fc.mappedTrackerKeyIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
                fc.mappedTrackerKeyIndices[2].index = 4;
                fc.mappedTrackerKeyIndices[2].eType = EncodedIndexType.ENCODED_VALUES;
                fc.foreignCallAddress = address(pfcContractAddress);
                fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256,string,uint256,string,address)")));
                fc.returnType = ParamTypes.UINT;
                fc.parameterTypes = fcArgs;
                foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256,string,uint256,string,address)");
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
                RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, selectors, functionIds, ruleIdsArr, PolicyType.CLOSED_POLICY);
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
                ExampleUserContract.transferFrom.selector,
                to,
                value,
                abi.encode("TESTER")
            );

            vm.startSnapshotGas("checkRule_ForeignCall_Bytes");
            RulesEngineProcessorFacet(address(red)).checkPolicies(transferCalldata);
            vm.stopSnapshotGas();

            bytes memory actualMsgData = ExampleUserContract(userContractAddress).msgData();
            assertEq(actualMsgData, transferCalldata, "Foreign call should set msgData to the transfer calldata");
            vm.stopPrank();
        }
    }

    /////////////////////////////////////////////////////////////////////////
    // PERMISSIONED FOREIGN CALL TESTS
    ////////////////////////////////////////////////////////////////////////

    function testRulesEngine_Unit_PermissionedForeignCall_SetAdmin_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
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
    }

    function testRulesEngine_Unit_PermissionedForeignCall_SetAdmin_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);
        assertFalse(
            RulesEngineAdminRolesFacet(address(red)).isForeignCallAdmin(
                address(permissionedForeignCallContract),
                address(0x6666666),
                foreignCallSelector
            )
        );
    }

    function testRulesEngine_Unit_PermissionedForeignCall_SetAdminByCallingFacetDirectly_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        vm.expectRevert("Only Foreign Call Contract Can Create Admin Role");
        RulesEngineAdminRolesFacet(address(red)).grantForeignCallAdminRole(pfcContractAddress, address(0x55556666), foreignCallSelector);
    }

    function testRulesEngine_Unit_PermissionedForeignCall_AddAdminsToList_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
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

        // add multiple admins to the permissions list
        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(0x66666666), foreignCallSelector);
        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(0x77777777), foreignCallSelector);
        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(0x88888888), foreignCallSelector);

        address[] memory pfcStorage = RulesEngineForeignCallFacet(address(red)).getForeignCallPermissionList(
            pfcContractAddress,
            foreignCallSelector
        );
        assertTrue(pfcStorage.length == 4, "There should be four permissioned foreign call admins");
    }

    function testRulesEngine_Unit_PermissionedForeignCall_AddAdminsToList_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        bytes4 foreignCallSelector2 = PermissionedForeignCallTestContract.square.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);
        assertTrue(
            RulesEngineAdminRolesFacet(address(red)).isForeignCallAdmin(
                address(permissionedForeignCallContract),
                address(0x55556666),
                foreignCallSelector
            )
        );

        vm.expectRevert("Not An Authorized Foreign Call Admin");
        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(0x66666666), foreignCallSelector2);

        address[] memory pfcStorage = RulesEngineForeignCallFacet(address(red)).getForeignCallPermissionList(
            pfcContractAddress,
            foreignCallSelector
        );
        assertTrue(pfcStorage.length == 1, "There should be one permissioned foreign call admins");
    }

    function testRulesEngine_Unit_PermissionedForeignCall_RemoveForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);

        // add multiple foreign calls to the master list
        bytes4 foreignCallSelector2 = PermissionedForeignCallTestContract.square.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector2);
        bytes4 foreignCallSelector3 = PermissionedForeignCallTestContract.getInternalValue.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector3);

        PermissionedForeignCallStorage memory pfcStorage = RulesEngineForeignCallFacet(address(red)).getAllPermissionedFCs();
        assertEq(pfcStorage.permissionedForeignCallAddresses.length, 3, "There should be three permissioned foreign calls");
        assertEq(pfcStorage.permissionedForeignCallSignatures.length, 3, "There should be three permissioned foreign call signatures");

        // remove the foreign call from the master list
        RulesEngineForeignCallFacet(address(red)).removeForeignCallPermissions(pfcContractAddress, foreignCallSelector2);
        pfcStorage = RulesEngineForeignCallFacet(address(red)).getAllPermissionedFCs();
        assertEq(pfcStorage.permissionedForeignCallAddresses.length, 2, "There should be two permissioned foreign calls");
        assertEq(pfcStorage.permissionedForeignCallSignatures.length, 2, "There should be two permissioned foreign call signatures");
        // check that the foreign call is no longer in the master list
        assertEq(
            pfcStorage.permissionedForeignCallSignatures[0],
            foreignCallSelector,
            "The first foreign call signature should be the simpleCheck"
        );
        assertEq(
            pfcStorage.permissionedForeignCallSignatures[1],
            foreignCallSelector3,
            "The second foreign call signature should be the getInternalValue"
        );
    }

    function testRulesEngine_Unit_PermissionedForeignCall_GetAllForeignCalls_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);

        // add multiple foreign calls to the master list
        bytes4 foreignCallSelector2 = PermissionedForeignCallTestContract.square.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector2);
        bytes4 foreignCallSelector3 = PermissionedForeignCallTestContract.getInternalValue.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector3);

        PermissionedForeignCallStorage memory pfcStorage = RulesEngineForeignCallFacet(address(red)).getAllPermissionedFCs();
        assertEq(pfcStorage.permissionedForeignCallAddresses.length, 3, "There should be three permissioned foreign calls");
        assertEq(pfcStorage.permissionedForeignCallSignatures.length, 3, "There should be three permissioned foreign call signatures");
    }

    function testRulesEngine_Unit_PermissionedForeignCall_AddPermissionedFCToPolicy_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
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

        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(policyAdmin), foreignCallSelector);

        vm.stopPrank();
        vm.startPrank(policyAdmin);
        // add the permissioned foreign call to the policy
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(pfcContractAddress);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256)");
    }

    function testRulesEngine_Unit_PermissionedForeignCall_AddPermissionedFCToPolicy_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
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

        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(
            pfcContractAddress,
            address(address(0x66666666)),
            foreignCallSelector
        );

        vm.stopPrank();
        vm.startPrank(policyAdmin);
        // add the permissioned foreign call to the policy
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(pfcContractAddress);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        vm.expectRevert("Not Permissioned For Foreign Call");
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256)");
    }

    function testRulesEngine_Unit_PermissionedForeignCall_UpdatePermissionedFC_NewPolicyAdmin_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
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

        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(policyAdmin), foreignCallSelector);

        vm.stopPrank();
        vm.startPrank(policyAdmin);
        // add the permissioned foreign call to the policy
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(pfcContractAddress);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256)");

        // transfer policyAdmin role to new, non permissioned address and test update fails as expected
        RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(newPolicyAdmin, policyId);
        vm.stopPrank();
        vm.startPrank(newPolicyAdmin);
        RulesEngineAdminRolesFacet(address(red)).confirmNewPolicyAdmin(policyId);

        vm.expectRevert("Not Permissioned For Foreign Call");
        RulesEngineForeignCallFacet(address(red)).updateForeignCall(
            policyId,
            0, // foreign call index
            fc
        );
    }

    function testRulesEngine_Unit_PermissionedForeignCall_removeAll_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
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

        // add multiple admins to the permissions list
        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(0x66666666), foreignCallSelector);
        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(0x77777777), foreignCallSelector);
        RulesEngineForeignCallFacet(address(red)).addAdminToPermissionList(pfcContractAddress, address(0x88888888), foreignCallSelector);
        RulesEngineForeignCallFacet(address(red)).removeAllFromPermissionList(pfcContractAddress, foreignCallSelector);
        address[] memory pfcStorage = RulesEngineForeignCallFacet(address(red)).getForeignCallPermissionList(
            pfcContractAddress,
            foreignCallSelector
        );
        assertTrue(pfcStorage.length == 1, "There should be only be the original foreign call admin");
    }

    function testRulesEngine_Unit_PermissionedForeignCall_removeAllWithOnlyOneAdmin_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
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

        // test remove with only one admin
        RulesEngineForeignCallFacet(address(red)).removeAllFromPermissionList(pfcContractAddress, foreignCallSelector);
        address[] memory pfcStorage = RulesEngineForeignCallFacet(address(red)).getForeignCallPermissionList(
            pfcContractAddress,
            foreignCallSelector
        );
        assertTrue(pfcStorage.length == 1, "There should be only be the original foreign call admin");
    }

    function testRulesEngine_Unit_PermissionedForeignCall_removeAll_AddToPolicyAfterRemoval_Positive()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // start test as address 0x55556666
        vm.startPrank(address(0x55556666));
        // set the selector from the permissioned foreign call contract
        bytes4 foreignCallSelector = PermissionedForeignCallTestContract.simpleCheck.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector);

        // add multiple foreign calls to the master list
        bytes4 foreignCallSelector2 = PermissionedForeignCallTestContract.square.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector2);
        bytes4 foreignCallSelector3 = PermissionedForeignCallTestContract.getInternalValue.selector;
        permissionedForeignCallContract.setForeignCallAdmin(address(0x55556666), foreignCallSelector3);

        PermissionedForeignCallStorage memory pfcStorage = RulesEngineForeignCallFacet(address(red)).getAllPermissionedFCs();
        assertEq(pfcStorage.permissionedForeignCallAddresses.length, 3, "There should be three permissioned foreign calls");
        assertEq(pfcStorage.permissionedForeignCallSignatures.length, 3, "There should be three permissioned foreign call signatures");

        // remove the foreign call from the master list
        RulesEngineForeignCallFacet(address(red)).removeForeignCallPermissions(pfcContractAddress, foreignCallSelector2);
        pfcStorage = RulesEngineForeignCallFacet(address(red)).getAllPermissionedFCs();
        assertEq(pfcStorage.permissionedForeignCallAddresses.length, 2, "There should be two permissioned foreign calls");
        assertEq(pfcStorage.permissionedForeignCallSignatures.length, 2, "There should be two permissioned foreign call signatures");
        // check that the foreign call is no longer in the master list
        assertEq(
            pfcStorage.permissionedForeignCallSignatures[0],
            foreignCallSelector,
            "The first foreign call signature should be the simpleCheck"
        );
        assertEq(
            pfcStorage.permissionedForeignCallSignatures[1],
            foreignCallSelector3,
            "The second foreign call signature should be the getInternalValue"
        );

        // now add the non permissioned FC to a policy
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(pfcContractAddress);
        fc.signature = bytes4(keccak256(bytes("square(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "square(uint256)");
    }

    function testRulesEngine_Unit_ForeignCall_MappedTrackerAsParam_UintToUintMappedTracker()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create policy
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        _addCallingFunctionToPolicy(policyIds[0]);
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1);
        trackerKeys[1] = abi.encode(2);
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(1000000000);
        trackerValues[1] = abi.encode(2000000000);
        Rule memory rule;
        ForeignCall memory fc;
        (rule, fc) = _createForeignCallUsingMappedTrackerValueRule(
            policyIds,
            ParamTypes.UINT,
            ParamTypes.UINT,
            trackerKeys,
            trackerValues,
            1,
            2000000000
        );
        _createForeignCallUsingMappedTrackerValueHelper(rule, policyIds, fc, EffectTypes.REVERT, false);
        vm.expectRevert();
        userContract.transfer(address(0x7654321), 1);

        userContract.transfer(address(0x7654321), 2);

        assertEq(testContract.getInternalValue(), 2000000000, "The internal value should be updated to 2000000000");
    }

    function testRulesEngine_Unit_ForeignCall_MappedTrackerAsParam_AddressToUintMappedTracker()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create policy
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        _addCallingFunctionToPolicy(policyIds[0]);
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(address(0x7654321));
        trackerKeys[1] = abi.encode(address(0x7654322));
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(1000000000);
        trackerValues[1] = abi.encode(2000000000);
        Rule memory rule;
        ForeignCall memory fc;
        (rule, fc) = _createForeignCallUsingMappedTrackerValueRule(
            policyIds,
            ParamTypes.UINT,
            ParamTypes.UINT,
            trackerKeys,
            trackerValues,
            0,
            2000000000
        );
        _createForeignCallUsingMappedTrackerValueHelper(rule, policyIds, fc, EffectTypes.REVERT, false);
        vm.expectRevert();
        userContract.transfer(address(0x7654321), 10);

        userContract.transfer(address(0x7654322), 15);

        assertEq(testContract.getInternalValue(), 2000000000, "The internal value should be updated to 2000000000");
    }

    function testRulesEngine_Unit_ForeignCall_MappedTrackerAsParam_UintToAddressMappedTracker()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create policy
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        _addCallingFunctionToPolicy(policyIds[0]);
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(1000000000);
        trackerKeys[1] = abi.encode(2000000000);
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x7654321));
        trackerValues[1] = abi.encode(address(0x7654322));
        Rule memory rule;
        ForeignCall memory fc;
        (rule, fc) = _createForeignCallUsingMappedTrackerValueRule(
            policyIds,
            ParamTypes.ADDR,
            ParamTypes.ADDR,
            trackerKeys,
            trackerValues,
            1,
            uint256(uint160(address(0x7654322)))
        );
        _createForeignCallUsingMappedTrackerValueHelper(rule, policyIds, fc, EffectTypes.REVERT, false);
        vm.expectRevert();
        userContract.transfer(address(0x7654321), 1000000000);

        userContract.transfer(address(0x7654322), 2000000000);

        assertEq(
            testContract.getInternalValue(),
            uint256(uint160(address(0x7654322))),
            "The internal value should be updated to the `to` address"
        );
    }

    function testRulesEngine_Unit_ForeignCall_MappedTrackerAsParam_Bytes32ToAddressMappedTracker()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // create policy
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](5);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.BYTES;
        pTypes[3] = ParamTypes.BOOL;
        pTypes[4] = ParamTypes.STR;
        _addCallingFunctionToPolicy(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes("transferFrom(address,uint256,bytes32)")))),
            pTypes,
            string("transferFom(address,uint256,bytes32)")
        );
        bytes[] memory trackerKeys = new bytes[](2);
        trackerKeys[0] = abi.encode(uint(bytes32("TestKey1")));
        trackerKeys[1] = abi.encode(uint(bytes32("TestKey2")));
        bytes[] memory trackerValues = new bytes[](2);
        trackerValues[0] = abi.encode(address(0x7654321));
        trackerValues[1] = abi.encode(address(0x7654322));
        Rule memory rule;
        ForeignCall memory fc;
        (rule, fc) = _createForeignCallUsingMappedTrackerValueRuleBytes32(
            policyIds,
            ParamTypes.ADDR,
            ParamTypes.BYTES,
            trackerKeys,
            trackerValues,
            2,
            uint256(uint160(address(0x7654322)))
        );
        _createForeignCallUsingMappedTrackerValueHelper(rule, policyIds, fc, EffectTypes.REVERT, false);
        // validate tracker exists
        Trackers memory returnedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyIds[0], 1);
        assertTrue(returnedTracker.mapped);

        bytes memory value = RulesEngineComponentFacet(address(red)).getMappedTrackerValue(
            policyIds[0],
            1,
            abi.encode(uint(bytes32("TestKey1")))
        );
        assertEq(value, abi.encode(address(0x7654321)));
        console2.log(uint256(bytes32("TestKey1")));

        vm.expectRevert();
        userContract.transferFrom(address(0x7654321), 1000000000, bytes32("TestKey1"));
        assertEq(testContract.getInternalValue(), 0);

        userContract.transferFrom(address(0x7654322), 2000000000, bytes32("TestKey2"));

        assertEq(
            testContract.getInternalValue(),
            uint256(uint160(address(0x7654322))),
            "The internal value should be updated to the `to` address"
        );
    }

    function testRulesEngine_Unit_ForeignCall_ValidateMappedTrackerKeyLengths_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // start test as address 0x55556666
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory fcArgs = new ParamTypes[](2);
        fcArgs[0] = ParamTypes.UINT;
        fcArgs[1] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
        fc.encodedIndices[1].index = 0;
        fc.encodedIndices[1].eType = EncodedIndexType.GLOBAL_VAR;
        fc.mappedTrackerKeyIndices = new ForeignCallEncodedIndex[](1);
        fc.mappedTrackerKeyIndices[0].index = 0;
        fc.mappedTrackerKeyIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(pfcContractAddress);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256,uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256,uint256)");
    }

    function testRulesEngine_Unit_ForeignCall_ValidateMappedTrackerKeyLengths_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        // start test as address 0x55556666
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory fcArgs = new ParamTypes[](2);
        fcArgs[0] = ParamTypes.UINT;
        fcArgs[1] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
        fc.encodedIndices[1].index = 1;
        fc.encodedIndices[1].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
        fc.mappedTrackerKeyIndices = new ForeignCallEncodedIndex[](1);
        fc.mappedTrackerKeyIndices[0].index = 0;
        fc.mappedTrackerKeyIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(pfcContractAddress);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256,uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        vm.expectRevert("Mapped tracker key indices length mismatch.");
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256,uint256)");
    }

    function testRulesEngine_Unit_ForeignCall_ValidateMappedTrackerKeyLengths_Negative_ExtraMappedTrackerKey()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // start test as address 0x55556666
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory fcArgs = new ParamTypes[](2);
        fcArgs[0] = ParamTypes.UINT;
        fcArgs[1] = ParamTypes.UINT;
        ForeignCall memory fc;

        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
        fc.encodedIndices[1].index = 0;
        fc.encodedIndices[1].eType = EncodedIndexType.GLOBAL_VAR;
        fc.mappedTrackerKeyIndices = new ForeignCallEncodedIndex[](2);
        fc.mappedTrackerKeyIndices[0].index = 0;
        fc.mappedTrackerKeyIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.mappedTrackerKeyIndices[1].index = 1;
        fc.mappedTrackerKeyIndices[1].eType = EncodedIndexType.ENCODED_VALUES;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(pfcContractAddress);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256,uint256)")));

        vm.expectRevert("Mapped tracker key indices length mismatch.");
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256,uint256)");
    }

    function testRulesEngine_Unit_ForeignCall_ValidateMappedTrackerKeyLengths_Negative_DoubleNestedMappedTrackerKey()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // start test as address 0x55556666
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory fcArgs = new ParamTypes[](2);
        fcArgs[0] = ParamTypes.UINT;
        fcArgs[1] = ParamTypes.UINT;
        ForeignCall memory fc;

        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.MAPPED_TRACKER_KEY;
        fc.encodedIndices[1].index = 0;
        fc.encodedIndices[1].eType = EncodedIndexType.GLOBAL_VAR;
        fc.mappedTrackerKeyIndices = new ForeignCallEncodedIndex[](1);
        fc.mappedTrackerKeyIndices[0].index = 0;
        fc.mappedTrackerKeyIndices[0].eType = EncodedIndexType.MAPPED_TRACKER_KEY;

        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(pfcContractAddress);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256,uint256)")));
        fc.returnType = ParamTypes.UINT;

        vm.expectRevert("Mapped tracker key cannot be double nested");
        RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "simpleCheck(uint256,uint256)");
    }
}
