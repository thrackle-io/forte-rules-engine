/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract rules is RulesEngineCommon {
    /**
     *
     *
     * Validation tests for rules within the rules engine
     *
     *
     */

    // CRUD Functions: Rules
    // Create
    function testRulesEngine_Unit_createRule_ForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCall(4, EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), transferValue);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_createRule_ForeignCall_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        // change values in order to violate rule
        ruleValue = 15;
        transferValue = 10;
        setupRuleWithForeignCall(ruleValue, EffectTypes.REVERT, false);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), transferValue);
        vm.startPrank(address(userContract));
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_createRule_Tracker_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithTracker(10);

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), transferValue);

        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_createRule_Tracker_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithTracker(15);
        transferValue = 10;

        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), transferValue);
        vm.startPrank(address(userContract));
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function testRulesEngine_Unit_createRule_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;
        rule.instructionSet = new uint256[](2);
        rule.instructionSet[0] = 0;
        rule.instructionSet[1] = 0;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;

        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);
    }

    function testRulesEngine_Unit_createRule_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;

        // Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);
    }

    function testRulesEngine_Unit_AddClosedPolicy_Subscriber_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankcallingFunctionIds,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).addClosedPolicySubscriber(policyId, address(1));
    }

    function testRulesEngine_Unit_AddClosedPolicy_Subscriber_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankcallingFunctionIds,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );

        // Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).addClosedPolicySubscriber(policyId, address(1));
    }

    function testRulesEngine_Unit_RemoveClosedPolicy_Subscriber_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankcallingFunctionIds,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        RulesEngineComponentFacet(address(red)).addClosedPolicySubscriber(policyId, address(1));
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineComponentFacet(address(red)).removeClosedPolicySubscriber(policyId, address(1));
    }

    function testRulesEngine_Unit_RemoveClosedPolicy_Subscriber_Negative_Non_PolicyAdmin()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 policyId = _createBlankPolicy();
        bytes4[] memory blankcallingFunctions = new bytes4[](0);
        uint256[] memory blankcallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            blankcallingFunctions,
            blankcallingFunctionIds,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        RulesEngineComponentFacet(address(red)).addClosedPolicySubscriber(policyId, address(1));

        // Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineComponentFacet(address(red)).removeClosedPolicySubscriber(policyId, address(1));
    }

    function testRulesEngine_Unit_CreateRule_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();
        uint256 ruleId = 1;
        Rule memory rule;
        rule.instructionSet = new uint256[](2);
        rule.instructionSet[0] = 0;
        rule.instructionSet[1] = 0;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;
        vm.expectEmit(true, false, false, false);
        emit RuleCreated(policyId, ruleId);
        RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);
    }

    // Update
    function testRulesEngine_Unit_updateRule_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
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

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);
        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineRuleFacet(address(red)).updateRule(policyId, ruleId, rule, ruleName, ruleDescription);
    }

    function testRulesEngine_Unit_updateRule_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
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

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);
        // Prank a random, non-policy admin address
        vm.startPrank(address(0x1337));
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineRuleFacet(address(red)).updateRule(policyId, ruleId, rule, ruleName, ruleDescription);
    }

    function testRulesEngine_Unit_UpdateRule_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;
        rule.instructionSet = new uint256[](2);
        rule.instructionSet[0] = 0;
        rule.instructionSet[1] = 0;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);
        vm.expectEmit(true, false, false, false);
        emit RuleUpdated(policyId, ruleId);
        RulesEngineRuleFacet(address(red)).updateRule(policyId, 0, rule, ruleName, ruleDescription);
    }

    // Delete
    function testRulesEngine_Unit_deleteRule_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyId, 0, rule, ruleName, ruleDescription);

        RulesEngineRuleFacet(address(red)).deleteRule(policyId, ruleId);
        RuleStorageSet memory sig = RulesEngineRuleFacet(address(red)).getRule(policyId, ruleId);
        assertEq(sig.set, false);
    }

    function testRulesEngine_Unit_deleteRule_Negative_CementedPolicy() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyId, 0, rule, ruleName, ruleDescription);

        RulesEnginePolicyFacet(address(red)).cementPolicy(policyId);
        vm.expectRevert("Not allowed for cemented policy");
        RulesEngineRuleFacet(address(red)).deleteRule(policyId, ruleId);
    }

    function testRulesEngine_Unit_deleteRule_Negative_Non_PolicyAdmin() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;

        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyId, 0, rule, ruleName, ruleDescription);

        vm.startPrank(newPolicyAdmin);
        vm.expectRevert("Not Authorized To Policy");
        RulesEngineRuleFacet(address(red)).deleteRule(policyId, ruleId);
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
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyId, 0, rule, ruleName, ruleDescription);
        vm.expectEmit(true, false, false, false);
        emit RuleDeleted(policyId, ruleId);
        RulesEngineRuleFacet(address(red)).deleteRule(policyId, ruleId);
    }

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
        rule.instructionSet[1] = 0; // r0: placeholder 0 (global block.timestamp)
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1000; // r1: constant 1000
        rule.instructionSet[4] = uint(LogicalOp.GTEQL);
        rule.instructionSet[5] = 0; // block.timestamp
        rule.instructionSet[6] = 1; // constant 1000

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
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);

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
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        // block.timestamp < 1000 should fail
        vm.warp(900);
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // block.timestamp == 1000 should pass
        vm.warp(1000);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // block.timestamp > 1000 should pass
        vm.warp(1100);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
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
        rule.instructionSet[1] = 0; // r0: placeholder 0 (global block.number)
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1000; // r1: constant 1000
        rule.instructionSet[4] = uint(LogicalOp.GTEQL);
        rule.instructionSet[5] = 0; // block.number
        rule.instructionSet[6] = 1; // constant 1000

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
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);

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
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        // block.number < 1000 should fail
        vm.roll(900);
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // block.number == 1000 should pass
        vm.roll(1000);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // block.number > 1000 should pass
        vm.roll(1100);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
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
        rule.instructionSet[1] = 0; // r0: placeholder 0 (global msg.sender)
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(uint160(expectedAddress)); // r1: expected address
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0; // msg.sender
        rule.instructionSet[6] = 1; // expected address

        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].flags = uint8(GLOBAL_MSG_SENDER << SHIFT_GLOBAL_VAR);

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);

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
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        // Call from incorrect address - should fail
        vm.stopPrank();
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // Call from correct address - should pass
        vm.stopPrank();
        vm.startPrank(expectedAddress);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
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
        rule.instructionSet[1] = 0; // r0: placeholder 0 (global tx.origin)
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(uint160(expectedAddress)); // r1: expected address
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0; // tx.origin
        rule.instructionSet[6] = 1; // expected address

        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].flags = uint8(GLOBAL_TX_ORIGIN << SHIFT_GLOBAL_VAR);

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);

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
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        // Call from incorrect tx.origin - should fail
        vm.stopPrank();
        vm.startPrank(userContractAddress, address(0x9999)); // Second parameter is tx.origin
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        // Call from correct tx.origin - should pass
        vm.stopPrank();
        vm.startPrank(userContractAddress, expectedAddress); // Second parameter is tx.origin
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
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
                ForeignCallEncodedIndex[] memory encodedIndices = new ForeignCallEncodedIndex[](1);
                encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES; // Regular parameter
                encodedIndices[0].index = 2;
                ForeignCall memory fc;
                fc.foreignCallAddress = foreignCallTarget;
                fc.signature = setMsgDataSelector;
                fc.returnType = ParamTypes.BOOL;
                fc.parameterTypes = fcParamTypes;
                fc.encodedIndices = encodedIndices;
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
                ForeignCallEncodedIndex[] memory encodedIndices = new ForeignCallEncodedIndex[](1);
                encodedIndices[0].eType = EncodedIndexType.GLOBAL_VAR;
                encodedIndices[0].index = GLOBAL_MSG_DATA;
                ForeignCall memory fc;
                fc.foreignCallAddress = foreignCallTarget;
                fc.signature = setMsgDataSelector;
                fc.returnType = ParamTypes.BOOL;
                fc.parameterTypes = fcParamTypes;
                fc.encodedIndices = encodedIndices;
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

            RulesEngineProcessorFacet(address(red)).checkPolicies(transferCalldata);

            bytes memory actualMsgData = ExampleUserContract(userContractAddress).msgData();

            bytes4 checkPoliciesSelector = RulesEngineProcessorFacet(address(red)).checkPolicies.selector;
            bytes memory expectedMsgData = abi.encodeWithSelector(checkPoliciesSelector, transferCalldata);
            assertEq(actualMsgData, expectedMsgData, "Foreign call should set msgData to the ABI-encoded checkPolicies(bytes) calldata");
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
                ForeignCallEncodedIndex[] memory encodedIndices = new ForeignCallEncodedIndex[](1);
                encodedIndices[0].eType = EncodedIndexType.GLOBAL_VAR;
                encodedIndices[0].index = GLOBAL_MSG_SENDER;
                ForeignCall memory fc;
                fc.foreignCallAddress = foreignCallTarget;
                fc.signature = setUserAddressSelector;
                fc.returnType = ParamTypes.BOOL;
                fc.parameterTypes = fcParamTypes;
                fc.encodedIndices = encodedIndices;
                foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "setUserAddress(address)");
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
                ForeignCallEncodedIndex[] memory encodedIndices = new ForeignCallEncodedIndex[](1);
                encodedIndices[0].eType = EncodedIndexType.GLOBAL_VAR;
                encodedIndices[0].index = GLOBAL_BLOCK_TIMESTAMP;
                ForeignCall memory fc;
                fc.foreignCallAddress = foreignCallTarget;
                fc.signature = setNumberSelector;
                fc.returnType = ParamTypes.BOOL;
                fc.parameterTypes = fcParamTypes;
                fc.encodedIndices = encodedIndices;
                foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "setNumber(uint256)");
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
            // Set the block timestamp
            uint256 testTimestamp = 12345;
            vm.warp(testTimestamp);

            vm.startPrank(userContractAddress);
            address to = address(0xBEEF);
            uint256 value = 42;
            bytes memory transferCalldata = abi.encodeWithSelector(
                ExampleUserContract.transferFrom.selector,
                to,
                value,
                abi.encode("TESTER")
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
                ForeignCallEncodedIndex[] memory encodedIndices = new ForeignCallEncodedIndex[](1);
                encodedIndices[0].eType = EncodedIndexType.GLOBAL_VAR;
                encodedIndices[0].index = GLOBAL_BLOCK_NUMBER;
                ForeignCall memory fc;
                fc.foreignCallAddress = foreignCallTarget;
                fc.signature = setNumberSelector;
                fc.returnType = ParamTypes.BOOL;
                fc.parameterTypes = fcParamTypes;
                fc.encodedIndices = encodedIndices;
                foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "setNumber(uint256)");
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
            // Set the block number
            uint256 testBlockNumber = 9876;
            vm.roll(testBlockNumber);

            vm.startPrank(userContractAddress);
            address to = address(0xBEEF);
            uint256 value = 42;
            bytes memory transferCalldata = abi.encodeWithSelector(
                ExampleUserContract.transferFrom.selector,
                to,
                value,
                abi.encode("TESTER")
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
                ForeignCallEncodedIndex[] memory encodedIndices = new ForeignCallEncodedIndex[](1);
                encodedIndices[0].eType = EncodedIndexType.GLOBAL_VAR;
                encodedIndices[0].index = GLOBAL_TX_ORIGIN;
                ForeignCall memory fc;
                fc.foreignCallAddress = foreignCallTarget;
                fc.signature = setUserAddressSelector;
                fc.returnType = ParamTypes.BOOL;
                fc.parameterTypes = fcParamTypes;
                fc.encodedIndices = encodedIndices;
                foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyId, fc, "setUserAddress(address)");
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
            // Set the tx.origin
            address txOriginAddress = address(0xABCD);

            vm.startPrank(userContractAddress, txOriginAddress);
            address to = address(0xBEEF);
            uint256 value = 42;
            bytes memory transferCalldata = abi.encodeWithSelector(
                ExampleUserContract.transferFrom.selector,
                to,
                value,
                abi.encode("TESTER")
            );

            RulesEngineProcessorFacet(address(red)).checkPolicies(transferCalldata);

            // The userAddress should now be set to the tx.origin address
            address actualUserAddress = ExampleUserContract(userContractAddress).userAddress();
            assertEq(actualUserAddress, txOriginAddress, "Foreign call should set userAddress to tx.origin");
            vm.stopPrank();
        }
    }

    function testRulesEngine_Unit_Tracker_UpdateWithBlockTimestamp() public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256 policyId;
        uint256 trackerId;
        uint256 ruleId;
        uint256 callingFunctionId;

        {
            vm.startPrank(policyAdmin);

            policyId = _createBlankPolicy();

            // Create a tracker to store the timestamp
            Trackers memory tracker;
            tracker.pType = ParamTypes.UINT;
            tracker.trackerValue = abi.encode(uint256(0));
            trackerId = RulesEngineComponentFacet(address(red)).createTracker(policyId, tracker, "timestampTracker");

            // Create a rule that always passes (1 == 1)
            Rule memory rule;

            // Simple rule instruction: 1 == 1 (always true)
            rule.instructionSet = new uint256[](7);
            rule.instructionSet[0] = uint(LogicalOp.NUM); // Load constant 1 into memory[0]
            rule.instructionSet[1] = 1;
            rule.instructionSet[2] = uint(LogicalOp.NUM); // Load constant 1 into memory[1]
            rule.instructionSet[3] = 1;
            rule.instructionSet[4] = uint(LogicalOp.EQ); // Compare memory[0] == memory[1] (always true)
            rule.instructionSet[5] = 0;
            rule.instructionSet[6] = 1;

            // Effect placeholders for global block.timestamp
            rule.effectPlaceHolders = new Placeholder[](1);
            rule.effectPlaceHolders[0].pType = ParamTypes.UINT;
            rule.effectPlaceHolders[0].flags = uint8(GLOBAL_BLOCK_TIMESTAMP << SHIFT_GLOBAL_VAR);

            // Create effect that updates tracker with current block.timestamp
            rule.posEffects = new Effect[](1);
            rule.posEffects[0].valid = true;
            rule.posEffects[0].effectType = EffectTypes.EXPRESSION;
            rule.posEffects[0].text = "";

            // Effect instruction: TRU trackerId = effectPlaceholder[0] (global timestamp)
            rule.posEffects[0].instructionSet = new uint256[](4);
            rule.posEffects[0].instructionSet[0] = uint(LogicalOp.TRU);
            rule.posEffects[0].instructionSet[1] = trackerId;
            rule.posEffects[0].instructionSet[2] = 0; // effectPlaceHolders[0] (contains block.timestamp)
            rule.posEffects[0].instructionSet[3] = uint(TrackerTypes.PLACE_HOLDER); // Use PLACE_HOLDER type

            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);

            // Set up calling function (transfer)
            ParamTypes[] memory pTypes = new ParamTypes[](2);
            pTypes[0] = ParamTypes.ADDR;
            pTypes[1] = ParamTypes.UINT;
            callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
                policyId,
                bytes4(keccak256(bytes(callingFunction))),
                pTypes,
                callingFunction,
                ""
            );

            // Link rule to calling function in policy
            bytes4[] memory selectors = new bytes4[](1);
            selectors[0] = bytes4(keccak256(bytes(callingFunction)));
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

            // Apply policy to user contract
            uint256[] memory policyIds = new uint256[](1);
            policyIds[0] = policyId;
            vm.stopPrank();
            vm.startPrank(callingContractAdmin);
            RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
            vm.stopPrank();
        }

        // Set a specific block timestamp for testing
        uint256 testTimestamp = 12345;
        vm.warp(testTimestamp);

        // Execute the rule
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopPrank();

        // Check if tracker was updated with the block timestamp
        Trackers memory updatedTracker = RulesEngineComponentFacet(address(red)).getTracker(policyId, trackerId);
        uint256 trackerTimestamp = abi.decode(updatedTracker.trackerValue, (uint256));
        assertEq(trackerTimestamp, testTimestamp, "Tracker should be updated with current block.timestamp");
    }

    function testRulesEngine_Unit_RulesValidationCreateRule_PolicyIdCannotBeZero() public ifDeploymentTestsEnabled resetsGlobalVariables {
        vm.startPrank(policyAdmin);
        // Create a blank policy
        uint256 policyId = _createBlankPolicy();

        // Create a rule with a zero policyId - should fail
        Rule memory rule;

        vm.expectRevert("Policy ID cannot be 0. Create policy before updating");
        RulesEngineRuleFacet(address(red)).createRule(0, rule, ruleName, ruleDescription);
        vm.stopPrank();
    }

    function testRulesEngine_Unit_RulesValidationUpdateRule_PolicyIdCannotBeZero() public ifDeploymentTestsEnabled resetsGlobalVariables {
        vm.startPrank(policyAdmin);
        // Create a blank policy
        uint256 policyId = _createBlankPolicy();

        // Create a rule with a zero policyId - should fail
        Rule memory rule;
        rule.instructionSet = new uint256[](2);
        rule.instructionSet[0] = 0;
        rule.instructionSet[1] = 0;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(1, rule, ruleName, ruleDescription);

        vm.expectRevert("Policy ID cannot be 0. Create policy before updating");
        RulesEngineRuleFacet(address(red)).updateRule(0, ruleId, rule, ruleName, ruleDescription);

        vm.stopPrank();
    }

    function testRulesEngine_Unit_RulesValidationDeleteRule_PolicyIdCannotBeZero() public ifDeploymentTestsEnabled resetsGlobalVariables {
        vm.startPrank(policyAdmin);
        // Create a blank policy
        uint256 policyId = _createBlankPolicy();

        // Create a rule with a zero policyId - should fail
        Rule memory rule;
        rule.instructionSet = new uint256[](2);
        rule.instructionSet[0] = 0;
        rule.instructionSet[1] = 0;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(1, rule, ruleName, ruleDescription);

        vm.expectRevert("Policy ID cannot be 0. Create policy before updating");
        RulesEngineRuleFacet(address(red)).deleteRule(0, ruleId);

        vm.stopPrank();
    }

    function testRulesEngine_Unit_RulesValidationRuleGetters_PolicyIdCannotBeZero() public ifDeploymentTestsEnabled resetsGlobalVariables {
        vm.startPrank(policyAdmin);
        // Create a blank policy
        uint256 policyId = _createBlankPolicy();

        // Create a rule with a zero policyId - should fail
        Rule memory rule;
        rule.instructionSet = new uint256[](2);
        rule.instructionSet[0] = 0;
        rule.instructionSet[1] = 0;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_event;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(1, rule, ruleName, ruleDescription);

        vm.expectRevert("Policy ID cannot be 0. Create policy before updating");
        RulesEngineRuleFacet(address(red)).getRule(0, ruleId);

        vm.expectRevert("Policy ID cannot be 0. Create policy before updating");
        RulesEngineRuleFacet(address(red)).getAllRules(0);

        vm.expectRevert("Policy ID cannot be 0. Create policy before updating");
        RulesEngineRuleFacet(address(red)).getRuleMetadata(0, ruleId);

        vm.stopPrank();
    }
}
