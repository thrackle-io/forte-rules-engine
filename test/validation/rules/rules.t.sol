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

    function testRulesEngine_Unit_CreateRule_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();
        uint256 ruleId = 1;
        Rule memory rule;
        vm.expectEmit(true, false, false, false);
        emit RuleCreated(policyId, ruleId);
        RulesEngineRuleFacet(address(red)).createRule(policyId, rule);
    }

    // Update 
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

    function testRulesEngine_Unit_UpdateRule_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule);
        vm.expectEmit(true, false, false, false);
        emit RuleUpdated(policyId, ruleId);
        RulesEngineRuleFacet(address(red)).updateRule(policyId, 0, rule);
    }

    // Delete
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

    function testRulesEngine_Unit_GlobalVariable_MsgData_Match() public ifDeploymentTestsEnabled resetsGlobalVariables {
        vm.skip(true);
        uint256 policyId;
        uint256 ruleId;
        uint256 callingFunctionId;

        {
            vm.startPrank(policyAdmin);
            policyId = _createBlankPolicy();

            // Prepare known calldata and hash
            bytes4 selector = bytes4(keccak256("transfer(address,uint256)"));
            address testAddr = address(0x1234);
            uint256 testAmount = 1;
            bytes memory knownCalldata = abi.encodeWithSelector(selector, testAddr, testAmount);

            // Compute the actual msg.data as seen by the rules engine (outer call)
            bytes4 checkPoliciesSelector = bytes4(keccak256("checkPolicies(bytes)"));
            bytes memory engineMsgData = abi.encodeWithSelector(checkPoliciesSelector, knownCalldata);
            uint256 knownHash = uint256(keccak256(engineMsgData));

        
            {
                Rule memory rule;
                rule.instructionSet = new uint256[](7);
                rule.instructionSet[0] = uint(LogicalOp.PLH);
                rule.instructionSet[1] = 0;
                rule.instructionSet[2] = uint(LogicalOp.NUM);
                rule.instructionSet[3] = knownHash;
                rule.instructionSet[4] = uint(LogicalOp.EQ);
                rule.instructionSet[5] = 0;
                rule.instructionSet[6] = 1;

                rule.placeHolders = new Placeholder[](1);
                rule.placeHolders[0].pType = ParamTypes.BYTES;
                rule.placeHolders[0].flags = uint8(GLOBAL_MSG_DATA << SHIFT_GLOBAL_VAR);

                rule.negEffects = new Effect[](1);
                rule.negEffects[0] = effectId_revert;
                rule.posEffects = new Effect[](1);
                rule.posEffects[0] = effectId_event;

                ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule);
            }

        
            {
                ParamTypes[] memory pTypes = new ParamTypes[](2);
                pTypes[0] = ParamTypes.ADDR;
                pTypes[1] = ParamTypes.UINT;
                callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
                    policyId,
                    selector,
                    pTypes,
                    "transfer(address,uint256)",
                    ""
                );
            }

        
            {
                bytes4[] memory selectors = new bytes4[](1);
                selectors[0] = selector;
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

            uint256[] memory policyIds = new uint256[](1);
            policyIds[0] = policyId;
            vm.stopPrank();
            vm.startPrank(callingContractAdmin);
            RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
            vm.stopPrank();

       
            vm.startPrank(userContractAddress);
            bytes memory arguments = knownCalldata;
            uint256 response = RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
            assertEq(response, 1, "Rule using msg.data should pass if calldata matches known pattern");
            vm.stopPrank();

        
            vm.startPrank(userContractAddress);
            bytes memory differentCalldata = abi.encodeWithSelector(selector, address(0x5678), 2);
            vm.expectRevert(abi.encodePacked(revert_text));
            RulesEngineProcessorFacet(address(red)).checkPolicies(differentCalldata);
            vm.stopPrank();
        }
    }


}
