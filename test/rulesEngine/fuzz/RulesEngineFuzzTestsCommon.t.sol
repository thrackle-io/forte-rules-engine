/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract RulesEngineFuzzTestsCommon is RulesEngineCommon {

    /// Creation and update Fuzz Tests 

    // Rule creation 
    function testRulesEngine_Fuzz_createRule_simple(uint256 ruleValue, uint256 transferValue) public {
        bool response;
        // create a rule without foreign call or tracker 
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule;
        // Instruction set: LC.PLH, 1, 0, LC.NUM, 4, LC.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(ruleValue);
        // Build the calling function argument placeholder 
        rule.placeHolders = new RulesStorageStructure.Placeholder[](1);
        rule.placeHolders[0].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        uint256 ruleId = logic.updateRule(0,rule);

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;
        // Save the function signature
        uint256 functionSignatureId = logic.updateFunctionSignature(0, bytes4(bytes(functionSignature)),pTypes);
        // Save the Policy
        signatures.push(bytes(functionSignature));  
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        uint256[] memory policyIds = new uint256[](1); 
        policyIds[0] = logic.updatePolicy(0, signatures, functionSignatureIds, ruleIds);        
        logic.applyPolicy(address(userContract), policyIds);
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly 
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(transferValue);
        bytes memory retVal = abi.encode(arguments);
        if (ruleValue < transferValue) {
            response = logic.checkPolicies(address(userContract), bytes(functionSignature), retVal);
            assertTrue(response);
        } else if (ruleValue > transferValue){ 
            response = logic.checkPolicies(address(userContract), bytes(functionSignature), retVal);
            assertFalse(response);
        }
    }

    // Foreign Call creation 
    function testRulesEngine_Fuzz_createRule_ForeignCall(uint256 ruleValue, uint256 transferValue) public {
        bool response;
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"        
        RulesStorageStructure.Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new RulesStorageStructure.Placeholder[](1); 
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(ruleValue);
        // Build the mapping between calling function arguments and foreign call arguments
        rule.fcArgumentMappingsConditions = new RulesStorageStructure.ForeignCallArgumentMappings[](1);
        rule.fcArgumentMappingsConditions[0].mappings = new RulesStorageStructure.IndividualArgumentMapping[](1);
        rule.fcArgumentMappingsConditions[0].mappings[0].functionCallArgumentType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.foreignCall = false;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.pType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.typeSpecificIndex = 1;
        rule.negEffects = new uint256[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = logic.updateRule(0,rule);

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.UINT;
        pTypes[1] = RulesStorageStructure.PT.ADDR;
        // Save the function signature
        uint256 functionSignatureId = logic.updateFunctionSignature(0, bytes4(bytes(functionSignature)),pTypes);
        // Save the Policy
        signatures.push(bytes(functionSignature));  
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        uint256[] memory policyIds = new uint256[](1);
        uint256 policyId = logic.updatePolicy(0, signatures, functionSignatureIds, ruleIds);
        RulesStorageStructure.PT[] memory fcArgs = new RulesStorageStructure.PT[](1);
        fcArgs[0] = RulesStorageStructure.PT.UINT;
        RulesStorageStructure.ForeignCall memory fc = logic.updateForeignCall(policyId, address(testContract), "simpleCheck(uint256)", RulesStorageStructure.PT.UINT, fcArgs);        
        policyIds[0] = policyId;
        logic.applyPolicy(address(userContract), policyIds);
        fc;  //added to silence warnings during testing revamp 

        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(transferValue);
        bytes memory retVal = abi.encode(arguments);

        if (ruleValue < transferValue) {
            response = logic.checkPolicies(address(userContract), bytes(functionSignature), retVal);
            assertTrue(response);
        } else if (ruleValue >= transferValue){ 
            vm.expectRevert(abi.encodePacked(revert_text)); 
            logic.checkPolicies(address(userContract), bytes(functionSignature), retVal);
        }
    }

    // Tracker creation 
    function testRulesEngine_Fuzz_createRule_Tracker(uint256 trackerValue, uint256 transferValue) public {
        uint256 policyId;
        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule;
        // Instruction set: LC.PLH, 1, 0, LC.PLH, 1, 0, LC.GT, 0, 1
        rule.instructionSet = _createInstructionSet(0,1);

        rule.placeHolders = new RulesStorageStructure.Placeholder[](2);
        rule.placeHolders[0].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[1].trackerValue = true;
        // Add a negative/positive effects
        rule.negEffects = new uint256[](1);
        rule.posEffects = new uint256[](2);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = logic.updateRule(0,rule);

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;
        // Save the function signature
        uint256 functionSignatureId = logic.updateFunctionSignature(0, bytes4(bytes(functionSignature)),pTypes);
        // Save the Policy
        signatures.push(bytes(functionSignature));  
        functionSignatureIds.push(functionSignatureId);
        // Build the tracker
        RulesStorageStructure.Trackers memory tracker;  

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        uint256[] memory policyIds = new uint256[](1); 
        policyId = logic.updatePolicy(0, signatures, functionSignatureIds, ruleIds);  
        /// build the members of the struct: 
        tracker.pType = RulesStorageStructure.PT.UINT; 
        tracker.trackerValue = abi.encode(trackerValue);
        // Add the tracker
        logic.addTracker(policyId, tracker);
        functionSignatureId = logic.updateFunctionSignature(0, bytes4(bytes(functionSignature)),pTypes);
        policyIds[0] = policyId;     
        logic.applyPolicy(address(userContract), policyIds);
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(transferValue);
        bytes memory retVal = abi.encode(arguments);
        if (trackerValue < transferValue) {
            bool response = logic.checkPolicies(address(userContract), bytes(functionSignature), retVal);
            assertTrue(response);
        } else if (trackerValue >= transferValue){ 
            vm.expectRevert(abi.encodePacked(revert_text)); 
            logic.checkPolicies(address(userContract), bytes(functionSignature), retVal);
        }
    }
    // Policy creation 
    function _createBlankPolicy() internal returns (uint256) {
        bytes[] memory blankSignatures = new bytes[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        uint256 policyId = logic.updatePolicy(0, blankSignatures, blankFunctionSignatureIds, blankRuleIds);
        return policyId;
    }

    function testRulesEngine_Fuzz_createRule_CreatePolicy(uint256 _iterator) public {
        // create a number of blank policies so that rules engine has more than 1 
        _iterator = bound(_iterator, 1, 1000);
        for(uint256 i = 0; i < _iterator; i++){
            _createBlankPolicy();
        }
        // Create Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" to update a policy 
        RulesStorageStructure.Rule memory rule;
        // Instruction set: LC.PLH, 1, 0, LC.NUM, 4, LC.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder 
        rule.placeHolders = new RulesStorageStructure.Placeholder[](1);
        rule.placeHolders[0].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        uint256 ruleId = logic.updateRule(0,rule);
        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;
        // Save the function signature
        uint256 functionSignatureId = logic.updateFunctionSignature(0, bytes4(bytes(functionSignature)),pTypes);
        // Save the Policy
        signatures.push(bytes(functionSignature));  
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        assertGt(logic.updatePolicy(0, signatures, functionSignatureIds, ruleIds),0);

    }


    /// Rule Processing Fuzz Tests 
    // check Rule 
    function testRulesEngine_Fuzz_checkRule_simple(uint256 ruleValue, uint256 transferValue) public {
        bool response;
        // create a rule without foreign call or tracker 
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule;
        // Instruction set: LC.PLH, 1, 0, LC.NUM, 4, LC.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(ruleValue); 
        // Build the calling function argument placeholder 
        rule.placeHolders = new RulesStorageStructure.Placeholder[](1);
        rule.placeHolders[0].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        uint256 ruleId = logic.updateRule(0,rule);

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;
        // Save the function signature
        uint256 functionSignatureId = logic.updateFunctionSignature(0, bytes4(bytes(functionSignature)),pTypes);
        // Save the Policy
        signatures.push(bytes(functionSignature));  
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        uint256[] memory policyIds = new uint256[](1); 
        policyIds[0] = logic.updatePolicy(0, signatures, functionSignatureIds, ruleIds);        
        logic.applyPolicy(address(userContract), policyIds);
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly 
        if (ruleValue < transferValue) {
            response = userContract.transfer(address(0x7654321), transferValue);
            assertTrue(response);
        } else { 
            response = userContract.transfer(address(0x7654321), transferValue);
            assertFalse(response);
        }
    }
    // check rule with Foreign Call  
    function testRulesEngine_Fuzz_checkRule_ForeignCall(uint256 ruleValue, uint256 transferValue) public {
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"        
        RulesStorageStructure.Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new RulesStorageStructure.Placeholder[](1); 
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(ruleValue);
        // Build the mapping between calling function arguments and foreign call arguments
        rule.fcArgumentMappingsConditions = new RulesStorageStructure.ForeignCallArgumentMappings[](1);
        rule.fcArgumentMappingsConditions[0].mappings = new RulesStorageStructure.IndividualArgumentMapping[](1);
        rule.fcArgumentMappingsConditions[0].mappings[0].functionCallArgumentType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.foreignCall = false;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.pType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.typeSpecificIndex = 1;
        rule.negEffects = new uint256[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = logic.updateRule(0,rule);

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.UINT;
        pTypes[1] = RulesStorageStructure.PT.ADDR;
        // Save the function signature
        uint256 functionSignatureId = logic.updateFunctionSignature(0, bytes4(bytes(functionSignature)),pTypes);
        // Save the Policy
        signatures.push(bytes(functionSignature));  
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        uint256[] memory policyIds = new uint256[](1);
        uint256 policyId = logic.updatePolicy(0, signatures, functionSignatureIds, ruleIds);
        RulesStorageStructure.PT[] memory fcArgs = new RulesStorageStructure.PT[](1);
        fcArgs[0] = RulesStorageStructure.PT.UINT;
        logic.updateForeignCall(policyId, address(testContract), "simpleCheck(uint256)", RulesStorageStructure.PT.UINT, fcArgs);        
        policyIds[0] = policyId;
        logic.applyPolicy(address(userContract), policyIds);
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly 
        if (ruleValue < transferValue) {
            bool response = userContract.transfer(address(0x7654321), transferValue);
            assertTrue(response);
        } else { 
            vm.expectRevert(abi.encodePacked(revert_text)); 
            userContract.transfer(address(0x7654321), transferValue);
        }
    }

    // check rule with Tracker 
function testRulesEngine_Fuzz_checkRule_Tracker(uint256 trackerValue, uint256 transferValue) public {
        uint256 policyId;
        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule;
        // Instruction set: LC.PLH, 1, 0, LC.PLH, 1, 0, LC.GT, 0, 1
        rule.instructionSet = _createInstructionSet(0,1);
        rule.placeHolders = new RulesStorageStructure.Placeholder[](2);
        rule.placeHolders[0].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[1].trackerValue = true;
        // Add a negative/positive effects
        rule.negEffects = new uint256[](1);
        rule.posEffects = new uint256[](2);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = logic.updateRule(0,rule);

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;
        // Save the function signature
        uint256 functionSignatureId = logic.updateFunctionSignature(0, bytes4(bytes(functionSignature)),pTypes);
        // Save the Policy
        signatures.push(bytes(functionSignature));  
        functionSignatureIds.push(functionSignatureId);
        // Build the tracker
        RulesStorageStructure.Trackers memory tracker;  

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        uint256[] memory policyIds = new uint256[](1); 
        policyId = logic.updatePolicy(0, signatures, functionSignatureIds, ruleIds);  
        /// build the members of the struct: 
        tracker.pType = RulesStorageStructure.PT.UINT; 
        tracker.trackerValue = abi.encode(trackerValue);
        // Add the tracker
        logic.addTracker(policyId, tracker);
        functionSignatureId = logic.updateFunctionSignature(0, bytes4(bytes(functionSignature)),pTypes);
        policyIds[0] = policyId;     
        logic.applyPolicy(address(userContract), policyIds);
        if (trackerValue < transferValue) {
            bool retVal = userContract.transfer(address(0x7654321), transferValue);
            assertTrue(retVal);
        } else {
            vm.expectRevert(abi.encodePacked(revert_text)); 
            userContract.transfer(address(0x7654321), transferValue);
        }
    }


    // check Negative effects 
    function testRulesEngine_Fuzz_checkRule_WithEffect_Revert(uint256 transferValue, uint256 ruleAmount) public {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule =  _createGTRule(ruleAmount);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = logic.updateRule(0,rule);
        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;
        // Save the function signature
        uint256 functionSignatureId = logic.updateFunctionSignature(0, bytes4(bytes(functionSignature)),pTypes);
        // Save the Policy
        signatures.push(bytes(functionSignature));  
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        uint256[] memory policyIds = new uint256[](1); 
        policyIds[0] = logic.updatePolicy(0, signatures, functionSignatureIds, ruleIds);        
        logic.applyPolicy(address(userContract), policyIds);
        if (ruleAmount < transferValue) {
            bool retVal = userContract.transfer(address(0x7654321), transferValue);
            assertTrue(retVal);
        } else {
            vm.expectRevert(abi.encodePacked(revert_text)); 
            userContract.transfer(address(0x7654321), transferValue);
        }
    }

    // check Positive effects 
    function testRulesEngine_Fuzz_checkRule_WithEffect_Event(uint256 transferValue, uint256 ruleAmount) public {
        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule =  _createGTRule(ruleAmount);
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = logic.updateRule(0,rule);

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;
        // Save the function signature
        uint256 functionSignatureId = logic.updateFunctionSignature(0, bytes4(bytes(functionSignature)),pTypes);
        // Save the Policy
        signatures.push(bytes(functionSignature));  
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        uint256[] memory policyIds = new uint256[](1); 
        policyIds[0] = logic.updatePolicy(0, signatures, functionSignatureIds, ruleIds);        
        logic.applyPolicy(address(userContract), policyIds);

        if (ruleAmount < transferValue) {
            vm.expectEmit(true, true, false, false);
            emit RulesEngineEvent(event_text);
            userContract.transfer(address(0x7654321), transferValue);
        } else {
            bool retVal = userContract.transfer(address(0x7654321), transferValue);
            assertFalse(retVal);
        }
    }

    // internal rule builder 
    function _createGTRule(uint256 _amount) public returns(RulesStorageStructure.Rule memory){
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LC.PLH, 1, 0, LC.NUM, _amount, LC.GT, 0, 1
        rule.instructionSet = rule.instructionSet = _createInstructionSet(_amount);
        rule.placeHolders = new RulesStorageStructure.Placeholder[](1);
        rule.placeHolders[0].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new uint256[](1);
        rule.posEffects = new uint256[](2);
        return rule;
    }
}
