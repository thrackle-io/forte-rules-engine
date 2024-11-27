/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract RulesEngineUnitTestsCommon is RulesEngineCommon {

    function setupRuleWithoutForeignCall() public ifDeploymentTestsEnabled endWithStopPrank {
        // Initial setup for what we'll need later
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        policyIds[0] = _createBlankPolicy();

        // Add the function signature to the policy
        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);
        
        
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule;
        
        // Instruction set: LC.PLH, 1, 0, LC.NUM, 4, LC.GT, 0, 1

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(RulesStorageStructure.LC.NUM);
        rule.instructionSet[3] = 4;
        rule.instructionSet[4] = uint(RulesStorageStructure.LC.GT);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        // Build the calling function argument placeholder 
        rule.placeHolders = new RulesStorageStructure.Placeholder[](1);
        rule.placeHolders[0].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        uint256 ruleId = logic.updateRule(0,rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        
        // Apply the policy 
        logic.applyPolicy(address(userContract), policyIds);
    }

        function setupRuleWithStringComparison() public ifDeploymentTestsEnabled endWithStopPrank returns (uint256 ruleId) {
        // Rule: info == "Bad Info" -> revert -> updateInfo(address _to, string info) returns (bool)"
        RulesStorageStructure.Rule memory rule;
        
        // Instruction set: LC.PLH, 1, 0, LC.NUM, *uint256 representation of Bad Info*, LC.EQ, 0, 1

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(RulesStorageStructure.LC.NUM);
        rule.instructionSet[3] = uint256(keccak256(abi.encode("Bad Info")));
        rule.instructionSet[4] = uint(RulesStorageStructure.LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.rawData.argumentTypes = new RulesStorageStructure.PT[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = RulesStorageStructure.PT.STR;
        rule.rawData.dataValues[0] = abi.encode("Bad Info");
        rule.rawData.instructionSetIndex[0] = 3;


        // Build the calling function argument placeholder 
        rule.placeHolders = new RulesStorageStructure.Placeholder[](1);
        rule.placeHolders[0].pType = RulesStorageStructure.PT.STR;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        ruleId = logic.updateRule(0,rule);

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.STR;
        // Save the function signature
        uint256 functionSignatureId = logic.updateFunctionSignature(0, bytes4(bytes(functionSignature2)),pTypes);
        // Save the Policy
        signatures.push(bytes(functionSignature2));  
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        uint256[] memory policyIds = new uint256[](1); 
        policyIds[0] = logic.updatePolicy(0, signatures, functionSignatureIds, ruleIds);        
        logic.applyPolicy(address(userContract), policyIds);

        return ruleId;
    }

        function setupRuleWithAddressComparison() public ifDeploymentTestsEnabled endWithStopPrank returns (uint256 ruleId) {
        // Rule: _to == 0x1234567 -> revert -> updateInfo(address _to, string info) returns (bool)"
        RulesStorageStructure.Rule memory rule;
        
        // Instruction set: LC.PLH, 1, 0, LC.NUM, *uint256 representation of 0x1234567o*, LC.EQ, 0, 1

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(RulesStorageStructure.LC.NUM);
        rule.instructionSet[3] = uint256(uint160(address(0x1234567)));
        rule.instructionSet[4] = uint(RulesStorageStructure.LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.rawData.argumentTypes = new RulesStorageStructure.PT[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        rule.rawData.dataValues[0] = abi.encode(0x1234567);
        rule.rawData.instructionSetIndex[0] = 3;


        // Build the calling function argument placeholder 
        rule.placeHolders = new RulesStorageStructure.Placeholder[](1);
        rule.placeHolders[0].pType = RulesStorageStructure.PT.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Save the rule
        ruleId = logic.updateRule(0,rule);

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.STR;
        // Save the function signature
        uint256 functionSignatureId = logic.updateFunctionSignature(0, bytes4(bytes(functionSignature2)),pTypes);
        // Save the Policy
        signatures.push(bytes(functionSignature2));  
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        uint256[] memory policyIds = new uint256[](1); 
        policyIds[0] = logic.updatePolicy(0, signatures, functionSignatureIds, ruleIds);        
        logic.applyPolicy(address(userContract), policyIds);

        return ruleId;
    }

    // Test attempt to add a policy with no signatures saved.
    function testRulesEngine_Unit_UpdatePolicy_InvalidRule() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;
        // Save the function signature
        uint256 functionSignatureId = logic.updateFunctionSignature(0, bytes4(bytes(functionSignature)),pTypes);
        signatures.push(bytes(functionSignature));  
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= 1;
        vm.expectRevert("Invalid Rule");
        logic.updatePolicy(policyId, signatures, functionSignatureIds, ruleIds);
    }

    // Test attempt to add a policy with no signatures saved.
    function testRulesEngine_Unit_UpdatePolicy_InvalidSignature() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = _createBlankPolicy();
        signatures.push(bytes(functionSignature));  
        functionSignatureIds.push(1);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= 1;
        vm.expectRevert("Invalid Signature");
        logic.updatePolicy(policyId, signatures, functionSignatureIds, ruleIds);
    }

    // Test attempt to add a policy with valid parts.
    function testRulesEngine_Unit_UpdatePolicy_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule;
        
        // Instruction set: LC.PLH, 1, 0, LC.NUM, 4, LC.GT, 0, 1

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(RulesStorageStructure.LC.NUM);
        rule.instructionSet[3] = 4;
        rule.instructionSet[4] = uint(RulesStorageStructure.LC.GT);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

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

    function setupEffectWithTrackerUpdate() public ifDeploymentTestsEnabled endWithStopPrank returns (uint256 ruleId) {
        uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicy();

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);

        // Rule: 1 == 1 -> TRU:someTracker += FC:simpleCheck(amount) -> transfer(address _to, uint256 amount) returns (bool)
        RulesStorageStructure.PT[] memory fcArgs = new RulesStorageStructure.PT[](1);
        fcArgs[0] = RulesStorageStructure.PT.UINT;
        RulesStorageStructure.Rule memory rule;
        rule.posEffects = new uint256[](1);
        rule.posEffects[0] = effectId_expression2;
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(RulesStorageStructure.LC.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(RulesStorageStructure.LC.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(RulesStorageStructure.LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.effectPlaceHolders = new RulesStorageStructure.Placeholder[](2); 
        rule.effectPlaceHolders[0].foreignCall = true;
        rule.effectPlaceHolders[0].typeSpecificIndex = 0;
        rule.effectPlaceHolders[1].pType = RulesStorageStructure.PT.UINT;
        rule.effectPlaceHolders[1].trackerValue = true;

        rule.fcArgumentMappingsEffects = new RulesStorageStructure.ForeignCallArgumentMappings[](1);
        rule.fcArgumentMappingsEffects[0].mappings = new RulesStorageStructure.IndividualArgumentMapping[](1);
        rule.fcArgumentMappingsEffects[0].mappings[0].functionCallArgumentType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappingsEffects[0].mappings[0].functionSignatureArg.foreignCall = false;
        rule.fcArgumentMappingsEffects[0].mappings[0].functionSignatureArg.pType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappingsEffects[0].mappings[0].functionSignatureArg.typeSpecificIndex = 1;
        ruleId = logic.updateRule(0, rule);

        //build tracker 
        RulesStorageStructure.Trackers memory tracker;  
        /// build the members of the struct: 
        tracker.pType = RulesStorageStructure.PT.UINT; 
        tracker.trackerValue = abi.encode(2); 

        
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        logic.addTracker(policyIds[0], tracker);      
        RulesStorageStructure.ForeignCall memory fc = logic.updateForeignCall(policyIds[0], address(testContract), "simpleCheck(uint256)", RulesStorageStructure.PT.UINT, fcArgs);

        logic.applyPolicy(address(userContract), policyIds);
        fc;  //added to silence warnings during testing revamp 
        return policyIds[0];
    }

    function setupEffectWithForeignCall() public ifDeploymentTestsEnabled endWithStopPrank {
       uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicy();

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);
        // Rule: 1 == 1 -> FC:simpleCheck(amount) -> transfer(address _to, uint256 amount) returns (bool)

        // build Foreign Call Structure
        RulesStorageStructure.Rule memory rule;
        rule.posEffects = new uint256[](1);
        rule.posEffects[0] = effectId_expression;
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(RulesStorageStructure.LC.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(RulesStorageStructure.LC.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(RulesStorageStructure.LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.effectPlaceHolders = new RulesStorageStructure.Placeholder[](1); 
        rule.effectPlaceHolders[0].foreignCall = true;
        rule.effectPlaceHolders[0].typeSpecificIndex = 0;

        rule.fcArgumentMappingsEffects = new RulesStorageStructure.ForeignCallArgumentMappings[](1);
        rule.fcArgumentMappingsEffects[0].mappings = new RulesStorageStructure.IndividualArgumentMapping[](1);
        rule.fcArgumentMappingsEffects[0].mappings[0].functionCallArgumentType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappingsEffects[0].mappings[0].functionSignatureArg.foreignCall = false;
        rule.fcArgumentMappingsEffects[0].mappings[0].functionSignatureArg.pType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappingsEffects[0].mappings[0].functionSignatureArg.typeSpecificIndex = 1;
        uint256 ruleId = logic.updateRule(0, rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesStorageStructure.PT[] memory fcArgs = new RulesStorageStructure.PT[](1);
        fcArgs[0] = RulesStorageStructure.PT.UINT;
        logic.updateForeignCall(policyIds[0], address(testContract), "simpleCheck(uint256)", RulesStorageStructure.PT.UINT, fcArgs);        
        logic.applyPolicy(address(userContract), policyIds);
    }

    function setupRuleWithForeignCall() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicy();

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);

        
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"        
        RulesStorageStructure.Rule memory rule;
        
        // Build the foreign call placeholder
        rule.placeHolders = new RulesStorageStructure.Placeholder[](1); 
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 0;

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(RulesStorageStructure.LC.NUM);
        rule.instructionSet[3] = 4;
        rule.instructionSet[4] = uint(RulesStorageStructure.LC.GT);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

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

        RulesStorageStructure.PT[] memory fcArgs = new RulesStorageStructure.PT[](1);
        fcArgs[0] = RulesStorageStructure.PT.UINT;
        RulesStorageStructure.ForeignCall memory fc = logic.updateForeignCall(policyIds[0], address(testContract), "simpleCheck(uint256)", RulesStorageStructure.PT.UINT, fcArgs);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);       
        logic.applyPolicy(address(userContract), policyIds);
        fc;  //added to silence warnings during testing revamp 
    }

    function _setupRuleWithRevert() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicy();

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);

        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule =  _createGTRule(4);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = logic.updateRule(0,rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        logic.applyPolicy(address(userContract), policyIds);
    }

    function _setupRuleWithPosEvent() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);

        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule =  _createGTRule(4);
        rule.posEffects[0] = effectId_event;
       
        // Save the rule
        uint256 ruleId = logic.updateRule(0,rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        logic.applyPolicy(address(userContract), policyIds);
    }

    function _setupPolicyWithMultipleRulesWithPosEvents() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicy();

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);

        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        // Rule 1: GT 4
        RulesStorageStructure.Rule memory rule =  _createGTRule(4);
        rule.posEffects[0] = effectId_event;
       
        // Save the rule
        uint256 ruleId = logic.updateRule(0,rule);

        ruleIds.push(new uint256[](4));
        ruleIds[0][0]= ruleId;

        // Rule 2: GT 5
        rule =  _createGTRule(5);
        rule.posEffects[0] = effectId_event2;
       
        // Save the rule
        ruleId = logic.updateRule(0,rule);

        // // Save the fKureIds.push(functionSignatureId);
        ruleIds[0][1]= ruleId;

        // Rule 3: GT 6
        rule =  _createGTRule(6);
        rule.posEffects[0] = effectId_event;
       
        // Save the rule
        ruleId = logic.updateRule(0,rule);

        // // Save the fKureIds.push(functionSignatureId);
        ruleIds[0][2]= ruleId;

        // Rule 4: GT 7
        rule =  _createGTRule(7);
        rule.posEffects[0] = effectId_event2;
       
        // Save the rule
        ruleId = logic.updateRule(0,rule);

        // // Save the fKureIds.push(functionSignatureId);
        ruleIds[0][3]= ruleId;

        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        logic.applyPolicy(address(userContract), policyIds);
    }

    function _setupRuleWith2PosEvent() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicy();

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);

        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule =  _createGTRule(4);
        rule.posEffects[0] = effectId_event;
        rule.posEffects[1] = effectId_event2;
       
        // Save the rule
        uint256 ruleId = logic.updateRule(0,rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        logic.applyPolicy(address(userContract), policyIds);
    }

    function testRulesEngine_Unit_CheckRules_Explicit() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithoutForeignCall();
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(5);
        bytes memory retVal = abi.encode(arguments);
        uint256 response = logic.checkPolicies(address(userContract), bytes(functionSignature), retVal);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_CheckPolicies_Explicit_StringComparison_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithStringComparison();
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.STR;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode("Bad Info");
        bytes memory retVal = abi.encode(arguments);
        uint256 response = logic.checkPolicies(address(userContract), bytes(functionSignature2), retVal);
        assertEq(response, 1);
    }

        function testRulesEngine_Unit_CheckPolicies_Explicit_StringComparison_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithStringComparison();
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.STR;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode("test");
        bytes memory retVal = abi.encode(arguments);
        uint256 response = logic.checkPolicies(address(userContract), bytes(functionSignature2), retVal);
        assertEq(response, 0);
    }

    function testRulesEngine_Unit_RetrieveRawStringFromInstructionSet() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 ruleId = setupRuleWithStringComparison();
        RulesStorageStructure.StringVerificationStruct memory retVal = logic.retrieveRawStringFromInstructionSet(ruleId, 3);
        console2.log(retVal.instructionSetValue);
        console2.log(retVal.rawData);
        assertEq(retVal.instructionSetValue, uint256(keccak256(abi.encode(retVal.rawData))));
    }

    function testRulesEngine_Unit_CheckPolicies_Explicit_AddressComparison_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithAddressComparison();
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.STR;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x1234567));
        arguments.values[1] = abi.encode("test");
        bytes memory retVal = abi.encode(arguments);
        uint256 response = logic.checkPolicies(address(userContract), bytes(functionSignature2), retVal);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_CheckPolicies_Explicit_AddressComparison_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithAddressComparison();
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.STR;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode("test");
        bytes memory retVal = abi.encode(arguments);
        uint256 response = logic.checkPolicies(address(userContract), bytes(functionSignature2), retVal);
        assertEq(response, 0);
    }

    function testRulesEngine_Unit_RetrieveRawAddressFromInstructionSet() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 ruleId = setupRuleWithAddressComparison();
        RulesStorageStructure.AddressVerificationStruct memory retVal = logic.retrieveRawAddressFromInstructionSet(ruleId, 3);
        console2.log(retVal.instructionSetValue);
        console2.log(retVal.rawData);
        assertEq(retVal.instructionSetValue, uint256(uint160(address(retVal.rawData))));
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCall();
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(5);
        bytes memory retVal = abi.encode(arguments);

        uint256 response = logic.checkPolicies(address(userContract), bytes(functionSignature), retVal);
        assertEq(response, 1);
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithForeignCallEffect() public ifDeploymentTestsEnabled endWithStopPrank {
        setupEffectWithForeignCall();
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(5);
        bytes memory retVal = abi.encode(arguments);
        // The Foreign call will be placed during the effect for the single rule in this policy.
        // The value being set in the foreign contract is then polled to verify that it has been udpated.
        logic.checkPolicies(address(userContract), bytes(functionSignature), retVal);
        assertEq(testContract.getInternalValue(), 5);
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithTrackerUpdateEffect() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = setupEffectWithTrackerUpdate();
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(5);
        bytes memory retVal = abi.encode(arguments);
        // The tracker will be updated during the effect for the single rule in this policy.
        // It will have the result of the foreign call (simpleCheck) added to it. 
        // original tracker value 2, added value 5, resulting updated tracker value should be 7
        logic.checkPolicies(address(userContract), bytes(functionSignature), retVal);
        RulesStorageStructure.Trackers memory tracker = logic.getTracker(policyId, 0);
        assertEq(tracker.trackerValue, abi.encode(7));
    }

    function testRulesEngine_Unit_CheckRules_Explicit_WithForeignCallNegative() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithForeignCall();
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        arguments.values = new bytes[](2);
        arguments.values[0] = abi.encode(address(0x7654321));
        arguments.values[1] = abi.encode(3);
        bytes memory retVal = abi.encode(arguments);
        vm.expectRevert(abi.encodePacked(revert_text)); 
        logic.checkPolicies(address(userContract), bytes(functionSignature), retVal);
    }

    /// Ensure that rule with a negative effect revert applied, that passes, will revert
    function testRulesEngine_Unit_CheckRules_WithExampleContract_Negative_Revert() public ifDeploymentTestsEnabled endWithStopPrank {
        _setupRuleWithRevert();
        vm.expectRevert(abi.encodePacked(revert_text)); 
        userContract.transfer(address(0x7654321), 3);
    }

    /// Ensure that rule with a positive effect event applied, that passes, will emit the event
    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        _setupRuleWithPosEvent();
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text);
        userContract.transfer(address(0x7654321), 5);
    }

    // Ensure that a policy with multiple rules with positive events fire in the correct order
    function testRulesEngine_Unit_CheckPolicy_ExecuteRuleOrder() public ifDeploymentTestsEnabled endWithStopPrank {
        _setupPolicyWithMultipleRulesWithPosEvents();
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text2);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text2);
        userContract.transfer(address(0x7654321), 11);
    }

    /// Ensure that rule with a positive effect event applied, that passes, will emit the event
    function testRulesEngine_Unit_CheckRules_WithExampleContract_Multiple_Positive_Event() public ifDeploymentTestsEnabled endWithStopPrank {
        _setupRuleWith2PosEvent();
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text2);
        userContract.transfer(address(0x7654321), 11);
    }

    function testRulesEngine_Unit_EncodingForeignCall() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSig(uint256,string,uint256,string,address)";

        RulesStorageStructure.PT[] memory parameterTypes = new RulesStorageStructure.PT[](5);
        parameterTypes[0] = RulesStorageStructure.PT.UINT;
        parameterTypes[1] = RulesStorageStructure.PT.STR;
        parameterTypes[2] = RulesStorageStructure.PT.UINT;
        parameterTypes[3] = RulesStorageStructure.PT.STR;
        parameterTypes[4] = RulesStorageStructure.PT.ADDR;

        bytes[] memory vals = new bytes[](5);
        vals[0] = abi.encode(1);
        vals[1] = abi.encode("test");
        vals[2] = abi.encode(2);
        vals[3] = abi.encode("superduperduperduperduperduperduperduperduperduperlongstring");
        vals[4] = abi.encode(address(0x1234567));

        uint256[] memory dynamicVarLengths = new uint256[](2);
        dynamicVarLengths[0] = 4;
        dynamicVarLengths[1] = 44;

        bytes4 FUNC_SELECTOR = bytes4(keccak256(bytes(functionSig)));

        bytes memory argsEncoded = logic.assemblyEncodeExt(parameterTypes, vals, FUNC_SELECTOR, dynamicVarLengths);
        
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        (bool response, bytes memory data) = address(foreignCall).call(argsEncoded);
        assertEq(foreignCall.getDecodedIntOne(), 1);
        assertEq(foreignCall.getDecodedIntTwo(), 2);
        assertEq(foreignCall.getDecodedStrOne(), "test");
        assertEq(foreignCall.getDecodedStrTwo(), "superduperduperduperduperduperduperduperduperduperlongstring");
        assertEq(foreignCall.getDecodedAddr(), address(0x1234567));
        response; 
        data; // added to silence warnings - we should have these in an assertion 
    }

    function testRulesEngine_Unit_EvaluateForeignCallForRule() public ifDeploymentTestsEnabled endWithStopPrank {
        RulesStorageStructure.ForeignCall memory fc;
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        string memory functionSig = "testSig(uint256,string,uint256,string,address)";

        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.foreignCallIndex = 0;
        fc.returnType = RulesStorageStructure.PT.BOOL;

        fc.parameterTypes = new RulesStorageStructure.PT[](5);
        fc.parameterTypes[0] = RulesStorageStructure.PT.UINT;
        fc.parameterTypes[1] = RulesStorageStructure.PT.STR;
        fc.parameterTypes[2] = RulesStorageStructure.PT.UINT;
        fc.parameterTypes[3] = RulesStorageStructure.PT.STR;
        fc.parameterTypes[4] = RulesStorageStructure.PT.ADDR;

        RulesStorageStructure.Arguments memory functionArguments;
        // rule signature function arguments (RS): string, uint256, uint256, string, uint256, string, address
        // foreign call function arguments (FC): uint256, string, uint256, string, address
        //
        // Mapping:
        // FC index: 0 1 2 3 4
        // RS index: 1 3 4 5 6

        // Build the rule signature function arguments structure
        functionArguments.argumentTypes = new RulesStorageStructure.PT[](7);
        functionArguments.argumentTypes[0] = RulesStorageStructure.PT.STR;
        functionArguments.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        functionArguments.argumentTypes[2] = RulesStorageStructure.PT.UINT;
        functionArguments.argumentTypes[3] = RulesStorageStructure.PT.STR;
        functionArguments.argumentTypes[4] = RulesStorageStructure.PT.UINT;
        functionArguments.argumentTypes[5] = RulesStorageStructure.PT.STR;
        functionArguments.argumentTypes[6] = RulesStorageStructure.PT.ADDR;

        functionArguments.values = new bytes[](6);
        functionArguments.values[0] = abi.encode("one");
        functionArguments.values[1] = abi.encode(2);
        functionArguments.values[2] = abi.encode(3);
        functionArguments.values[3] = abi.encode("four");
        functionArguments.values[4] = abi.encode(5);
        functionArguments.values[5] = abi.encode(address(0x12345678));

        RulesStorageStructure.Rule memory rule;

        // Build the mapping between calling function arguments and foreign call arguments
        rule.fcArgumentMappingsConditions = new RulesStorageStructure.ForeignCallArgumentMappings[](1);
        rule.fcArgumentMappingsConditions[0].foreignCallIndex = 0;
        rule.fcArgumentMappingsConditions[0].mappings = new RulesStorageStructure.IndividualArgumentMapping[](5);

        rule.fcArgumentMappingsConditions[0].mappings[0].functionCallArgumentType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.pType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.typeSpecificIndex = 1;

        rule.fcArgumentMappingsConditions[0].mappings[1].functionCallArgumentType = RulesStorageStructure.PT.STR;
        rule.fcArgumentMappingsConditions[0].mappings[1].functionSignatureArg.pType = RulesStorageStructure.PT.STR;
        rule.fcArgumentMappingsConditions[0].mappings[1].functionSignatureArg.typeSpecificIndex = 0;

        rule.fcArgumentMappingsConditions[0].mappings[2].functionCallArgumentType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[2].functionSignatureArg.pType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[2].functionSignatureArg.typeSpecificIndex = 2;

        rule.fcArgumentMappingsConditions[0].mappings[3].functionCallArgumentType = RulesStorageStructure.PT.STR;
        rule.fcArgumentMappingsConditions[0].mappings[3].functionSignatureArg.pType = RulesStorageStructure.PT.STR;
        rule.fcArgumentMappingsConditions[0].mappings[3].functionSignatureArg.typeSpecificIndex = 3;

        rule.fcArgumentMappingsConditions[0].mappings[4].functionCallArgumentType = RulesStorageStructure.PT.ADDR;
        rule.fcArgumentMappingsConditions[0].mappings[4].functionSignatureArg.pType = RulesStorageStructure.PT.ADDR;
        rule.fcArgumentMappingsConditions[0].mappings[4].functionSignatureArg.typeSpecificIndex = 5;

        RulesStorageStructure.ForeignCallReturnValue memory retVal = logic.evaluateForeignCallForRuleExt(fc, rule.fcArgumentMappingsConditions, functionArguments);
        console2.logBytes(retVal.value);
    }
    function _createGTRule(uint256 _amount) public ifDeploymentTestsEnabled endWithStopPrank returns(RulesStorageStructure.Rule memory rule) {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LC.PLH, 1, 0, LC.NUM, _amount, LC.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(RulesStorageStructure.LC.NUM);
        rule.instructionSet[3] = _amount;
        rule.instructionSet[4] = uint(RulesStorageStructure.LC.GT);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;
        rule.placeHolders = new RulesStorageStructure.Placeholder[](1);
        rule.placeHolders[0].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new uint256[](1);
        rule.posEffects = new uint256[](2);
        return rule;
    }

    /// Tracker Tests 

    // set up a rule with a uint256 tracker value for testing 
     function setupRuleWithTracker(uint256 trackerValue) public ifDeploymentTestsEnabled endWithStopPrank returns(uint256 policyId){
        uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicy();

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule;

        // Instruction set: LC.PLH, 1, 0, LC.PLH, 1, 0, LC.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(RulesStorageStructure.LC.PLH);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(RulesStorageStructure.LC.GT);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;
        
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
        // Build the tracker
        RulesStorageStructure.Trackers memory tracker; 

        /// build the members of the struct: 
        tracker.pType = RulesStorageStructure.PT.UINT; 
        tracker.trackerValue = abi.encode(trackerValue);
        // Add the tracker
        logic.addTracker(policyIds[0], tracker); 

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        logic.applyPolicy(address(userContract), policyIds);
        return policyIds[0];
    }

    function testRulesEngine_Unit_CheckRules_WithTrackerValue() public ifDeploymentTestsEnabled endWithStopPrank {
        setupRuleWithTracker(2);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text);
        bool retVal = userContract.transfer(address(0x7654321), 3);
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
        logic.updateTracker(policyId, 7, address(0x00), "", true, ""); 

        vm.expectRevert(abi.encodePacked(revert_text)); 
        retVal = userContract.transfer(address(0x7654321), 4);

        retVal = userContract.transfer(address(0x7654321), 9);
        assertTrue(retVal);

    }

    function testRulesEngine_Unit_GetTrackerValue() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 policyId = setupRuleWithTracker(2);
        bool retVal = userContract.transfer(address(0x7654321), 3);
        assertTrue(retVal);

        RulesStorageStructure.Trackers memory testTracker = logic.getTracker(policyId, 0); 

        assertTrue(abi.decode(testTracker.trackerValue, (uint256)) == 2); 
        assertFalse(abi.decode(testTracker.trackerValue, (uint256)) == 3); 

    }

    function testRulesEngine_Unit_UpdatePolicy_ValidatesForeignCalls() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicy();

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule;
        
        rule.placeHolders = new RulesStorageStructure.Placeholder[](2);
        rule.placeHolders[0].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[1].foreignCall = true;

        uint256 ruleId = logic.updateRule(0, rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        vm.expectRevert("Foreign Call referenced in rule not set");
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
    }

    function testRulesEngine_Unit_UpdatePolicy_ValidatesTrackers() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicy();

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0], bytes(functionSignature), pTypes);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule;

        // Instruction set: LC.PLH, 1, 0, LC.PLH, 1, 0, LC.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(RulesStorageStructure.LC.PLH);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(RulesStorageStructure.LC.GT);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;
        
        rule.placeHolders = new RulesStorageStructure.Placeholder[](2);
        rule.placeHolders[0].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[1].trackerValue = true;

        uint256 ruleId = logic.updateRule(0, rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        vm.expectRevert("Tracker referenced in rule not set");
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
    }



    /// Foreign call tests
    function testRulesEngine_ForeignCalls_getFCAddress() public ifDeploymentTestsEnabled endWithStopPrank {
        RulesStorageStructure.ForeignCallReturnValue memory retVal;
        retVal.pType = RulesStorageStructure.PT.ADDR;
        retVal.value = abi.encode(address(1));
        address addr = FCEncodingLib.getFCAddress(retVal);
        assertEq(addr, address(1));
    }

    function testRulesEngine_ForeignCalls_getFCAddress_wrongType() public ifDeploymentTestsEnabled endWithStopPrank {
        RulesStorageStructure.ForeignCallReturnValue memory retVal;
        retVal.pType = RulesStorageStructure.PT.UINT;
        retVal.value = abi.encode(uint256(1));
        vm.expectRevert();
        FCEncodingLib.getFCAddress(retVal);
    }

    function testRulesEngine_ForeignCalls_getFCString() public ifDeploymentTestsEnabled endWithStopPrank {
        RulesStorageStructure.ForeignCallReturnValue memory retVal;
        retVal.pType = RulesStorageStructure.PT.STR;
        retVal.value = abi.encode("hello");
        string memory str = FCEncodingLib.getFCString(retVal);
        assertEq(str, "hello");
    }

    function testRulesEngine_ForeignCalls_getFCString_negative() public ifDeploymentTestsEnabled endWithStopPrank {
        RulesStorageStructure.ForeignCallReturnValue memory retVal;
        retVal.pType = RulesStorageStructure.PT.UINT;
        retVal.value = abi.encode(uint256(1));
        vm.expectRevert();
        FCEncodingLib.getFCString(retVal);
    }

    function testRulesEngine_ForeignCalls_getFCUint() public ifDeploymentTestsEnabled endWithStopPrank {
        RulesStorageStructure.ForeignCallReturnValue memory retVal;
        retVal.pType = RulesStorageStructure.PT.UINT;
        retVal.value = abi.encode(uint256(1));
        uint256 uintVal = FCEncodingLib.getFCUint(retVal);
        assertEq(uintVal, 1);
    }

    function testRulesEngine_ForeignCalls_getFCUint_negative() public ifDeploymentTestsEnabled endWithStopPrank {
        RulesStorageStructure.ForeignCallReturnValue memory retVal;
        retVal.pType = RulesStorageStructure.PT.STR;
        retVal.value = abi.encode("hello");
        vm.expectRevert();
        FCEncodingLib.getFCUint(retVal);
    }

    function testRulesEngine_ForeignCalls_getFCBool() public ifDeploymentTestsEnabled endWithStopPrank {
        RulesStorageStructure.ForeignCallReturnValue memory retVal;
        retVal.pType = RulesStorageStructure.PT.BOOL;
        retVal.value = abi.encode(true);
        bool boolVal = FCEncodingLib.getFCBool(retVal);
        assertEq(boolVal, true);
    }

    function testRulesEngine_ForeignCalls_getFCBool_negative() public ifDeploymentTestsEnabled endWithStopPrank {
        RulesStorageStructure.ForeignCallReturnValue memory retVal;
        retVal.pType = RulesStorageStructure.PT.UINT;
        retVal.value = abi.encode(uint256(1));
        vm.expectRevert();
        FCEncodingLib.getFCBool(retVal);
    }


}
