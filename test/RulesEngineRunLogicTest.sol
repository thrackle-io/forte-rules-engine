/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "src/RulesEngineRunLogic.sol";
import "src/ExampleUserContract.sol";
import "forge-std/Test.sol";
import "test/ForeignCallTestContract.sol";
import "src/effects/EffectStructures.sol";
import "test/RulesEngineRunLogicWrapper.sol";

/**
 * @title Test the functionality of the RulesEngineRunLogic contract
 * @author @mpetersoCode55 
 */
contract RulesEngineRunLogicTest is Test,EffectStructures {

    RulesEngineRunLogicWrapper logic;
    ExampleUserContract userContract;
    ForeignCallTestContract testContract;

    address contractAddress = address(0x1234567);
    string functionSignature = "transfer(address,uint256) returns (bool)";

    string constant event_text = "Rules Engine Event";
    string constant revert_text = "Rules Engine Revert";
    string constant event_text2 = "Rules Engine Event 2";
    string constant revert_text2 = "Rules Engine Revert 2";
    uint256 effectId_revert;
    uint256 effectId_revert2;
    uint256 effectId_event;
    uint256 effectId_event2;
    bytes[] signatures;        
    uint256[] functionSignatureIds;
    uint256[][] ruleIds;

    uint256 effectId_expression;
    uint256 effectId_expression2;

    function setUp() public{
        logic = new RulesEngineRunLogicWrapper();
        userContract = new ExampleUserContract();
        userContract.setRulesEngineAddress(address(logic));
        testContract = new ForeignCallTestContract();
        _setupEffectProcessor();
    }

    function setupRuleWithoutForeignCall() public {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule;
        
        // Instruction set: LC.PLH, 1, 0, LC.NUM, 4, LC.GT, 0, 1

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](8);
        rule.instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = 0;
        rule.instructionSet[3] = uint(RulesStorageStructure.LC.NUM);
        rule.instructionSet[4] = 4;
        rule.instructionSet[5] = uint(RulesStorageStructure.LC.GT);
        rule.instructionSet[6] = 0;
        rule.instructionSet[7] = 1;

        // Build the calling function argument placeholder 
        rule.placeHolders = new RulesStorageStructure.Placeholder[](1);
        rule.placeHolders[0].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 0;
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
    }


    // Test attempt to add a policy with no signatures saved.
    function testUpdatePolicyInvalidRule() public {
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
        logic.updatePolicy(0, signatures, functionSignatureIds, ruleIds);
    }

    // Test attempt to add a policy with no signatures saved.
    function testUpdatePolicyInvalidSignature() public {
        signatures.push(bytes(functionSignature));  
        functionSignatureIds.push(1);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= 1;
        vm.expectRevert("Invalid Signature");
        logic.updatePolicy(0, signatures, functionSignatureIds, ruleIds);
    }

    // Test attempt to add a policy with valid parts.
    function testUpdatePolicyPositive() public {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule;
        
        // Instruction set: LC.PLH, 1, 0, LC.NUM, 4, LC.GT, 0, 1

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](8);
        rule.instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = 0;
        rule.instructionSet[3] = uint(RulesStorageStructure.LC.NUM);
        rule.instructionSet[4] = 4;
        rule.instructionSet[5] = uint(RulesStorageStructure.LC.GT);
        rule.instructionSet[6] = 0;
        rule.instructionSet[7] = 1;

        // Build the calling function argument placeholder 
        rule.placeHolders = new RulesStorageStructure.Placeholder[](1);
        rule.placeHolders[0].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 0;
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

    function setupEffectWithTrackerUpdate() public returns (uint256) {
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
        rule.fcArgumentMappingsEffects[0].mappings[0].functionSignatureArg.typeSpecificIndex = 0;
        uint256 ruleId = logic.updateRule(0, rule);

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;

        //build tracker 
        RulesStorageStructure.Trackers memory tracker;  
        /// build the members of the struct: 
        tracker.pType = RulesStorageStructure.PT.UINT; 
        tracker.uintTracker = 2; 

        

        uint256 functionSignatureId = logic.updateFunctionSignature(0, bytes4(bytes(functionSignature)),pTypes);
        // // Save the Policy
        signatures.push(bytes(functionSignature));  
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        uint256[] memory policyIds = new uint256[](1);
        uint256 policyId = logic.updatePolicy(0, signatures, functionSignatureIds, ruleIds); 
        logic.addTracker(policyId, tracker);      
        RulesStorageStructure.ForeignCall memory fc = logic.updateForeignCall(policyId, address(testContract), "simpleCheck(uint256)", RulesStorageStructure.PT.UINT, fcArgs);
        policyIds[0] = policyId;
        logic.applyPolicy(address(userContract), policyIds);
        return policyId;
    }

    function setupEffectWithForeignCall() public {
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
        rule.fcArgumentMappingsEffects[0].mappings[0].functionSignatureArg.typeSpecificIndex = 0;
        uint256 ruleId = logic.updateRule(0, rule);

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;

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

    }

    function setupRuleWithForeignCall() public {
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"        
        RulesStorageStructure.Rule memory rule;
        
        // Build the foreign call placeholder
        rule.placeHolders = new RulesStorageStructure.Placeholder[](1); 
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 0;

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](8);
        rule.instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = 0;
        rule.instructionSet[3] = uint(RulesStorageStructure.LC.NUM);
        rule.instructionSet[4] = 4;
        rule.instructionSet[5] = uint(RulesStorageStructure.LC.GT);
        rule.instructionSet[6] = 0;
        rule.instructionSet[7] = 1;

        // Build the mapping between calling function arguments and foreign call arguments
        rule.fcArgumentMappingsConditions = new RulesStorageStructure.ForeignCallArgumentMappings[](1);
        rule.fcArgumentMappingsConditions[0].mappings = new RulesStorageStructure.IndividualArgumentMapping[](1);
        rule.fcArgumentMappingsConditions[0].mappings[0].functionCallArgumentType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.foreignCall = false;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.pType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.typeSpecificIndex = 0;
        rule.negEffects = new uint256[](1);
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
        uint256 policyId = logic.updatePolicy(0, signatures, functionSignatureIds, ruleIds);
        RulesStorageStructure.PT[] memory fcArgs = new RulesStorageStructure.PT[](1);
        fcArgs[0] = RulesStorageStructure.PT.UINT;
        RulesStorageStructure.ForeignCall memory fc = logic.updateForeignCall(policyId, address(testContract), "simpleCheck(uint256)", RulesStorageStructure.PT.UINT, fcArgs);        
        policyIds[0] = policyId;
        logic.applyPolicy(address(userContract), policyIds);
    }

    function _setupRuleWithRevert() public {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule =  _createGTRule(4);
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
    }

    function _setupRuleWithPosEvent() public {
        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule =  _createGTRule(4);
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
    }

    function _setupRuleWith2PosEvent() public {
        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule =  _createGTRule(4);
        rule.posEffects[0] = effectId_event;
        rule.posEffects[1] = effectId_event2;
       
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
    }

    function testCheckRulesExplicit() public {
        setupRuleWithoutForeignCall();
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        arguments.addresses = new address[](1);
        arguments.addresses[0] = address(0x7654321);
        arguments.ints = new uint256[](1);
        arguments.ints[0] = 5;
        bytes memory retVal = RuleEncodingLibrary.customEncoder(arguments);
        bool response = logic.checkPolicies(contractAddress, bytes(functionSignature), retVal);
        assertTrue(response);
    }

    function testCheckRulesExplicitWithForeignCallPositive() public {
        setupRuleWithForeignCall();
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        arguments.addresses = new address[](1);
        arguments.addresses[0] = address(0x7654321);
        arguments.ints = new uint256[](1);
        arguments.ints[0] = 5;
        bytes memory retVal = RuleEncodingLibrary.customEncoder(arguments);

        bool response = logic.checkPolicies(address(userContract), bytes(functionSignature), retVal);
        assertTrue(response);
    }

    function testCheckRulesExplicitWithForeignCallEffect() public {
        setupEffectWithForeignCall();
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        arguments.addresses = new address[](1);
        arguments.addresses[0] = address(0x7654321);
        arguments.ints = new uint256[](1);
        arguments.ints[0] = 5;
        bytes memory retVal = RuleEncodingLibrary.customEncoder(arguments);

        bool response = logic.checkPolicies(address(userContract), bytes(functionSignature), retVal);
        assertEq(testContract.getInternalValue(), 5);
    }

    function testCheckRulesExplicitWithTrackerUpdateEffect() public {
        uint256 policyId = setupEffectWithTrackerUpdate();
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        arguments.addresses = new address[](1);
        arguments.addresses[0] = address(0x7654321);
        arguments.ints = new uint256[](1);
        arguments.ints[0] = 5;
        bytes memory retVal = RuleEncodingLibrary.customEncoder(arguments);

        bool response = logic.checkPolicies(address(userContract), bytes(functionSignature), retVal);
        RulesStorageStructure.Trackers memory trackerValue = logic.getTracker(policyId, 0);
        assertEq(trackerValue.uintTracker, 7);
    }

    function testCheckRulesExplicitWithForeignCallNegative() public {
        setupRuleWithForeignCall();
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        arguments.addresses = new address[](1);
        arguments.addresses[0] = address(0x7654321);
        arguments.ints = new uint256[](1);
        arguments.ints[0] = 3;
        bytes memory retVal = RuleEncodingLibrary.customEncoder(arguments);
        vm.expectRevert(abi.encodePacked(revert_text)); 
        logic.checkPolicies(address(userContract), bytes(functionSignature), retVal);
    }

    /// Ensure that rule with a negative effect revert applied, that passes, will revert
    function testCheckRulesWithExampleContractNegativeRevert() public {
        _setupRuleWithRevert();
        vm.expectRevert(abi.encodePacked(revert_text)); 
        userContract.transfer(address(0x7654321), 3);
    }

    /// Ensure that rule with a positive effect event applied, that passes, will emit the event
    function testCheckRulesWithExampleContractPositiveEvent() public {
        _setupRuleWithPosEvent();
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text);
        userContract.transfer(address(0x7654321), 5);
    }

    /// Ensure that rule with a positive effect event applied, that passes, will emit the event
    function testCheckRulesWithExampleContractMultiplePositiveEvent() public {
        _setupRuleWith2PosEvent();
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text2);
        userContract.transfer(address(0x7654321), 11);
    }

    function testEncodingForeignCall() public {
        string memory functionSig = "testSig(uint256,string,uint256,string,address)";

        uint256[] memory vals = new uint256[](3);
        vals[0] = 1;
        vals[1] = 2;
        vals[2] = 3;

        uint256[] memory params = new uint256[](5);
        params[0] = 0;
        params[1] = 2;
        params[2] = 0;
        params[3] = 2;
        params[4] = 1;

        address[] memory addresses = new address[](1);
        addresses[0] = address(0x1234567);

        string[] memory strings = new string[](2);
        strings[0] = "test";
        strings[1] = "otherTest";
        bytes memory argsEncoded = logic.assemblyEncodeExt(params, vals, addresses, strings);
        bytes4 FUNC_SELECTOR = bytes4(keccak256(bytes(functionSig)));
        bytes memory encoded;
        encoded = bytes.concat(encoded, FUNC_SELECTOR);
        encoded = bytes.concat(encoded, argsEncoded);
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        (bool response, bytes memory data) = address(foreignCall).call(encoded);
        assertEq(foreignCall.getDecodedIntOne(), 1);
        assertEq(foreignCall.getDecodedIntTwo(), 2);
        assertEq(foreignCall.getDecodedStrOne(), "test");
        assertEq(foreignCall.getDecodedStrTwo(), "otherTest");
        assertEq(foreignCall.getDecodedAddr(), address(0x1234567));
        response; 
        data; // added to silence warnings - we should have these in an assertion 
    }

    function testEvaluateForeignCallForRule() public {
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

        functionArguments.addresses = new address[](1);
        functionArguments.addresses[0] = address(0x12345678);

        functionArguments.strings = new string[](3);
        functionArguments.strings[0] = "one";
        functionArguments.strings[1] = "two";
        functionArguments.strings[2] = "three";

        functionArguments.ints = new uint256[](3);
        functionArguments.ints[0] = 1;
        functionArguments.ints[1] = 2;
        functionArguments.ints[2] = 3;

        RulesStorageStructure.Rule memory rule;

        // Build the mapping between calling function arguments and foreign call arguments
        rule.fcArgumentMappingsConditions = new RulesStorageStructure.ForeignCallArgumentMappings[](1);
        rule.fcArgumentMappingsConditions[0].foreignCallIndex = 0;
        rule.fcArgumentMappingsConditions[0].mappings = new RulesStorageStructure.IndividualArgumentMapping[](5);

        rule.fcArgumentMappingsConditions[0].mappings[0].functionCallArgumentType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.pType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.typeSpecificIndex = 0;

        rule.fcArgumentMappingsConditions[0].mappings[1].functionCallArgumentType = RulesStorageStructure.PT.STR;
        rule.fcArgumentMappingsConditions[0].mappings[1].functionSignatureArg.pType = RulesStorageStructure.PT.STR;
        rule.fcArgumentMappingsConditions[0].mappings[1].functionSignatureArg.typeSpecificIndex = 1;

        rule.fcArgumentMappingsConditions[0].mappings[2].functionCallArgumentType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[2].functionSignatureArg.pType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[2].functionSignatureArg.typeSpecificIndex = 2;

        rule.fcArgumentMappingsConditions[0].mappings[3].functionCallArgumentType = RulesStorageStructure.PT.STR;
        rule.fcArgumentMappingsConditions[0].mappings[3].functionSignatureArg.pType = RulesStorageStructure.PT.STR;
        rule.fcArgumentMappingsConditions[0].mappings[3].functionSignatureArg.typeSpecificIndex = 2;

        rule.fcArgumentMappingsConditions[0].mappings[4].functionCallArgumentType = RulesStorageStructure.PT.ADDR;
        rule.fcArgumentMappingsConditions[0].mappings[4].functionSignatureArg.pType = RulesStorageStructure.PT.ADDR;
        rule.fcArgumentMappingsConditions[0].mappings[4].functionSignatureArg.typeSpecificIndex = 0;

        RulesStorageStructure.ForeignCallReturnValue memory retVal = logic.evaluateForeignCallForRuleExt(fc, rule.fcArgumentMappingsConditions, functionArguments);
        console2.log(retVal.boolValue);
    }
    function _createGTRule(uint256 _amount) public returns(RulesStorageStructure.Rule memory){
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LC.PLH, 1, 0, LC.NUM, _amount, LC.GT, 0, 1
        rule.instructionSet = new uint256[](8);
        rule.instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = 0;
        rule.instructionSet[3] = uint(RulesStorageStructure.LC.NUM);
        rule.instructionSet[4] = _amount;
        rule.instructionSet[5] = uint(RulesStorageStructure.LC.GT);
        rule.instructionSet[6] = 0;
        rule.instructionSet[7] = 1;
        rule.placeHolders = new RulesStorageStructure.Placeholder[](1);
        rule.placeHolders[0].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Add a negative/positive effects
        rule.negEffects = new uint256[](1);
        rule.posEffects = new uint256[](2);
        return rule;
    }

    function _setupEffectProcessor() public {
        _createAllEffects();
    }

    function _createAllEffects() public {
        effectId_event = _createEffectEvent(event_text); // effectId = 1
        effectId_revert = _createEffectRevert(revert_text); // effectId = 2
        effectId_event2 = _createEffectEvent(event_text2); // effectId = 3
        effectId_revert2 = _createEffectRevert(revert_text2); // effectId = 4
        effectId_expression = _createEffectExpression(); // effectId = 5;
        effectId_expression2 = _createEffectExpressionTrackerUpdate();

    }

    function _createEffectEvent(string memory _text) public returns(uint256 _effectId){
        uint256[] memory emptyArray = new uint256[](1);
        // Create a event effect
        return logic.updateEffect(Effect({effectId: 0, effectType: ET.EVENT, text: _text, instructionSet: emptyArray}));
    }

    function _createEffectRevert(string memory _text) public returns(uint256 _effectId) {
        uint256[] memory emptyArray = new uint256[](1);
        // Create a revert effect
        return logic.updateEffect(Effect({effectId: 0, effectType: ET.REVERT, text: _text, instructionSet: emptyArray}));
    }

    function _createEffectExpression() public returns(uint256 _effectId) {
        EffectStructures.Effect memory effect;

        effect.effectId = 0;
        effect.effectType = ET.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](1);

        return logic.updateEffect(effect);
    }

    function _createEffectExpressionTrackerUpdate() public returns(uint256 _effectId) {
        EffectStructures.Effect memory effect;
        effect.effectId = 0;
        effect.effectType = ET.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](12);
        // Foreign Call Placeholder
        effect.instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        effect.instructionSet[1] = 0;
        effect.instructionSet[2] = 0;
        // Tracker Placeholder
        effect.instructionSet[3] = uint(RulesStorageStructure.LC.PLH);
        effect.instructionSet[4] = 1;
        effect.instructionSet[5] = 1;
        effect.instructionSet[6] = uint(RulesStorageStructure.LC.ADD);
        effect.instructionSet[7] = 0;
        effect.instructionSet[8] = 1;
        effect.instructionSet[9] = uint(RulesStorageStructure.LC.TRU);
        effect.instructionSet[10] = 0;
        effect.instructionSet[11] = 2;

        return logic.updateEffect(effect);
    }

    /// Tracker Tests 

    // set up a rule with a uint256 tracker value for testing 
     function setupRuleWithTracker(uint256 trackerValue) public returns(uint256 policyId){
        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule;

        // Instruction set: LC.PLH, 1, 0, LC.PLH, 1, 0, LC.GT, 0, 1
        rule.instructionSet = new uint256[](9);
        rule.instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = 0;
        rule.instructionSet[3] = uint(RulesStorageStructure.LC.PLH);
        rule.instructionSet[4] = 1;
        rule.instructionSet[5] = 1;
        rule.instructionSet[6] = uint(RulesStorageStructure.LC.GT);
        rule.instructionSet[7] = 0;
        rule.instructionSet[8] = 1;
        
        rule.placeHolders = new RulesStorageStructure.Placeholder[](2);
        rule.placeHolders[0].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 0;
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
        tracker.uintTracker = trackerValue; 
        // Add the tracker
        logic.addTracker(policyId, tracker);
        functionSignatureId = logic.updateFunctionSignature(0, bytes4(bytes(functionSignature)),pTypes);
        policyIds[0] = policyId;     
        logic.applyPolicy(address(userContract), policyIds);
        return policyId;
    }

    function testCheckRulesWithTrackerValue() public {
        setupRuleWithTracker(2);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(event_text);
        bool retVal = userContract.transfer(address(0x7654321), 3);
        assertTrue(retVal);
    }

    function testCheckRulesWithTrackerValueNegative() public {
        setupRuleWithTracker(7);
        vm.expectRevert(abi.encodePacked(revert_text)); 
        userContract.transfer(address(0x7654321), 6);
    }

    function testManualUpdateToTrackerThenCheckRules() public {
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

    function testGetTrackerValue() public {
        uint256 policyId = setupRuleWithTracker(2);
        bool retVal = userContract.transfer(address(0x7654321), 3);
        assertTrue(retVal);

        RulesStorageStructure.Trackers memory testTracker = logic.getTracker(policyId, 0); 

        assertTrue(testTracker.uintTracker == 2); 
        assertTrue(testTracker.addressTracker == address(0x00)); 
        assertFalse(testTracker.uintTracker == 3); 

    }
}
