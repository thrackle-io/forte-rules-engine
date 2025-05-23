// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "lib/forge-std/src/Test.sol";
import "lib/forge-std/src/console2.sol";
import "test/utils/ForeignCallTestCommon.sol";
import "src/utils/DiamondMine.sol";
import "src/utils/FCEncodingLib.sol";
import "src/engine/facets/RulesEngineComponentFacet.sol";

/**
 * Shared testing logic, set ups, helper functions and global test variables for Rules Engine Testing Framework
 * Code used across multiple testing directories belogns here
 */

contract RulesEngineCommon is DiamondMine, Test { 
    // contract objects 
    ForeignCallTestContract testContract; 
    ForeignCallTestContractOFAC testContract2;

    // strings 
    string functionSignature = "transfer(address,uint256)";
    string functionSignature2 = "updateInfo(address _to, string info)";
    string functionSignature3 = "transferFrom(address,uint256)";
    string functionSignatureBytes = "transferBytes(address,uint256)";
    string functionSignatureWithBytes = "transferWithBytes(address,uint256,bytes)";
    string functionSignatureString = "transferString(address,uint256)";
    string functionSignatureWithString = "transferWithString(address,uint256,string)";
    string functionSignatureBool = "transferBool(address,uint256)";
    string functionSignatureArrayStatic = "transferArray(address,uint256)";
    string functionSignatureArrayDynamic = "transferDynamicArray(address,uint256)";
    string constant event_text = "Rules Engine Event";
    string constant revert_text = "Rules Engine Revert";
    string constant event_text2 = "Rules Engine Event 2";
    string constant revert_text2 = "Rules Engine Revert 2";
    string constant customEventText = "Custom Event"; 

    //bytes32 
    bytes32 public constant EVENTTEXT = bytes32("Rules Engine Event"); 
    bytes32 public constant EVENTTEXT2 = bytes32("Rules Engine Event 2");

    //bytes4 
    bytes4[] signatures;

    // Effect structures 
    Effect effectId_revert;
    Effect effectId_revert2;
    Effect effectId_event;
    Effect effectId_event2;
    Effect effectId_Log1;
    Effect effectId_Log2;
    Effect effectId_Log3;
    Effect effectId_Log;
    Effect effectId_expression;
    Effect effectId_expression2;
    Effect effectId_expression3;
    Effect effectId_expression4;
    
    //uint256 arrays 
    uint256[] functionSignatureIds;
    uint256[][] ruleIds;

    // uint256
    uint256 ruleValue = 10; 
    uint256 transferValue = 15;
    uint256 constant ATTO = 10 ** 18;

    // bool
    bool public testDeployments = true;

    // address arrays 
    address[] testAddressArray = [
        address(0xFF1),
        address(0xFF2),
        address(0xFF3),
        address(0xFF4),
        address(0xFF5),
        address(0xFF6),
        address(0xFF7),
        address(0xFF8)
    ];

    // addresses 
    address user1 = address(0x001);
    address policyAdmin = address(0x54321);
    address newPolicyAdmin = address(0x0Add);
    address callingContractAdmin = address(0x12345);
    address constant USER_ADDRESS = address(0xd00d); 
    address constant USER_ADDRESS_2 = address(0xBADd00d);
    address userContractAddress;
    address newUserContractAddress;
    address userContractExtraParamAddress;

    //test modifiers 
    modifier ifDeploymentTestsEnabled() {
        if (testDeployments) {
            _;
        }
    }

    modifier endWithStopPrank() {
        _;
        vm.stopPrank();
    }

    modifier resetsGlobalVariables() {
        _resetGlobalVariables();
        _;
    }

    /// Set up functions
    function setupRuleWithoutForeignCall()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // Initial setup for what we'll need later
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        policyIds[0] = _createBlankPolicy();
        // Add the function signature to the policy
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0]);
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Instruction set: LC.PLH, 0, LC.NUM, 4, LC.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        // Apply the policy 
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        
    }

    function setUpRuleSimple()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        returns (uint256 policyId, uint256 ruleId)
    {
        // Initial setup for what we'll need later
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        policyIds[0] = _createBlankPolicy();
        // Add the function signature to the policy
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0]);
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Instruction set: LC.PLH, 0, LC.NUM, 4, LC.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        
        // Apply the policy 
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return (policyIds[0], ruleId);
    }

    function setUpRuleSimpleGTEQL()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        returns (uint256 policyId, uint256 ruleId)
    {
        // Initial setup for what we'll need later
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        policyIds[0] = _createBlankPolicy();
        // Add the function signature to the policy
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0]);
        // Rule: amount >= 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Instruction set: LC.PLH, 0, LC.GTEQL, 4, LC.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet("GTEQL", 4, LC.GTEQL);
        
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        
        // Apply the policy 
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return (policyIds[0], ruleId);
    }

    function setUpRuleSimpleLTEQL()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        returns (uint256 policyId, uint256 ruleId)
    {
        // Initial setup for what we'll need later
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        policyIds[0] = _createBlankPolicy();
        // Add the function signature to the policy
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0]);
        // Rule: amount <= 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Instruction set: LC.PLH, 0, LC.LTEQL, 4, LC.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet("LTEQL", 4, LC.LTEQL);
        
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        
        // Apply the policy 
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        

        return (policyIds[0], ruleId);
    }

    function setupRuleWithStringComparison()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        returns (uint256 ruleId)
    {
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        policyIds[0] = _createBlankPolicy();
        // Rule: info == "Bad Info" -> revert -> updateInfo(address _to, string info) returns (bool)"
        Rule memory rule;
        // Instruction set: LC.PLH, 0, LC.NUM, *uint256 representation of Bad Info*, LC.EQ, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = uint256(keccak256(abi.encode("Bad Info")));
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.rawData.argumentTypes = new PT[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = PT.STR;
        rule.rawData.dataValues[0] = abi.encode("Bad Info");
        rule.rawData.instructionSetIndex[0] = 3;

        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.STR;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        ruleId = RulesEnginePolicyFacet(address(red)).updateRule(policyIds[0], 0, rule);

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.STR;
        // Save the function signature
        uint256 functionSignatureId = RulesEngineComponentFacet(address(red))
            .createFunctionSignature(
                policyIds[0],
                bytes4(keccak256(bytes(functionSignature2))),
                pTypes,
                functionSignature2,
                ""
            );
        // Save the Policy
        signatures.push(bytes4(keccak256(bytes(functionSignature2))));
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], signatures, functionSignatureIds, ruleIds, PolicyType.CLOSED_POLICY); 
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);       
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        return ruleId;
    }

    function setupRuleWithAddressComparison()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        returns (uint256 ruleId)
    {
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        policyIds[0] = _createBlankPolicy();
        // Rule: _to == 0x1234567 -> revert -> updateInfo(address _to, string info) returns (bool)"
        Rule memory rule;
        // Instruction set: LC.PLH, 0, LC.NUM, *uint256 representation of 0x1234567o*, LC.EQ, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = uint256(uint160(address(0x1234567)));
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.rawData.argumentTypes = new PT[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = PT.ADDR;
        rule.rawData.dataValues[0] = abi.encode(0x1234567);
        rule.rawData.instructionSetIndex[0] = 3;

        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Save the rule
        ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.STR;
        // Save the function signature
        uint256 functionSignatureId = RulesEngineComponentFacet(address(red))
            .createFunctionSignature(
                policyIds[0],
                bytes4(keccak256(bytes(functionSignature2))),
                pTypes,
                functionSignature2,
                ""
            );
        // Save the Policy
        signatures.push(bytes4(keccak256(bytes(functionSignature2))));
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], signatures, functionSignatureIds, ruleIds, PolicyType.CLOSED_POLICY);    
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);    
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        return ruleId;
    }

    function setupEffectWithTrackerUpdateUint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        resetsGlobalVariables
        returns (uint256 ruleId)
    {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0]);

        // Rule: 1 == 1 -> TRU:someTracker += FC:simpleCheck(amount) -> transfer(address _to, uint256 amount) returns (bool)

        Rule memory rule;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_expression2;
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.effectPlaceHolders = new Placeholder[](2);
        rule.effectPlaceHolders[0].pType = PT.ADDR;
        rule.effectPlaceHolders[0].typeSpecificIndex = 2;
        rule.effectPlaceHolders[1].pType = PT.ADDR;
        rule.effectPlaceHolders[1].trackerValue = true;
        rule.effectPlaceHolders[1].typeSpecificIndex = 1;

        ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = PT.UINT;
        tracker.trackerValue = abi.encode(2);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName");      
        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 1;

        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineComponentFacet(address(red)).createForeignCall(policyIds[0], fc, "simpleCheck(uint256)");

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        fc;  //added to silence warnings during testing revamp 
        return policyIds[0];
    }

    function setupEffectWithTrackerUpdate(uint256 _policyId, Trackers memory tracker)
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        resetsGlobalVariables
        returns (uint256 ruleId)
    {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _policyId;

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0]);

        // Rule: 1 == 1 -> TRU:someTracker += FC:simpleCheck(amount) -> transfer(address _to, uint256 amount) returns (bool)

        Rule memory rule;
        rule.posEffects = new Effect[](1);
        rule.posEffects[0] = effectId_expression2;
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.effectPlaceHolders = new Placeholder[](2);
        rule.effectPlaceHolders[0].pType = PT.UINT;
        rule.effectPlaceHolders[0].foreignCall = true;
        rule.effectPlaceHolders[0].typeSpecificIndex = 1;
        rule.effectPlaceHolders[1].pType = PT.UINT;
        rule.effectPlaceHolders[1].trackerValue = true;
        rule.effectPlaceHolders[1].typeSpecificIndex = 1;


        ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName");      
        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 1;

        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineComponentFacet(address(red)).createForeignCall(policyIds[0], fc, "simpleCheck(uint256)");

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        fc;  //added to silence warnings during testing revamp 
        return policyIds[0];
    }

    function setupRuleWithForeignCall(
        uint256 _amount,
        ET _effectType,
        bool isPositive
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables returns(uint256 policyId) {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0]);

        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 1;

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(_amount);

        rule = _setUpEffect(rule, _effectType, isPositive);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 1;
        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineComponentFacet(address(red)).createForeignCall(policyIds[0], fc, "simpleCheck(uint256)");
        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);


        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);       
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        return policyIds[0];
    }

    function _setUpEffect(
        Rule memory rule,
        ET _effectType,
        bool isPositive
    ) public view returns (Rule memory _rule) {
        if (isPositive) {
            rule.posEffects = new Effect[](1);
            if (_effectType == ET.REVERT) {
                rule.posEffects[0] = effectId_revert;
            }
            if (_effectType == ET.EVENT) {
                rule.posEffects[0] = effectId_event;
            }
        } else {
            rule.negEffects = new Effect[](1);
            if (_effectType == ET.REVERT) {
                rule.negEffects[0] = effectId_revert;
            }
            if (_effectType == ET.EVENT) {
                rule.negEffects[0] = effectId_event;
            }
        }
        return rule;
    }

    function _setupRuleWithRevert(address userContractMinTransferAddress)
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicyOpen();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0]);

        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        // Rule memory rule = _createGTRule(policyIds[0], 4);
        Rule memory rule;
        // Instruction set: LC.PLH, 0, LC.NUM, _amount, LC.GT, 0, 1
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = 4;
        rule.instructionSet[4] = uint(LC.GT); // register 2
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;
        rule.posEffects[0] = effectId_revert;
        
        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractMinTransferAddress, policyIds);
    }

    function _setupRuleWithPosEvent()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        resetsGlobalVariables
    {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0]);

        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule = _createGTRule(4);
        rule.posEffects[0] = effectId_event;

        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _setupRuleWithPosEventParams(bytes memory param, PT pType) 
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        resetsGlobalVariables
    {

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0]);

        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule = _createGTRuleWithCustomEventParams(4, param, pType);
        rule.posEffects[0] = effectId_event;

        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _setupRuleWithPosEventDynamicParamsFromCallingFunctionParams(PT pType) 
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        resetsGlobalVariables
    {

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0]);
        Rule memory rule;
        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        if(pType == PT.ADDR){
            rule = _createGTRuleWithDynamicEventParamsAddress(4);
            rule.posEffects[0] = effectId_event;
        } else{
            rule = _createGTRuleWithDynamicEventParams(4);
            rule.posEffects[0] = effectId_event;
        } 
        
        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _setupMinTransferWithPosEvent(
        uint256 threshold,
        address contractAddress
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0]);

        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule = _createGTRule(threshold);
        rule.posEffects[0] = effectId_event;

        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        if (ruleIds.length == 0) ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(contractAddress), policyIds);
    }

    function _resetGlobalVariables() public {
        delete signatures;
        delete functionSignatureIds;
        delete ruleIds;
    }

    function _setupPolicyWithMultipleRulesWithPosEvents()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        resetsGlobalVariables
    {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0]);

        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        // Rule 1: GT 4
        Rule memory rule = _createGTRule(4);
        rule.posEffects[0] = effectId_event;

        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](4));
        ruleIds[0][0] = ruleId;

        // Rule 2: GT 5
        rule = _createGTRule(5);
        rule.posEffects[0] = effectId_event2;

        // Save the rule
        ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        // // Save the fKureIds.push(functionSignatureId);
        ruleIds[0][1] = ruleId;

        // Rule 3: GT 6
        rule = _createGTRule(6);
        rule.posEffects[0] = effectId_event;

        // Save the rule
        ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        // // Save the fKureIds.push(functionSignatureId);
        ruleIds[0][2] = ruleId;

        // Rule 4: GT 7
        rule = _createGTRule(7);
        rule.posEffects[0] = effectId_event2;

        // Save the rule
        ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        // // Save the fKureIds.push(functionSignatureId);
        ruleIds[0][3] = ruleId;

        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _setupRuleWith2PosEvent()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        resetsGlobalVariables
    {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0]);

        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule = _createGTRule(4);
        rule.posEffects = new Effect[](2);
        rule.posEffects[0] = effectId_event;
        rule.posEffects[1] = effectId_event2;

        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    // set up a rule with a uint256 tracker value for testing
    function setupRuleWithTracker(
        uint256 trackerValue
    )
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        resetsGlobalVariables
        returns (uint256 policyId)
    {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Instruction set: LC.PLH, 0, LC.PLH, 1, LC.GT, 0, 1
        rule.instructionSet = _createInstructionSet(0, 1);

        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].trackerValue = true;
        rule.placeHolders[1].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;

        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);
        // Build the tracker
        Trackers memory tracker;

        /// build the members of the struct:
        tracker.pType = PT.UINT;
        tracker.trackerValue = abi.encode(trackerValue);
        // Add the tracker
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName");

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return policyIds[0];
    }

    function setupRuleWithTracker(
        uint256 _policyId, Trackers memory tracker
    )
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        resetsGlobalVariables
        returns (uint256 policyId)
    {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _policyId;

        PT[] memory pTypes = new PT[](3);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.ADDR;

        _addFunctionSignatureToPolicy(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Instruction set: LC.PLH, 0, LC.PLH, 1, LC.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = PT.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].pType = PT.BYTES;
        rule.placeHolders[2].typeSpecificIndex = 2;

        rule.effectPlaceHolders = new Placeholder[](1);
        rule.effectPlaceHolders[0].pType = PT.BYTES;
        rule.effectPlaceHolders[0].typeSpecificIndex = 2;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // rule.posEffects[0] = _createEffectExpressionTrackerUpdateParameter();
        rule.posEffects[0] = effectId_event;

        // Add the tracker
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName");
        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return policyIds[0];
    }

    function setupRuleWithTracker2(
        uint256 _policyId, Trackers memory tracker
    )
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        resetsGlobalVariables
        returns (uint256 policyId)
    {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _policyId;

        PT[] memory pTypes = new PT[](3);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.BYTES;

        _addFunctionSignatureToPolicyWithString(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Instruction set: LC.PLH, 0, LC.PLH, 1, LC.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = PT.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].pType = PT.BYTES;
        rule.placeHolders[2].typeSpecificIndex = 2;

        rule.effectPlaceHolders = new Placeholder[](1);
        rule.effectPlaceHolders[0].pType = PT.BYTES;
        rule.effectPlaceHolders[0].typeSpecificIndex = 2;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = _createEffectExpressionTrackerUpdateParameterPlaceHolder();
        // rule.posEffects[0] = effectId_event;

        // Add the tracker
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName");
        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return policyIds[0];
    }

    function setupRuleWithTrackerAddr(
        uint256 _policyId, Trackers memory tracker
    )
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        resetsGlobalVariables
        returns (uint256 policyId)
    {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _policyId;

        PT[] memory pTypes = new PT[](3);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.ADDR;

        _addFunctionSignatureToPolicyWithString(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Instruction set: LC.PLH, 0, LC.PLH, 1, LC.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = PT.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].pType = PT.ADDR;
        rule.placeHolders[2].typeSpecificIndex = 2;

        rule.effectPlaceHolders = new Placeholder[](1);
        rule.effectPlaceHolders[0].pType = PT.ADDR;
        rule.effectPlaceHolders[0].typeSpecificIndex = 2;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = _createEffectExpressionTrackerUpdateParameterPlaceHolder();

        // Add the tracker
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName");
        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return policyIds[0];
    }

    function setupRuleWithTrackerBool(
        uint256 _policyId, Trackers memory tracker
    )
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        resetsGlobalVariables
        returns (uint256 policyId)
    {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _policyId;

        PT[] memory pTypes = new PT[](3);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.BOOL;

        _addFunctionSignatureToPolicyWithString(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Instruction set: LC.PLH, 0, LC.PLH, 1, LC.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = PT.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].pType = PT.BOOL;
        rule.placeHolders[2].typeSpecificIndex = 2;

        rule.effectPlaceHolders = new Placeholder[](1);
        rule.effectPlaceHolders[0].pType = PT.ADDR;
        rule.effectPlaceHolders[0].typeSpecificIndex = 2;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = _createEffectExpressionTrackerUpdateParameterPlaceHolder();

        // Add the tracker
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName");
        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return policyIds[0];
    }

    function setupRuleWithTrackerUint(
        uint256 _policyId, Trackers memory tracker
    )
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        resetsGlobalVariables
        returns (uint256 policyId)
    {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _policyId;

        PT[] memory pTypes = new PT[](3);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.UINT;

        _addFunctionSignatureToPolicyWithString(policyIds[0]);

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Instruction set: LC.PLH, 0, LC.PLH, 1, LC.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.NUM);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = PT.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].pType = PT.UINT;
        rule.placeHolders[2].typeSpecificIndex = 2;

        rule.effectPlaceHolders = new Placeholder[](1);
        rule.effectPlaceHolders[0].pType = PT.UINT;
        rule.effectPlaceHolders[0].typeSpecificIndex = 2;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = _createEffectExpressionTrackerUpdateParameterPlaceHolder();

        // Add the tracker
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName");
        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return policyIds[0];
    }


    /// Test helper functions
    function _createBlankPolicy() internal returns (uint256) {
        FunctionSignatureStorageSet[] memory functionSignatures = new FunctionSignatureStorageSet[](0); 
        Rule[] memory rules = new Rule[](0); 
        uint256 policyId = RulesEnginePolicyFacet(address(red)).createPolicy(functionSignatures, rules, PolicyType.CLOSED_POLICY);
        RulesEngineComponentFacet(address(red)).addClosedPolicySubscriber(policyId, callingContractAdmin); 
        return policyId;
    }

    function _createBlankPolicyOpen() internal returns (uint256) {
        FunctionSignatureStorageSet[] memory functionSignatures = new FunctionSignatureStorageSet[](0); 
        Rule[] memory rules = new Rule[](0); 
        uint256 policyId = RulesEnginePolicyFacet(address(red)).createPolicy(functionSignatures, rules, PolicyType.OPEN_POLICY);
        return policyId;
    }

    function _createBlankPolicyWithAdminRoleString()
        internal
        returns (uint256)
    {
        FunctionSignatureStorageSet[] memory functionSignatures = new FunctionSignatureStorageSet[](0); 
        Rule[] memory rules = new Rule[](0); 
        uint256 policyId = RulesEnginePolicyFacet(address(red)).createPolicy(functionSignatures, rules, PolicyType.CLOSED_POLICY);
        return policyId;
    }

    // internal rule builder
    function _createGTRule(uint256 _amount) public returns (Rule memory) {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LC.PLH, 0, LC.NUM, _amount, LC.GT, 0, 1
        rule.instructionSet = rule.instructionSet = _createInstructionSet(
            _amount
        );
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

    function _createGTRuleWithCustomEventParams(uint256 _amount, bytes memory param, PT paramType) public returns (Rule memory) {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Set up custom event param effect.
        effectId_event = _createCustomEffectEvent(param, paramType);
        // Instruction set: LC.PLH, 0, LC.NUM, _amount, LC.GT, 0, 1
        rule.instructionSet = rule.instructionSet = _createInstructionSet(
            _amount
        );
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

    function _createGTRuleWithDynamicEventParams(uint256 _amount) public returns (Rule memory) {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Set up custom event param effect.
        effectId_event = _createEffectEventDynamicParams();
        // Instruction set: LC.PLH, 0, LC.NUM, _amount, LC.GT, 0, 1
        rule.instructionSet = rule.instructionSet = _createInstructionSet(
            _amount
        );
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;

        rule.effectPlaceHolders = new Placeholder[](1);
        rule.effectPlaceHolders[0].pType = PT.UINT;
        rule.effectPlaceHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

    function _createGTRuleWithDynamicEventParamsAddress(uint256 _amount) public returns (Rule memory) {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Set up custom event param effect.
        effectId_event = _createEffectEventDynamicParamsAddress();
        // Instruction set: LC.PLH, 0, LC.NUM, _amount, LC.GT, 0, 1
        rule.instructionSet = rule.instructionSet = _createInstructionSet(
            _amount
        );
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;

        rule.effectPlaceHolders = new Placeholder[](1);
        rule.effectPlaceHolders[0].pType = PT.ADDR;
        rule.effectPlaceHolders[0].typeSpecificIndex = 0;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

    function _createLTRule() public returns (Rule memory) {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LC.PLH, 0, LC.NUM, _amount, LC.GT, 0, 1
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.NUM);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = 2;
        rule.instructionSet[4] = uint(LC.LT);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }


    function _addFunctionSignatureToPolicy(uint256 policyId) internal returns (uint256) {
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        // Save the function signature
        uint256 functionSignatureId = RulesEngineComponentFacet(address(red))
            .createFunctionSignature(
                policyId, 
                bytes4(bytes4(keccak256(bytes(functionSignature)))), 
                pTypes,
                functionSignature,
                ""    
            );
        // Save the Policy
        signatures.push(bytes4(keccak256(bytes(functionSignature))));
        functionSignatureIds.push(functionSignatureId);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            signatures,
            functionSignatureIds,
            blankRuleIds,
            PolicyType.CLOSED_POLICY
        );
        return functionSignatureId;
    }

    function _addFunctionSignatureToPolicyWithString(uint256 policyId) internal returns (uint256) {
        PT[] memory pTypes = new PT[](3);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.BYTES;
        // Save the function signature
        uint256 functionSignatureId = RulesEngineComponentFacet(address(red))
            .createFunctionSignature(
                policyId, 
                bytes4(bytes4(keccak256(bytes(functionSignature)))), 
                pTypes,
                functionSignature,
                ""    
            );
        // Save the Policy
        signatures.push(bytes4(keccak256(bytes(functionSignature))));
        functionSignatureIds.push(functionSignatureId);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            signatures,
            functionSignatureIds,
            blankRuleIds,
            PolicyType.CLOSED_POLICY
        );
        return functionSignatureId;
    }

    function _addFunctionSignatureToPolicy(
        uint256 policyId,
        bytes4 _functionSignature,
        PT[] memory pTypes,
        string memory functionName
    ) internal returns (uint256) {
        // Save the function signature
        uint256 functionSignatureId = RulesEngineComponentFacet(address(red))
            .createFunctionSignature(
                policyId, 
                bytes4(_functionSignature), 
                pTypes, 
                functionName,
                "");
        // Save the Policy
        signatures.push(_functionSignature);
        functionSignatureIds.push(functionSignatureId);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            signatures,
            functionSignatureIds,
            blankRuleIds,
            PolicyType.CLOSED_POLICY
        );
        return functionSignatureId;
    }

    function _addFunctionSignatureToPolicyOpen(
        uint256 policyId,
        bytes4 _functionSignature,
        PT[] memory pTypes, 
        string memory functionName
    ) internal returns (uint256) {
        // Save the function signature
        uint256 functionSignatureId = RulesEngineComponentFacet(address(red))
            .createFunctionSignature(
                policyId, 
                bytes4(_functionSignature), 
                pTypes, 
                functionName,
                "");
        // Save the Policy
        signatures.push(_functionSignature);
        functionSignatureIds.push(functionSignatureId);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            signatures,
            functionSignatureIds,
            blankRuleIds,
            PolicyType.OPEN_POLICY
        );
        return functionSignatureId;
    }
    

    function _addRuleIdsToPolicy(
        uint256 policyId,
        uint256[][] memory _ruleIds
    ) internal {
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            signatures,
            functionSignatureIds,
            _ruleIds,
            PolicyType.CLOSED_POLICY
        );
    }

    function _addRuleIdsToPolicyOpen(
        uint256 policyId,
        uint256[][] memory _ruleIds
    ) internal {
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            signatures,
            functionSignatureIds,
            _ruleIds,
            PolicyType.OPEN_POLICY
        );
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
        effectId_expression2 = _createEffectExpressionTrackerUpdate(); // effectId = 6;
        effectId_expression3 = _createEffectExpressionTrackerUpdateParameterMemory(); // effectId = 7;
        effectId_expression4 = _createEffectExpressionTrackerUpdateParameterPlaceHolder(); // effectId = 8;
    }

    function _createEffectEvent(string memory _text) public pure returns(Effect memory){
        uint256[] memory emptyArray = new uint256[](1); 
        // Create a event effect
        return
            Effect({
                valid: true,
                dynamicParam:false,
                effectType: ET.EVENT,
                pType: PT.STR,
                param: abi.encode(_text),
                text: EVENTTEXT,
                errorMessage: _text,
                instructionSet: emptyArray
            });
    }

    function _createCustomEffectEvent(bytes memory param, PT paramType) public pure returns(Effect memory){
        uint256[] memory emptyArray = new uint256[](1); 
        bytes memory encodedParam; 
        if (paramType == PT.UINT) {
            encodedParam = abi.encode(abi.decode(param, (uint)));  
        } else if (paramType == PT.ADDR) {
            encodedParam = abi.encode(abi.decode(param, (address)));
        } else if (paramType == PT.BOOL) {
            encodedParam = abi.encode(abi.decode(param, (bool)));
        } else if (paramType == PT.STR) {
            encodedParam = abi.encode(abi.decode(param, (string)));
        } else if (paramType == PT.BYTES) {
            encodedParam = abi.encode(abi.decode(param, (bytes32)));
        }
        // Create a event effect
        return
            Effect({
                valid: true,
                dynamicParam:false,
                effectType: ET.EVENT,
                pType: paramType,
                param: encodedParam,
                text: EVENTTEXT,
                errorMessage: event_text,
                instructionSet: emptyArray
            });
    }

    function _createEffectEventDynamicParams() public pure returns(Effect memory){
        Effect memory effect;
        effect.valid = true;
        effect.dynamicParam = true;
        effect.effectType = ET.EVENT;
        effect.text = EVENTTEXT;
        effect.instructionSet = new uint256[](4);
        // Foreign Call Placeholder
        effect.instructionSet[0] = uint(LC.NUM);
        effect.instructionSet[1] = 0;
        // // Tracker Placeholder
        effect.instructionSet[2] = uint(LC.NUM);
        effect.instructionSet[3] = 1;

        return effect;
    }

    function _createEffectEventDynamicParamsAddress() public pure returns(Effect memory){
        Effect memory effect;
        effect.valid = true;
        effect.dynamicParam = true;
        effect.effectType = ET.EVENT;
        effect.text = EVENTTEXT;
        effect.instructionSet = new uint256[](4);
        // Foreign Call Placeholder
        effect.instructionSet[0] = uint(LC.NUM);
        effect.instructionSet[1] = 1;
        // // Tracker Placeholder
        effect.instructionSet[2] = uint(LC.NUM);
        effect.instructionSet[3] = 1;

        return effect;
    }

    function _createEffectRevert(string memory _text) public pure returns(Effect memory) {
        uint256[] memory emptyArray = new uint256[](1); 
        // Create a revert effect
        return
            Effect({
                valid: true,
                dynamicParam:false,
                effectType: ET.REVERT,
                pType: PT.STR,
                param: abi.encode(_text),
                text: EVENTTEXT,
                errorMessage: revert_text,
                instructionSet: emptyArray
            });
    }

    function _createEffectExpression() public pure returns(Effect memory) {
        Effect memory effect;

        effect.valid = true;
        effect.effectType = ET.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](1);

        return effect;
    }

    function _createEffectExpressionTrackerUpdate() public pure returns(Effect memory) {
        // Effect: TRU:someTracker += FC:simpleCheck(amount)
        Effect memory effect;
        effect.valid = true;
        effect.effectType = ET.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](10);
        // Foreign Call Placeholder
        effect.instructionSet[0] = uint(LC.PLH);
        effect.instructionSet[1] = 0;
        // Tracker Placeholder
        effect.instructionSet[2] = uint(LC.PLH);
        effect.instructionSet[3] = 1;
        effect.instructionSet[4] = uint(LC.ADD);
        effect.instructionSet[5] = 0;
        effect.instructionSet[6] = 1;
        effect.instructionSet[7] = uint(LC.TRU);
        effect.instructionSet[8] = 1;
        effect.instructionSet[9] = 2;

        return effect;
    }

    function _createEffectExpressionTrackerUpdateParameterPlaceHolder() public pure returns(Effect memory) {
        // Effect: TRU:someTracker = parameter 3
        Effect memory effect;
        effect.valid = true;
        effect.effectType = ET.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](6);
        // Foreign Call Placeholder
        effect.instructionSet[0] = uint(LC.PLH);
        effect.instructionSet[1] = 0;
        // Tracker Placeholder
        effect.instructionSet[2] = uint(LC.TRU);
        effect.instructionSet[3] = 1;
        effect.instructionSet[4] = 0;
        effect.instructionSet[5] = uint(TT.PLACE_HOLDER);

        return effect;
    }

    function _createEffectExpressionTrackerUpdateParameterMemory() public pure returns(Effect memory) {
        // Effect: TRU:someTracker = parameter 3
        Effect memory effect;
        effect.valid = true;
        effect.effectType = ET.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](6);
        // Tracker Placeholder
        effect.instructionSet[0] = uint(LC.TRU);
        effect.instructionSet[1] = 1;
        effect.instructionSet[2] = 0;
        effect.instructionSet[3] = uint(TT.MEMORY);

        return effect;
    }

    // internal instruction set builder: overload as needed
    function _createInstructionSet()
        public
        pure
        returns (uint256[] memory instructionSet)
    {
        instructionSet = new uint256[](7);
        instructionSet[0] = uint(LC.NUM);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LC.NUM);
        instructionSet[3] = 1;
        instructionSet[4] = uint(LC.GT);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
    }

    function _createInstructionSet(
        uint256 plh1
    ) public pure returns (uint256[] memory instructionSet) {
        instructionSet = new uint256[](7);
        instructionSet[0] = uint(LC.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LC.NUM);
        instructionSet[3] = plh1;
        instructionSet[4] = uint(LC.GT);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
    }

    function _createInstructionSet(
        string memory testString, // string added to identify this overloaded function vs the two uint256 param version 
        uint256 plh1,
        LC plcType
    ) public pure returns (uint256[] memory instructionSet) {
        instructionSet = new uint256[](7);
        instructionSet[0] = uint(LC.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LC.NUM);
        instructionSet[3] = plh1;
        instructionSet[4] = uint(plcType);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        console.log("testString: %s", testString);
    }

    function _createInstructionSet(
        uint256 plh1,
        uint256 plh2
    ) public pure returns (uint256[] memory instructionSet) {
        instructionSet = new uint256[](7);
        instructionSet[0] = uint(LC.PLH);
        instructionSet[1] = plh1;
        instructionSet[2] = uint(LC.PLH);
        instructionSet[3] = plh2;
        instructionSet[4] = uint(LC.GT);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
    }

    function _setup_checkRule_ForeignCall_Positive(uint256 _transferValue) public ifDeploymentTestsEnabled endWithStopPrank returns(uint256 _policyId) {
       
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicyOpen();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0]);
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"        
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1); 
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(_transferValue);
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 1;
        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineComponentFacet(address(red)).createForeignCall(policyIds[0], fc, "simpleCheck(uint256)");
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);      
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return policyIds[0];
    }

    function _setup_checkRule_TransferFrom_ForeignCall_Positive(uint256 _transferValue) public ifDeploymentTestsEnabled endWithStopPrank {
       
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicyOpen();
        PT[] memory pTypes = new PT[](3);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.ADDR;
        pTypes[2] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0]);
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"        
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1); 
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(_transferValue);
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 2;
        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineComponentFacet(address(red)).createForeignCall(policyIds[0], fc, "simpleCheck(uint256)");
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);   
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);    
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _setup_checkRule_ForeignCall_Negative(uint256 _transferValue)  public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        
        _addFunctionSignatureToPolicy(policyIds[0]);
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"        
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1); 
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(_transferValue);
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEnginePolicyFacet(address(red)).createRule(policyIds[0], rule);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 1;
        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = PT.UINT;

        RulesEngineComponentFacet(address(red)).createForeignCall(policyIds[0], fc, "simpleCheck(uint256)");
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);    
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);   
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _setUpForeignCallSimple(uint256 _policyId) public ifDeploymentTestsEnabled  returns(ForeignCall memory foreignCall) {
        ForeignCall memory fc;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.UINT;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 1;
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineComponentFacet(address(red)).createForeignCall(_policyId, fc, "simpleCheck(uint256)");
        return fc; 
    }

    function _setUpForeignCallSimpleReturnID(uint256 _policyId) public ifDeploymentTestsEnabled  returns(ForeignCall memory foreignCall, uint256 fcId) {
        ForeignCall memory fc;
        fc.foreignCallAddress = address(testContract);
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.UINT;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 1;
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;
        uint256 foreignCallId = RulesEngineComponentFacet(address(red)).createForeignCall(_policyId, fc, "simpleCheck(uint256)");
        return (fc, foreignCallId); 
    }

    function _switchCallingContractAdminRole(address newAdmin, address userContract) public ifDeploymentTestsEnabled {
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEngineAdminRolesFacet(address(red)).proposeNewCallingContractAdmin(newAdmin, userContract); 

        vm.stopPrank();
        vm.startPrank(newAdmin);
        RulesEngineAdminRolesFacet(address(red)).confirmNewCallingContractAdmin(userContract);

    }
}
