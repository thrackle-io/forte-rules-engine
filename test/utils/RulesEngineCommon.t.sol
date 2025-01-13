// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "lib/forge-std/src/Test.sol";

import "test/utils/ForeignCallTestCommon.sol";
import "src/utils/DiamondMine.sol";
import "src/utils/FCEncodingLib.sol";

/**
 * Shared testing logic and set up helper functions for Rules Engine Testing Framework
 * Code used across multiple testing directories belogns here
 */

contract RulesEngineCommon is DiamondMine, Test { 
    
    address userContractAddress;
    ForeignCallTestContract testContract; 

    string functionSignature = "transfer(address,uint256)";
    string functionSignature2 =
        "updateInfo(address _to, string info)";
    string constant event_text = "Rules Engine Event";
    string constant revert_text = "Rules Engine Revert";
    string constant event_text2 = "Rules Engine Event 2";
    string constant revert_text2 = "Rules Engine Revert 2";
    Effect effectId_revert;
    Effect effectId_revert2;
    Effect effectId_event;
    Effect effectId_event2;
    bytes4[] signatures;
    uint256[] functionSignatureIds;
    uint256[][] ruleIds;

    Effect effectId_expression;
    Effect effectId_expression2;

    bool public testDeployments = true;

    address policyAdmin = address(0x54321);
    address newPolicyAdmin = address(0x0Add);

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

    //test modifiers
    address constant USER_ADDRESS = address(0xd00d); 
    address constant USER_ADDRESS_2 = address(0xBADd00d);
    uint256 constant ATTO = 10 ** 18;

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
        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );
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
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        
        // Apply the policy 
        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function setupRuleWithStringComparison()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        returns (uint256 ruleId)
    {
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
        ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.STR;
        // Save the function signature
        uint256 functionSignatureId = RulesEngineDataFacet(address(red))
            .updateFunctionSignature(
                0,
                bytes4(keccak256(bytes(functionSignature2))),
                pTypes
            );
        // Save the Policy
        signatures.push(bytes4(keccak256(bytes(functionSignature2))));
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        uint256[] memory policyIds = new uint256[](1); 
        policyIds[0] = RulesEngineDataFacet(address(red)).updatePolicy(0, signatures, functionSignatureIds, ruleIds);        
        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        return ruleId;
    }

    function setupRuleWithAddressComparison()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
        returns (uint256 ruleId)
    {
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
        ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.STR;
        // Save the function signature
        uint256 functionSignatureId = RulesEngineDataFacet(address(red))
            .updateFunctionSignature(
                0,
                bytes4(keccak256(bytes(functionSignature2))),
                pTypes
            );
        // Save the Policy
        signatures.push(bytes4(keccak256(bytes(functionSignature2))));
        functionSignatureIds.push(functionSignatureId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        uint256[] memory policyIds = new uint256[](1); 
        policyIds[0] = RulesEngineDataFacet(address(red)).updatePolicy(0, signatures, functionSignatureIds, ruleIds);        
        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);

        return ruleId;
    }

    function setupEffectWithTrackerUpdate()
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

        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );

        // Rule: 1 == 1 -> TRU:someTracker += FC:simpleCheck(amount) -> transfer(address _to, uint256 amount) returns (bool)
        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
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
        rule.effectPlaceHolders[0].foreignCall = true;
        rule.effectPlaceHolders[0].typeSpecificIndex = 0;
        rule.effectPlaceHolders[1].pType = PT.UINT;
        rule.effectPlaceHolders[1].trackerValue = true;

        rule.fcArgumentMappingsEffects = new ForeignCallArgumentMappings[](1);
        rule.fcArgumentMappingsEffects[0].mappings = new IndividualArgumentMapping[](1);
        rule.fcArgumentMappingsEffects[0].mappings[0].functionCallArgumentType = PT.UINT;
        rule.fcArgumentMappingsEffects[0].mappings[0].functionSignatureArg.foreignCall = false;
        rule.fcArgumentMappingsEffects[0].mappings[0].functionSignatureArg.pType = PT.UINT;
        rule.fcArgumentMappingsEffects[0].mappings[0].functionSignatureArg.typeSpecificIndex = 1;
        ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);

        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = PT.UINT;
        tracker.trackerValue = abi.encode(2);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        uint256 tId = RulesEngineDataFacet(address(red)).addTracker(policyIds[0], tracker);      
        
        ForeignCall memory fc = RulesEngineDataFacet(address(red)).updateForeignCall(policyIds[0], address(testContract), "simpleCheck(uint256)", PT.UINT, fcArgs);

        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        fc;  //added to silence warnings during testing revamp 
        return policyIds[0];
    }

    function setupRuleWithForeignCall(
        uint256 _amount,
        ET _effectType,
        bool isPositive
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );

        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 0;

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(_amount);

        // Build the mapping between calling function arguments and foreign call arguments
        rule.fcArgumentMappingsConditions = new ForeignCallArgumentMappings[](
            1
        );
        rule
            .fcArgumentMappingsConditions[0]
            .mappings = new IndividualArgumentMapping[](1);
        rule
            .fcArgumentMappingsConditions[0]
            .mappings[0]
            .functionCallArgumentType = PT.UINT;
        rule
            .fcArgumentMappingsConditions[0]
            .mappings[0]
            .functionSignatureArg
            .foreignCall = false;
        rule
            .fcArgumentMappingsConditions[0]
            .mappings[0]
            .functionSignatureArg
            .pType = PT.UINT;
        rule
            .fcArgumentMappingsConditions[0]
            .mappings[0]
            .functionSignatureArg
            .typeSpecificIndex = 1;
        rule = _setUpEffect(rule, _effectType, isPositive);
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        ForeignCall memory fc = RulesEngineDataFacet(address(red))
            .updateForeignCall(
                policyIds[0],
                address(testContract),
                "simpleCheck(uint256)",
                PT.UINT,
                fcArgs
            );
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);       
        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        fc;  //added to silence warnings during testing revamp 
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

    function _setupRuleWithRevert()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );

        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        // Rule memory rule = _createGTRule(4);
        Rule memory rule;
        _setupEffectProcessor();
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
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _setupRuleWithRevertManyCondition()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );

        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        // Rule memory rule = _createGTRule(4);
        Rule memory rule;
        _setupEffectProcessor();
        // Instruction set: LC.PLH, 0, LC.NUM, _amount, LC.GT, 0, 1
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);

        rule.instructionSet = new uint256[](194);
        rule.instructionSet[0] = uint(LC.PLH); // register 0
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LC.NUM); // register 1
        rule.instructionSet[3] = 4;
        rule.instructionSet[4] = uint(LC.GT); // register 2
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.instructionSet[7] = uint(LC.PLH); // register 3
        rule.instructionSet[8] = 0;
        rule.instructionSet[9] = uint(LC.NUM); // register 4
        rule.instructionSet[10] = 4;
        rule.instructionSet[11] = uint(LC.GT); // register 5
        rule.instructionSet[12] = 3;
        rule.instructionSet[13] = 4;

        rule.instructionSet[14] = uint(LC.PLH); // register 6
        rule.instructionSet[15] = 0;
        rule.instructionSet[16] = uint(LC.NUM); // register 7
        rule.instructionSet[17] = 4;
        rule.instructionSet[18] = uint(LC.GT); // register 8
        rule.instructionSet[19] = 6;
        rule.instructionSet[20] = 7;

        rule.instructionSet[21] = uint(LC.PLH); // register 9
        rule.instructionSet[22] = 0;
        rule.instructionSet[23] = uint(LC.NUM); // register 10
        rule.instructionSet[24] = 4;
        rule.instructionSet[25] = uint(LC.GT); // register 11
        rule.instructionSet[26] = 9;
        rule.instructionSet[27] = 10;

        rule.instructionSet[28] = uint(LC.PLH); // register 12
        rule.instructionSet[29] = 0;
        rule.instructionSet[30] = uint(LC.NUM); // register 13
        rule.instructionSet[31] = 4;
        rule.instructionSet[32] = uint(LC.GT); // register 14
        rule.instructionSet[33] = 12;
        rule.instructionSet[34] = 13;

        rule.instructionSet[35] = uint(LC.PLH); // register 15
        rule.instructionSet[36] = 0;
        rule.instructionSet[37] = uint(LC.NUM); // register 16
        rule.instructionSet[38] = 4;
        rule.instructionSet[39] = uint(LC.GT); // register 17
        rule.instructionSet[40] = 15;
        rule.instructionSet[41] = 16;

        rule.instructionSet[42] = uint(LC.PLH); // register 18
        rule.instructionSet[43] = 0;
        rule.instructionSet[44] = uint(LC.NUM); // register 19
        rule.instructionSet[45] = 4;
        rule.instructionSet[46] = uint(LC.GT); // register 20
        rule.instructionSet[47] = 18;
        rule.instructionSet[48] = 19;

        rule.instructionSet[49] = uint(LC.PLH); // register 21
        rule.instructionSet[50] = 0;
        rule.instructionSet[51] = uint(LC.NUM); // register 22
        rule.instructionSet[52] = 4;
        rule.instructionSet[53] = uint(LC.GT); // register 23
        rule.instructionSet[54] = 21;
        rule.instructionSet[55] = 22;

        rule.instructionSet[56] = uint(LC.PLH); // register 24
        rule.instructionSet[57] = 0;
        rule.instructionSet[58] = uint(LC.NUM); // register 25
        rule.instructionSet[59] = 4;
        rule.instructionSet[60] = uint(LC.GT); // register 26
        rule.instructionSet[61] = 24;
        rule.instructionSet[62] = 25;

        rule.instructionSet[63] = uint(LC.PLH); // register 27
        rule.instructionSet[64] = 0;
        rule.instructionSet[65] = uint(LC.NUM); // register 28
        rule.instructionSet[66] = 4;
        rule.instructionSet[67] = uint(LC.GT); // register 29
        rule.instructionSet[68] = 27;
        rule.instructionSet[69] = 28;

        rule.instructionSet[70] = uint(LC.PLH); // register 30
        rule.instructionSet[71] = 0;
        rule.instructionSet[72] = uint(LC.NUM); // register 31
        rule.instructionSet[73] = 4;
        rule.instructionSet[74] = uint(LC.GT); // register 32
        rule.instructionSet[75] = 30;
        rule.instructionSet[76] = 31;

        rule.instructionSet[77] = uint(LC.PLH); // register 33
        rule.instructionSet[78] = 0;
        rule.instructionSet[79] = uint(LC.NUM); // register 34
        rule.instructionSet[80] = 4;
        rule.instructionSet[81] = uint(LC.GT); // register 35
        rule.instructionSet[82] = 33;
        rule.instructionSet[83] = 34;

        rule.instructionSet[84] = uint(LC.PLH); // register 36
        rule.instructionSet[85] = 0;
        rule.instructionSet[86] = uint(LC.NUM); // register 37
        rule.instructionSet[87] = 4;
        rule.instructionSet[88] = uint(LC.GT); // register 38
        rule.instructionSet[89] = 36;
        rule.instructionSet[90] = 37;

        rule.instructionSet[91] = uint(LC.PLH); // register 39
        rule.instructionSet[92] = 0;
        rule.instructionSet[93] = uint(LC.NUM); // register 40
        rule.instructionSet[94] = 4;
        rule.instructionSet[95] = uint(LC.GT); // register 41
        rule.instructionSet[96] = 39;
        rule.instructionSet[97] = 40;

        rule.instructionSet[98] = uint(LC.PLH); // register 42
        rule.instructionSet[99] = 0;
        rule.instructionSet[100] = uint(LC.NUM); // register 43
        rule.instructionSet[101] = 4;
        rule.instructionSet[102] = uint(LC.GT); // register 44
        rule.instructionSet[103] = 42;
        rule.instructionSet[104] = 43;

        rule.instructionSet[105] = uint(LC.PLH); // register 45
        rule.instructionSet[106] = 0;
        rule.instructionSet[107] = uint(LC.NUM); // register 46
        rule.instructionSet[108] = 4;
        rule.instructionSet[109] = uint(LC.GT); // register 47
        rule.instructionSet[110] = 45;
        rule.instructionSet[111] = 46;

        rule.instructionSet[112] = uint(LC.PLH); // register 48
        rule.instructionSet[113] = 0;
        rule.instructionSet[114] = uint(LC.NUM); // register 49
        rule.instructionSet[115] = 4;
        rule.instructionSet[116] = uint(LC.GT); // register 50
        rule.instructionSet[117] = 48;
        rule.instructionSet[118] = 49;

        rule.instructionSet[119] = uint(LC.PLH); // register 51
        rule.instructionSet[120] = 0;
        rule.instructionSet[121] = uint(LC.NUM); // register 52
        rule.instructionSet[122] = 4;
        rule.instructionSet[123] = uint(LC.GT); // register 53
        rule.instructionSet[124] = 51;
        rule.instructionSet[125] = 52;

        rule.instructionSet[126] = uint(LC.PLH); // register 54
        rule.instructionSet[127] = 0;
        rule.instructionSet[128] = uint(LC.NUM); // register 55
        rule.instructionSet[129] = 4;
        rule.instructionSet[130] = uint(LC.GT); // register 56
        rule.instructionSet[131] = 54;
        rule.instructionSet[132] = 55;

        rule.instructionSet[133] = uint(LC.PLH); // register 57
        rule.instructionSet[134] = 0;
        rule.instructionSet[135] = uint(LC.NUM); // register 58
        rule.instructionSet[136] = 4;
        rule.instructionSet[137] = uint(LC.GT); // register 59
        rule.instructionSet[138] = 56;
        rule.instructionSet[139] = 57;

        rule.instructionSet[140] = uint(LC.AND); // register 60
        rule.instructionSet[141] = 2;
        rule.instructionSet[142] = 5;

        rule.instructionSet[140] = uint(LC.AND); // register 61
        rule.instructionSet[141] = 60;
        rule.instructionSet[142] = 8;

        rule.instructionSet[143] = uint(LC.AND); // register 62
        rule.instructionSet[144] = 61;
        rule.instructionSet[145] = 11;

        rule.instructionSet[146] = uint(LC.AND); // register 63
        rule.instructionSet[147] = 62;
        rule.instructionSet[148] = 14;

        rule.instructionSet[149] = uint(LC.AND); // register 64
        rule.instructionSet[150] = 63;
        rule.instructionSet[151] = 17;

        rule.instructionSet[152] = uint(LC.AND); // register 65
        rule.instructionSet[153] = 64;
        rule.instructionSet[154] = 20;

        rule.instructionSet[155] = uint(LC.AND); // register 66
        rule.instructionSet[156] = 65;
        rule.instructionSet[157] = 23;

        rule.instructionSet[158] = uint(LC.AND); // register 67
        rule.instructionSet[159] = 66;
        rule.instructionSet[160] = 26;

        rule.instructionSet[161] = uint(LC.AND); // register 68
        rule.instructionSet[162] = 67;
        rule.instructionSet[163] = 29;

        rule.instructionSet[164] = uint(LC.AND); // register 69
        rule.instructionSet[165] = 68;
        rule.instructionSet[166] = 32;

        rule.instructionSet[167] = uint(LC.AND); // register 70
        rule.instructionSet[168] = 69;
        rule.instructionSet[169] = 35;

        rule.instructionSet[170] = uint(LC.AND); // register 71
        rule.instructionSet[171] = 70;
        rule.instructionSet[172] = 38;

        rule.instructionSet[173] = uint(LC.AND); // register 72
        rule.instructionSet[174] = 71;
        rule.instructionSet[175] = 41;

        rule.instructionSet[176] = uint(LC.AND); // register 73
        rule.instructionSet[177] = 72;
        rule.instructionSet[178] = 44;

        rule.instructionSet[179] = uint(LC.AND); // register 74
        rule.instructionSet[180] = 73;
        rule.instructionSet[181] = 47;

        rule.instructionSet[182] = uint(LC.AND); // register 75
        rule.instructionSet[183] = 74;
        rule.instructionSet[184] = 50;

        rule.instructionSet[185] = uint(LC.AND); // register 76
        rule.instructionSet[186] = 75;
        rule.instructionSet[187] = 53;

        rule.instructionSet[188] = uint(LC.AND); // register 77
        rule.instructionSet[189] = 76;
        rule.instructionSet[190] = 56;

        rule.instructionSet[191] = uint(LC.AND); // register 78
        rule.instructionSet[192] = 77;
        rule.instructionSet[193] = 59;

        rule.posEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);
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

        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );

        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule = _createGTRule(4);
        rule.posEffects[0] = effectId_event;

        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);
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

        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );

        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule = _createGTRule(threshold);
        rule.posEffects[0] = effectId_event;

        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);

        if (ruleIds.length == 0) ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(
            address(contractAddress),
            policyIds
        );
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

        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );

        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        // Rule 1: GT 4
        Rule memory rule = _createGTRule(4);
        rule.posEffects[0] = effectId_event;

        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);

        ruleIds.push(new uint256[](4));
        ruleIds[0][0] = ruleId;

        // Rule 2: GT 5
        rule = _createGTRule(5);
        rule.posEffects[0] = effectId_event2;

        // Save the rule
        ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);

        // // Save the fKureIds.push(functionSignatureId);
        ruleIds[0][1] = ruleId;

        // Rule 3: GT 6
        rule = _createGTRule(6);
        rule.posEffects[0] = effectId_event;

        // Save the rule
        ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);

        // // Save the fKureIds.push(functionSignatureId);
        ruleIds[0][2] = ruleId;

        // Rule 4: GT 7
        rule = _createGTRule(7);
        rule.posEffects[0] = effectId_event2;

        // Save the rule
        ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);

        // // Save the fKureIds.push(functionSignatureId);
        ruleIds[0][3] = ruleId;

        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);
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

        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );

        // Rule: amount > 4 -> event -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule = _createGTRule(4);
        rule.posEffects = new Effect[](2);
        rule.posEffects[0] = effectId_event;
        rule.posEffects[1] = effectId_event2;

        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);
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

        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );

        // Rule: amount > TR:minTransfer -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Instruction set: LC.PLH, 0, LC.PLH, 1, LC.GT, 0, 1
        rule.instructionSet = _createInstructionSet(0, 1);

        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].trackerValue = true;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;

        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);
        // Build the tracker
        Trackers memory tracker;

        /// build the members of the struct:
        tracker.pType = PT.UINT;
        tracker.trackerValue = abi.encode(trackerValue);
        // Add the tracker
        RulesEngineDataFacet(address(red)).addTracker(policyIds[0], tracker);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        return policyIds[0];
    }

    /// Test helper functions
    function _createBlankPolicy() internal returns (uint256) {
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        uint256 policyId = RulesEngineDataFacet(address(red)).updatePolicy(
            0,
            blankSignatures,
            blankFunctionSignatureIds,
            blankRuleIds
        );
        return policyId;
    }

    function _createBlankPolicyWithAdminRoleString()
        internal
        returns (uint256)
    {
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        uint256 policyID = RulesEngineDataFacet(address(red)).createPolicy(
            0,
            blankSignatures,
            blankFunctionSignatureIds,
            blankRuleIds
        );
        return policyID;
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

    function _createLTRule(uint256 _amount) public returns (Rule memory) {
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


    function _addFunctionSignatureToPolicy(
        uint256 policyId,
        bytes4 _functionSignature,
        PT[] memory pTypes
    ) internal returns (uint256) {
        // Save the function signature
        uint256 functionSignatureId = RulesEngineDataFacet(address(red))
            .updateFunctionSignature(0, bytes4(_functionSignature), pTypes);
        // Save the Policy
        signatures.push(_functionSignature);
        functionSignatureIds.push(functionSignatureId);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEngineDataFacet(address(red)).updatePolicy(
            policyId,
            signatures,
            functionSignatureIds,
            blankRuleIds
        );
        return functionSignatureId;
    }

    function _addRuleIdsToPolicy(
        uint256 policyId,
        uint256[][] memory _ruleIds
    ) internal {
        RulesEngineDataFacet(address(red)).updatePolicy(
            policyId,
            signatures,
            functionSignatureIds,
            _ruleIds
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
    }

    function _createEffectEvent(string memory _text) public pure returns(Effect memory){
        uint256[] memory emptyArray = new uint256[](1);
        // Create a event effect
        return
            Effect({
                valid: true,
                effectType: ET.EVENT,
                text: _text,
                instructionSet: emptyArray
            });
    }

    function _createEffectRevert(string memory _text) public pure returns(Effect memory) {
        uint256[] memory emptyArray = new uint256[](1);
        // Create a revert effect
        return
            Effect({
                valid: true,
                effectType: ET.REVERT,
                text: _text,
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
        effect.instructionSet[8] = 0;
        effect.instructionSet[9] = 2;

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

    function _setup_checkRule_ForeignCall_Positive(uint256 transferValue, string memory _functionSignature) public ifDeploymentTestsEnabled endWithStopPrank {
       
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0], bytes4(keccak256(bytes(_functionSignature))), pTypes);
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"        
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1); 
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(transferValue);
        // Build the mapping between calling function arguments and foreign call arguments
        rule.fcArgumentMappingsConditions = new ForeignCallArgumentMappings[](1);
        rule.fcArgumentMappingsConditions[0].mappings = new IndividualArgumentMapping[](1);
        rule.fcArgumentMappingsConditions[0].mappings[0].functionCallArgumentType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.foreignCall = false;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.pType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0,rule);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        RulesEngineDataFacet(address(red)).updateForeignCall(policyIds[0], address(testContract), "simpleCheck(uint256)", PT.UINT, fcArgs);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);       
        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _setup_checkRule_TransferFrom_ForeignCall_Positive(uint256 transferValue, string memory _functionSignature) public ifDeploymentTestsEnabled endWithStopPrank {
       
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        PT[] memory pTypes = new PT[](3);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.ADDR;
        pTypes[2] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0], bytes4(keccak256(bytes(_functionSignature))), pTypes);
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"        
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1); 
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(transferValue);
        // Build the mapping between calling function arguments and foreign call arguments
        rule.fcArgumentMappingsConditions = new ForeignCallArgumentMappings[](1);
        rule.fcArgumentMappingsConditions[0].mappings = new IndividualArgumentMapping[](1);
        rule.fcArgumentMappingsConditions[0].mappings[0].functionCallArgumentType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.foreignCall = false;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.pType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.typeSpecificIndex = 2;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0,rule);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        RulesEngineDataFacet(address(red)).updateForeignCall(policyIds[0], address(testContract), "simpleCheck(uint256)", PT.UINT, fcArgs);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);       
        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _setup_checkRule_ForeignCall_Negative(uint256 transferValue, string memory _functionSignature, PT[] memory pTypes)  public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        
        _addFunctionSignatureToPolicy(policyIds[0], bytes4(keccak256(bytes(_functionSignature))), pTypes);
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"        
        Rule memory rule;
        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](1); 
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(transferValue);
        // Build the mapping between calling function arguments and foreign call arguments
        rule.fcArgumentMappingsConditions = new ForeignCallArgumentMappings[](1);
        rule.fcArgumentMappingsConditions[0].mappings = new IndividualArgumentMapping[](1);
        rule.fcArgumentMappingsConditions[0].mappings[0].functionCallArgumentType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.foreignCall = false;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.pType = PT.UINT;
        rule.fcArgumentMappingsConditions[0].mappings[0].functionSignatureArg.typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0,rule);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        RulesEngineDataFacet(address(red)).updateForeignCall(policyIds[0], address(testContract), "simpleCheck(uint256)", PT.UINT, fcArgs);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);       
        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

}
