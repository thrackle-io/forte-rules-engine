// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "lib/forge-std/src/Test.sol";

import "test/utils/ForeignCallTestCommon.sol";
import "test/utils/DiamondMine.sol";
import "src/utils/FCEncodingLib.sol";
import "src/ExampleUserContract.sol";

/**
 * Shared testing logic and set up helper functions for Rules Engine Testing Framework
 * Code used across multiple testing directories belogns here 
 */

contract RulesEngineCommon is DiamondMine { 
    
    ExampleUserContract userContract;
    ForeignCallTestContract testContract; 

    string functionSignature = "transfer(address,uint256) returns (bool)";
    string functionSignature2 = "updateInfo(address _to, string info) returns (bool)";
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

    bool public testDeployments = true;

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

    /// Test helper functions 
    function _createBlankPolicy() internal returns (uint256) {
        bytes[] memory blankSignatures = new bytes[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        uint256 policyId = RulesEngineDataFacet(address(red)).updatePolicy(0, blankSignatures, blankFunctionSignatureIds, blankRuleIds);
        return policyId;
    }

    // internal rule builder 
    function _createGTRule(uint256 _amount) public returns(Rule memory){
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LC.PLH, 0, LC.NUM, _amount, LC.GT, 0, 1
        rule.instructionSet = rule.instructionSet = _createInstructionSet(_amount);
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new uint256[](1);
        rule.posEffects = new uint256[](2);
        return rule;
    }

    function _addFunctionSignatureToPolicy(uint256 policyId, bytes memory _functionSignature, PT[] memory pTypes) internal returns (uint256) {
        // Save the function signature
        uint256 functionSignatureId = RulesEngineDataFacet(address(red)).updateFunctionSignature(0, bytes4(_functionSignature), pTypes);
        // Save the Policy
        signatures.push(_functionSignature);
        functionSignatureIds.push(functionSignatureId);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEngineDataFacet(address(red)).updatePolicy(policyId, signatures, functionSignatureIds, blankRuleIds);
        return functionSignatureId;
    }

    function _addRuleIdsToPolicy(uint256 policyId, uint256[][] memory _ruleIds) internal {
        RulesEngineDataFacet(address(red)).updatePolicy(policyId, signatures, functionSignatureIds, _ruleIds);
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

    function _createEffectEvent(string memory _text) public returns(uint256 _effectId){
        uint256[] memory emptyArray = new uint256[](1);
        // Create a event effect
        return RulesEngineDataFacet(address(red)).updateEffect(Effect({effectId: 0, effectType: ET.EVENT, text: _text, instructionSet: emptyArray}));
    }

    function _createEffectRevert(string memory _text) public returns(uint256 _effectId) {
        uint256[] memory emptyArray = new uint256[](1);
        // Create a revert effect
        return RulesEngineDataFacet(address(red)).updateEffect(Effect({effectId: 0, effectType: ET.REVERT, text: _text, instructionSet: emptyArray}));
    }

    function _createEffectExpression() public returns(uint256 _effectId) {
        Effect memory effect;

        effect.effectId = 0;
        effect.effectType = ET.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](1);

        return RulesEngineDataFacet(address(red)).updateEffect(effect);
    }

    function _createEffectExpressionTrackerUpdate() public returns(uint256 _effectId) {
        // Effect: TRU:someTracker += FC:simpleCheck(amount)
        Effect memory effect;
        effect.effectId = 0;
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

        return RulesEngineDataFacet(address(red)).updateEffect(effect);
    }

    // internal instruction set builder: overload as needed 
    function _createInstructionSet() public pure returns (uint256[] memory instructionSet) {
        instructionSet = new uint256[](7);
        instructionSet[0] = uint(LC.NUM);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LC.NUM);
        instructionSet[3] = 1;
        instructionSet[4] = uint(LC.GT);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
    }

    function _createInstructionSet(uint256 plh1) public pure returns (uint256[] memory instructionSet) {
        instructionSet = new uint256[](7);
        instructionSet[0] = uint(LC.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LC.NUM);
        instructionSet[3] = plh1;
        instructionSet[4] = uint(LC.GT);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
    }

    function _createInstructionSet(uint256 plh1, uint256 plh2) public pure returns (uint256[] memory instructionSet) {
        instructionSet = new uint256[](7);
        instructionSet[0] = uint(LC.PLH);
        instructionSet[1] = plh1;
        instructionSet[2] = uint(LC.PLH);
        instructionSet[3] = plh2;
        instructionSet[4] = uint(LC.GT);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
    }

}
