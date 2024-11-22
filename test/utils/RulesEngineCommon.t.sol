// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "lib/forge-std/src/Test.sol";
import "lib/forge-std/src/Test.sol";

import "test/utils/ForeignCallTestCommon.sol";
import "test/utils/RulesEngineLogicWrapper.sol";

import "src/effects/EffectStructures.sol";
import "src/utils/FCEncodingLib.sol";
import "src/RulesEngineStructures.sol";
import "src/RulesEngineRunLogic.sol";
import "src/ExampleUserContract.sol";

/**
 * Shared testing logic and set up helper functions for Rules Engine Testing Framework
 * Code used across multiple testing directories belogns here 
 */

contract RulesEngineCommon is Test, EffectStructures { 
    
    RulesEngineLogicWrapper logic;
    ExampleUserContract userContract;
    ForeignCallTestContract testContract; 
    RulesEngineRunLogic rulesEngine; 

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

    /// Set up helper functions 
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
        // Effect: TRU:someTracker += FC:simpleCheck(amount)
        EffectStructures.Effect memory effect;
        effect.effectId = 0;
        effect.effectType = ET.EXPRESSION;
        effect.text = "";
        effect.instructionSet = new uint256[](10);
        // Foreign Call Placeholder
        effect.instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        effect.instructionSet[1] = 0;
        // Tracker Placeholder
        effect.instructionSet[2] = uint(RulesStorageStructure.LC.PLH);
        effect.instructionSet[3] = 1;
        effect.instructionSet[4] = uint(RulesStorageStructure.LC.ADD);
        effect.instructionSet[5] = 0;
        effect.instructionSet[6] = 1;
        effect.instructionSet[7] = uint(RulesStorageStructure.LC.TRU);
        effect.instructionSet[8] = 0;
        effect.instructionSet[9] = 2;

        return logic.updateEffect(effect);
    }

    // internal instruction set builder: overload as needed 
    function _createInstructionSet(uint256 plh1) public pure returns (uint256[] memory instructionSet) {
        instructionSet = new uint256[](7);
        instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(RulesStorageStructure.LC.NUM);
        instructionSet[3] = plh1;
        instructionSet[4] = uint(RulesStorageStructure.LC.GT);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
    }

    function _createInstructionSet(uint256 plh1, uint256 plh2) public pure returns (uint256[] memory instructionSet) {
        instructionSet = new uint256[](7);
        instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        instructionSet[1] = plh1;
        instructionSet[2] = uint(RulesStorageStructure.LC.PLH);
        instructionSet[3] = plh2;
        instructionSet[4] = uint(RulesStorageStructure.LC.GT);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
    }

}
