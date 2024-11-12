// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "src/effects/EffectStructures.sol";

/**
 * @title Rules Event Processor Logic
 * @dev This contract provides the ability to execute a rule's effects
 * @author @ShaneDuncan602 
 */

 contract EffectProcessor is EffectStructures {
     

    /**
     * @dev Loop through effects for a given rule and execute them
     * @param _effectIds list of effects
     */
    function doEffects(uint256[] calldata _effectIds) external {
        for(uint256 i = 0; i < _effectIds.length; i++) {
            if(_effectIds[i] > 0){// only ref Id's greater than 0 are valid
                Effect memory effect = effectStorage[_effectIds[i]];
                if (effect.effectType == ET.REVERT) doRevert(effect.text);
                if (effect.effectType == ET.EVENT) doEvent(effect.text);
            }
        }
    }

    /**
     * @dev Reverts the transaction
     * @param _message the reversion message
     */
    function doRevert(string memory _message) internal pure{
        revert(_message);
    }

    /**
     * @dev Emit an event
     * @param _message the reversion message
     */
    function doEvent(string memory _message) internal {
        emit RulesEngineEvent(_message);
    }

    /**
     * @dev Update an effect
     * @param _effect the Effect to update
     */
    function updateEffect(Effect calldata _effect) external returns (uint256 _effectId){
        if (_effect.effectId > 0){
            effectStorage[_effect.effectId] = _effect;
            _effectId = _effect.effectId;
        } else {
            effectTotal+=1;
            effectStorage[effectTotal] = _effect;
            _effectId = effectTotal;
        }
        return _effectId;
    }

    /**
     * @dev Delete an effect
     * @param _effectId the id of the effect to delete
     */
    function deleteEffect(uint256 _effectId) external {
        delete effectStorage[_effectId];
    }

 }