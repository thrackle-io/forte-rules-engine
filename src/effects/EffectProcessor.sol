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

    // /**
    //  * @dev Builds a foreign call structure and adds it to the contracts storage, mapped to the contract address it is associated with
    //  * @param contractAddress the address of the contract the foreign call will be mapped to
    //  * @param foreignContractAddress the address of the contract where the foreign call exists
    //  * @param functionSignature the string representation of the function signature of the foreign call
    //  * @param returnType the parameter type of the foreign calls return value
    //  * @param arguments the parameter types of the foreign calls arguments in order
    //  * @return fc the foreign call structure 
    //  */
    // function updateForeignCall(address contractAddress, address foreignContractAddress, string memory functionSignature, RulesStorageStructure.PT[] memory arguments) public returns (RulesStorageStructure.ForeignCall memory fc) {
    //     fc.foreignCallAddress = foreignContractAddress;
    //     // Convert the string representation of the function signature to a selector
    //     fc.signature = bytes4(keccak256(bytes(functionSignature)));
    //     fc.foreignCallIndex += 1;
    //     fc.parameterTypes = new RulesStorageStructure.PT[](arguments.length);
    //     for(uint256 i = 0; i < arguments.length; i++) {
    //         fc.parameterTypes[i] = arguments[i];
    //     }

    //     // If the foreign call structure already exists in the mapping update it, otherwise add it
    //     if(foreignCalls[contractAddress].set) {
    //         foreignCalls[contractAddress].foreignCalls.push(fc);
    //     } else {
    //         foreignCalls[contractAddress].set = true;
    //         foreignCalls[contractAddress].foreignCalls.push(fc);
    //     }
    // }
 }