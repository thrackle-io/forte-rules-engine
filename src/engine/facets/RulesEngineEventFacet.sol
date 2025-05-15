// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetCommonImports.sol";
import {RulesEngineProcessorLib as ProcessorLib} from "src/engine/facets/RulesEngineProcessorLib.sol";
import "lib/forge-std/src/Console2.sol";
/**
 * @title Rules Engine Event Facet
 * @dev This contract serves as the event processor during effect execution in the Rules Engine.
 * @notice This contract is a critical component of the Rules Engine, enabling secure and flexible effect execution.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract RulesEngineEventFacet is FacetCommonImports{

    /**
     * @dev Evaluate an effect expression
     * @param rule the rule structure containing the instruction set, with placeholders, to execute
     * @param _policyId the policy id
     * @param functionSignatureArgs arguments of the function signature
     * @param instructionSet instruction set 
     */
    function _evaluateExpression(Rule memory rule, uint256 _policyId, bytes calldata functionSignatureArgs, uint256[] memory instructionSet) internal {
        (bytes[] memory effectArguments, Placeholder[] memory placeholders) = ProcessorLib._buildArguments(rule, _policyId, functionSignatureArgs, true);
        if(instructionSet.length > 1) {
            ProcessorLib._run(instructionSet, placeholders, _policyId, effectArguments);
        }
    }

    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Effect Execution Functions
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @dev Internal function to process the effects of a rule.
     * @param rule The rule being processed, stored in the contract's storage.
     * @param _policyId The ID of the policy associated with the rule.
     * @param _effects An array of effects to be applied as part of the rule execution.
     * @param functionSignatureArgs Encoded calldata containing arguments for the function signature.
     */
    function _doEffects(Rule memory rule, uint256 _policyId, Effect[] memory _effects, bytes calldata functionSignatureArgs) internal {
        // Load the Effect data from storage
        console2.log(_effects.length);
        for(uint256 i = 0; i < _effects.length; i++) {
            Effect memory effect = _effects[i];
            if(effect.valid) {
                    // revert("doEvens");
                if (effect.effectType == ET.REVERT) { 
                    _doRevert(effect.errorMessage);
                } else if (effect.effectType == ET.EVENT) {
                    _buildEvent(rule, _effects[i].dynamicParam, _policyId, _effects[i].text, _effects[i], functionSignatureArgs);
                } else {
                    _evaluateExpression(rule, _policyId, functionSignatureArgs, effect.instructionSet);
                }
            }
        }
    }
    function doEffects(uint256 _ruleId, uint256 _policyId, bool positive, bytes calldata functionSignatureArgs) external {
        Rule memory rule = lib.getRuleStorage().ruleStorageSets[_policyId][_ruleId].rule;
        console2.log(positive==true);
        console2.log(rule.posEffects.length);
        console2.log(rule.negEffects.length);
        _doEffects(rule, _policyId, (positive==true?rule.posEffects:rule.negEffects), functionSignatureArgs);
    }
    /**
     * @dev Define event to be fired 
     * @param rule the rule struct event is associated to 
     * @param isDynamicParam static or dynamic event parameters 
     * @param _policyId policy Id 
     * @param _message Event Message String 
     * @param effectStruct effect struct 
     * @param functionSignatureArgs calling function signature arguments 
     */
    function _buildEvent(Rule memory rule,
        bool isDynamicParam, 
        uint256 _policyId, 
        bytes32 _message, 
        Effect memory effectStruct, 
        bytes calldata functionSignatureArgs
        ) internal {
        // determine if we need to dynamically build event key 
        if (isDynamicParam){
            // fire event by param type based on return value 
            _fireDynamicEvent(rule, _policyId, _message, functionSignatureArgs);
        } else {
            _fireEvent(_policyId, _message, effectStruct);
        }
    }

    /**
     * @dev Fire dynamic Event  
     * @param rule the rule struct event is associated to 
     * @param _policyId policy Id 
     * @param _message Event Message String 
     * @param functionSignatureArgs calling function signature arguments 
     */
    function _fireDynamicEvent(Rule memory rule, uint256 _policyId, bytes32 _message, bytes calldata functionSignatureArgs) internal {
        // Build the effect arguments struct for event parameters:  
        (bytes[] memory effectArguments, Placeholder[] memory placeholders) = ProcessorLib._buildArguments(rule, _policyId, functionSignatureArgs, true);
        for(uint256 i = 0; i < effectArguments.length; i++) { 
            // loop through PT types and set eventParam 
            if (placeholders[i].pType == PT.UINT) {
                uint256 uintParam = abi.decode(effectArguments[i], (uint)); 
                emit RulesEngineEvent(_policyId, _message, uintParam);
            } else if (placeholders[i].pType == PT.ADDR) {
                address addrParam = abi.decode(effectArguments[i], (address));
                emit RulesEngineEvent(_policyId, _message, addrParam);
            } else if (placeholders[i].pType == PT.BOOL) {
                bool boolParam = abi.decode(effectArguments[i], (bool));
                emit RulesEngineEvent(_policyId, _message, boolParam);
            } else if (placeholders[i].pType == PT.STR) {
                string memory textParam = abi.decode(effectArguments[i], (string));
                emit RulesEngineEvent(_policyId, _message, textParam);
            } else if (placeholders[i].pType == PT.BYTES) {
                bytes32 bytesParam = abi.decode(effectArguments[i], (bytes32));
                emit RulesEngineEvent(_policyId, _message, bytesParam);
            }
        }
    }

    /**
     * @dev Internal function to trigger an event based on the provided policy ID, message, and effect structure.
     * @param _policyId The unique identifier of the policy associated with the event.
     * @param _message A bytes32 message that provides context or details about the event.
     * @param effectStruct A struct containing the effect data to be processed during the event.
     */
    function _fireEvent(uint256 _policyId, bytes32 _message, Effect memory effectStruct) internal { 
        if (effectStruct.pType == PT.UINT) {
            uint256 uintParam = abi.decode(effectStruct.param, (uint));
            emit RulesEngineEvent(_policyId, _message, uintParam);
        } else if (effectStruct.pType == PT.ADDR) {
            address addrParam = abi.decode(effectStruct.param, (address));
            emit RulesEngineEvent(_policyId, _message, addrParam);
        } else if (effectStruct.pType == PT.BOOL) {
            bool boolParam = abi.decode(effectStruct.param, (bool));
            emit RulesEngineEvent(_policyId, _message, boolParam);
        } else if (effectStruct.pType == PT.STR) {
            string memory textParam = abi.decode(effectStruct.param, (string));
            emit RulesEngineEvent(_policyId, _message, textParam);
        } else if (effectStruct.pType == PT.BYTES) {
            bytes32 bytesParam = abi.decode(effectStruct.param, (bytes32));
            emit RulesEngineEvent(_policyId, _message, bytesParam);
        }
    }

    /**
     * @dev Internal pure function to revert the transaction with a custom error message.
     * @param _message The custom error message to include in the revert.
     */
    function _doRevert(string memory _message) internal pure{
        revert(_message);
    }
    
    /**
     * @notice Retrieves the raw string associated with a specific instruction set within a rule and policy.
     * @dev This function is used to fetch a `StringVerificationStruct` containing the raw string data.
     * @param _policyId The ID of the policy containing the rule.
     * @param _ruleId The ID of the rule containing the instruction set.
     * @param instructionSetId The ID of the instruction set to retrieve the raw string from.
     * @return retVal A `StringVerificationStruct` containing the raw string data for the specified instruction set.
     */
    function retrieveRawStringFromInstructionSet(uint256 _policyId, uint256 _ruleId, uint256 instructionSetId) public view returns (StringVerificationStruct memory retVal) {
        (uint256 instructionSetValue, bytes memory encoded) = _retreiveRawEncodedFromInstructionSet(_policyId, _ruleId, instructionSetId, PT.STR);
        retVal.rawData = abi.decode(encoded, (string));
        retVal.instructionSetValue = instructionSetValue;
    }

    /**
     * @notice Retrieves the raw address from a specific instruction set.
     * @dev This function is used to fetch the raw address associated with a given
     *      policy ID, rule ID, and instruction set ID.
     * @param _policyId The ID of the policy to which the rule belongs.
     * @param _ruleId The ID of the rule within the policy.
     * @param instructionSetId The ID of the instruction set to retrieve the address verification structure from.
     * @return retVal The AddressVerificationStruct containing the raw address data.
     */
    function retrieveRawAddressFromInstructionSet(uint256 _policyId, uint256 _ruleId, uint256 instructionSetId) public view returns (AddressVerificationStruct memory retVal) {
        (uint256 instructionSetValue, bytes memory encoded) = _retreiveRawEncodedFromInstructionSet(_policyId, _ruleId, instructionSetId, PT.ADDR);
        retVal.rawData = abi.decode(encoded, (address));
        retVal.instructionSetValue = instructionSetValue;
    }

    /**
     * @dev Retrieves the raw encoded data and instruction set value from a given instruction set ID.
     * @param _policyId The ID of the policy associated with the instruction set.
     * @param _ruleId The ID of the rule associated with the instruction set.
     * @param instructionSetId The ID of the instruction set to retrieve data from.
     * @param pType The parameter type (PT) associated with the instruction set.
     * @return instructionSetValue The value of the instruction set.
     * @return encoded The raw encoded data associated with the instruction set.
     */
    function _retreiveRawEncodedFromInstructionSet(uint256 _policyId, uint256 _ruleId, uint256 instructionSetId, PT pType) internal view returns (uint256 instructionSetValue, bytes memory encoded) {
        RuleStorageSet memory _ruleStorage = lib.getRuleStorage().ruleStorageSets[_policyId][_ruleId];
        if(!_ruleStorage.set) {
            revert("Unknown Rule");
        }
        for(uint256 i = 0; i < _ruleStorage.rule.rawData.instructionSetIndex.length; i++) {
            if(_ruleStorage.rule.rawData.instructionSetIndex[i] == instructionSetId) {
                if(_ruleStorage.rule.rawData.argumentTypes[i] != pType) {
                    revert("Incorrect type");
                }
                encoded = _ruleStorage.rule.rawData.dataValues[i];
                instructionSetValue = _ruleStorage.rule.instructionSet[instructionSetId];
                break;
            }
        }
    }

}