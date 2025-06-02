// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetCommonImports.sol";
import {RulesEngineProcessorLib as ProcessorLib} from "src/engine/facets/RulesEngineProcessorLib.sol";

/**
 * @title Rules Engine Processor Facet
 * @dev This contract serves as the core processor for evaluating rules and executing effects in the Rules Engine.
 *      It provides functionality for evaluating policies, rules, and conditions, as well as executing effects based on rule outcomes.
 *      The contract also supports foreign calls, dynamic argument handling, and tracker updates.
 * @notice This contract is a critical component of the Rules Engine, enabling secure and flexible rule evaluation and effect execution.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract RulesEngineProcessorFacet is FacetCommonImports{

    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Rule Evaluation Functions
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Evaluates the conditions associated with all applicable rules and returns the result.
     * @dev Primary entry point for policy checks.
     * @param contractAddress The address of the rules-enabled contract, used to pull the applicable rules.
     * @param arguments Function arguments, including the function signature and the arguments to be passed to the function.
     * @return retVal 1 if all rules pass, 0 if any rule fails.
     * TODO: refine the parameters to this function. contractAddress is not necessary as it's the message caller
     */
    function checkPolicies(address contractAddress, bytes calldata arguments) public returns (uint256 retVal) {  
        retVal = 1; 
        // Load the calling function data from storage
        PolicyAssociationS storage data = lib.getPolicyAssociationStorage();
        uint256[] memory policyIds = data.contractPolicyIdMap[contractAddress];
        // loop through all the active policies
        for(uint256 policyIdx = 0; policyIdx < policyIds.length; policyIdx++) {
            if(!_checkPolicy(policyIds[policyIdx], contractAddress, arguments)) {
                retVal = 0;
            }
        }
    }

    /**
     * @notice Checks a specific policy for compliance.
     * @param _policyId The ID of the policy to check.
     * @param _contractAddress The address of the contract being evaluated.
     * @param arguments Function arguments for the policy evaluation.
     * @return retVal True if the policy passes, false otherwise.
     */
    function _checkPolicy(uint256 _policyId, address _contractAddress, bytes calldata arguments) internal returns (bool retVal) {
        _contractAddress; // added to remove wanring. TODO remove this once msg.sender testing is complete 
        // Load the policy data from storage   
        PolicyStorageSet storage policyStorageSet = lib.getPolicyStorage().policyStorageSets[_policyId];
        mapping(uint256 ruleId => RuleStorageSet) storage ruleData = lib.getRuleStorage().ruleStorageSets[_policyId];

        // Retrieve placeHolder[] for specific rule to be evaluated and translate function signature argument array 
        // to rule specific argument array
        // note that arguments is being sliced, first 4 bytes are the function signature being passed (:4) and the rest (4:) 
        // are all the arguments associated for the rule to be invoked. This saves on further calculations so that we don't need to factor in the signature.
        retVal = _evaluateRulesAndExecuteEffects(ruleData ,_policyId, _loadApplicableRules(ruleData, policyStorageSet.policy, bytes4(arguments[:4])), arguments[4:]);
    }

    /**
     * @notice Loads applicable rules for a given calling function.
     * @param ruleData The mapping of rule IDs to rule storage sets.
     * @param policy The policy structure containing the rules.
     * @param callingFunction The function signature to match rules against.
     * @return An array of applicable rule IDs.
     */
    function _loadApplicableRules(mapping(uint256 ruleId => RuleStorageSet) storage ruleData, Policy storage policy, bytes4 callingFunction) internal view returns(uint256[] memory){
        // Load the applicable rule data from storage
        uint256[] memory applicableRules = new uint256[](policy.callingFunctionsToRuleIds[callingFunction].length);
        // Load the calling function data from storage
        uint256[] storage storagePointer = policy.callingFunctionsToRuleIds[callingFunction];
        for(uint256 i = 0; i < applicableRules.length; i++) {
            if(ruleData[storagePointer[i]].set) {
                applicableRules[i] = storagePointer[i];
            }
        }
        return applicableRules;
    }
    
    /**
     * @notice Evaluates rules and executes their effects based on the evaluation results.
     * @param ruleData The mapping of rule IDs to rule storage sets.
     * @param _policyId The ID of the policy being evaluated.
     * @param applicableRules An array of applicable rule IDs.
     * @param callingFunctionArgs The arguments for the calling function.
     * @return retVal True if all rules pass, false otherwise.
     */
    function _evaluateRulesAndExecuteEffects(mapping(uint256 ruleId => RuleStorageSet) storage ruleData, uint256 _policyId, uint256[] memory applicableRules, bytes calldata callingFunctionArgs) internal returns (bool retVal) {
        retVal = true;
        uint256 ruleCount = applicableRules.length;
        for(uint256 i = 0; i < ruleCount; i++) { 
            Rule storage rule = ruleData[applicableRules[i]].rule;
            if(!_evaluateIndividualRule(rule, _policyId, callingFunctionArgs)) {
                retVal = false;
                _doEffects(rule, _policyId, rule.negEffects, callingFunctionArgs);
            } else{
                _doEffects(rule, _policyId, rule.posEffects, callingFunctionArgs);
            }
        }
    }

    /**
     * @dev evaluates an individual rules condition(s)
     * @param _policyId Policy id being evaluated.
     * @param rule the rule structure containing the instruction set, with placeholders, to execute
     * @param callingFunctionArgs the values to replace the placeholders in the instruction set with.
     * @return response the result of the rule condition evaluation 
     */
    function _evaluateIndividualRule(Rule storage rule, uint256 _policyId, bytes calldata callingFunctionArgs) internal returns (bool response) {
        (bytes[] memory ruleArgs, Placeholder[] memory placeholders) = _buildArguments(rule, _policyId, callingFunctionArgs, false);
        response = _run(rule.instructionSet, placeholders, _policyId, ruleArgs);
    }

    /**
     * @dev Constructs the arguments required for building the rule's place holders.
     * @param rule The storage reference to the Rule struct containing the rule's details.
     * @param _policyId The unique identifier of the policy associated with the rule.
     * @param callingFunctionArgs The calldata containing the arguments for the calling function.
     * @param effect A boolean indicating whether the rule has an effect or not.
     * @return A tuple containing:
     *         - An array of bytes representing the constructed arguments.
     *         - An array of Placeholder structs used for argument substitution.
     */
    function _buildArguments(Rule storage rule, uint256 _policyId, bytes calldata callingFunctionArgs, bool effect) internal returns (bytes[] memory, Placeholder[] memory) {
        Placeholder[] memory placeHolders;
        if(effect) {
            placeHolders = rule.effectPlaceHolders;
        } else {
            placeHolders = rule.placeHolders;
        }       

        bytes[] memory retVals = new bytes[](placeHolders.length);
        for(uint256 placeholderIndex = 0; placeholderIndex < placeHolders.length; placeholderIndex++) {
            // Determine if the placeholder represents the return value of a foreign call or a function parameter from the calling function
            Placeholder memory placeholder = placeHolders[placeholderIndex];
            if(placeholder.foreignCall) {
                    ForeignCallReturnValue memory retVal = _evaluateForeignCalls(_policyId, callingFunctionArgs, placeholder.typeSpecificIndex, retVals);
                    // Set the placeholders value and type based on the value returned by the foreign call
                    retVals[placeholderIndex] = retVal.value;
                    placeHolders[placeholderIndex].pType = retVal.pType;
            } else if (placeholder.trackerValue) {
                // Load the Tracker data from storage
                Trackers memory tracker = lib.getTrackerStorage().trackers[_policyId][placeholder.typeSpecificIndex];
                retVals[placeholderIndex] = tracker.trackerValue;
            } else {
                // The placeholder represents a parameter from the calling function, set the value in the ruleArgs struct to the correct parameter
                if(placeholder.pType == PT.STR || placeholder.pType == PT.BYTES) {
                    retVals[placeholderIndex] = _getDynamicVariableFromCalldata(callingFunctionArgs, placeholder.typeSpecificIndex);
                } else if (placeholder.pType == PT.STATIC_TYPE_ARRAY || placeholder.pType == PT.DYNAMIC_TYPE_ARRAY) {
                    // if the placeholder represents an array, determine the length and set lenth as placeholder value in ruleArgs 
                    bytes32 value = bytes32(callingFunctionArgs[placeholder.typeSpecificIndex * 32: (placeholder.typeSpecificIndex + 1) * 32]);
                    retVals[placeholderIndex] = abi.encode(uint256(bytes32(callingFunctionArgs[uint(value):uint(value) + 32])));
                } else {
                    // since this is not a dynamic value, we can safely assume that it is only 1 word, therefore we multiply
                    // the typeSpecificIndex by 32 to get the correct position in the callingFunctionArgs array
                    // and then add 1 and multiply by 32 to get the correct 32 byte word to get the value
                    retVals[placeholderIndex] = callingFunctionArgs[
                        placeholder.typeSpecificIndex * 32: (placeholder.typeSpecificIndex + 1) * 32
                    ];
                }
            }
        }
        return (retVals, placeHolders);
    }

    /**
     * @dev Internal function to decode the arguments and do the comparisons.
     * @param prog An array of uint256 representing the program to be executed.
     * @param placeHolders An array of Placeholder structs used within the program.
     * @param _policyId The ID of the policy associated with the program execution.
     * @param arguments An array of bytes containing additional arguments for the program.
     * @return ans A boolean indicating the result of the program execution.
     */
    function _run(uint256[] memory prog, Placeholder[] memory placeHolders, uint256 _policyId, bytes[] memory arguments) internal returns (bool ans) {
        uint256[90] memory mem;
        uint256 idx = 0;
        uint256 opi = 0;
        while (idx < prog.length) {
            uint256 v = 0;
            LC op = LC(prog[idx]);
            if(op == LC.PLH) {
                // Placeholder format is: get the index of the argument in the array. For example, PLH 0 is the first argument in the arguments array and its type and value
                uint256 pli = prog[idx+1];
                PT typ = placeHolders[pli].pType;
                if(typ == PT.UINT) {
                    v = abi.decode(arguments[pli], (uint256)); idx += 2;
                } else if(typ == PT.ADDR) {
                    // Convert address to uint256 for direct comparison using == and != operations
                    v = uint256(uint160(address(abi.decode(arguments[pli], (address))))); idx += 2;
                } else if(typ == PT.STR) {
                    // Convert string to uint256 for direct comparison using == and != operations
                    v = uint256(keccak256(abi.encode(abi.decode(arguments[pli], (string))))); idx += 2;
                } else if(typ == PT.BOOL) {
                    // Convert bool to uint256 for direct comparison using == and != operations
                    v = uint256(ProcessorLib._bool2ui((abi.decode(arguments[pli], (bool))))); idx += 2;
                } else if(typ == PT.BYTES) {
                    // Convert bytes to uint256 for direct comparison using == and != operations
                    v = uint256(keccak256(abi.encode(abi.decode(arguments[pli], (bytes))))); idx += 2;
                } else if(typ == PT.STATIC_TYPE_ARRAY || typ == PT.DYNAMIC_TYPE_ARRAY) {
                    // length of array for direct comparison using == and != operations
                    v = abi.decode(arguments[pli], (uint256)); idx += 2;
                } else if (typ == PT.VOID) {
                    // v = 0; but already set to 0 above no need to do anything
                    idx += 2;
                }

            } else if(op == LC.TRU) {
                // update the tracker value
                // If the Tracker Type == Place Holder, pull the data from the place holder, otherwise, pull it from Memory
                TT tt = TT(prog[idx+3]);
                if (tt == TT.MEMORY){
                    _updateTrackerValue(_policyId, prog[idx + 1], mem[prog[idx+2]]);
                } else {
                    _updateTrackerValue(_policyId, prog[idx + 1], arguments[prog[idx+2]]);
                }
                idx += 4;
            } else if (op == LC.NUM) { v = prog[idx+1]; idx += 2; }
            else if (op == LC.ADD) { v = mem[prog[idx+1]] + mem[prog[idx+2]]; idx += 3; }
            else if (op == LC.SUB) { v = mem[prog[idx+1]] - mem[prog[idx+2]]; idx += 3; }
            else if (op == LC.MUL) { v = mem[prog[idx+1]] * mem[prog[idx+2]]; idx += 3; }
            else if (op == LC.DIV) { v = mem[prog[idx+1]] / mem[prog[idx+2]]; idx += 3; }
            else if (op == LC.ASSIGN) { v = mem[prog[idx+2]]; idx += 3; }
            else if (op == LC.LT) { v = ProcessorLib._bool2ui(mem[prog[idx+1]] < mem[prog[idx+2]]); idx += 3; }
            else if (op == LC.GT) { v = ProcessorLib._bool2ui(mem[prog[idx+1]] > mem[prog[idx+2]]); idx += 3; }
            else if (op == LC.EQ) { v = ProcessorLib._bool2ui(mem[prog[idx+1]] == mem[prog[idx+2]]); idx += 3; }
            else if (op == LC.NOTEQ) { v = ProcessorLib._bool2ui(mem[prog[idx+1]] != mem[prog[idx+2]]); idx += 3; }
            else if (op == LC.GTEQL) { v = ProcessorLib._bool2ui(mem[prog[idx+1]] >= mem[prog[idx+2]]); idx += 3; }
            else if (op == LC.LTEQL) { v = ProcessorLib._bool2ui(mem[prog[idx+1]] <= mem[prog[idx+2]]); idx += 3; }
            else if (op == LC.AND) { v = ProcessorLib._bool2ui(ProcessorLib._ui2bool(mem[prog[idx+1]]) && ProcessorLib._ui2bool(mem[prog[idx+2]])); idx += 3; }
            else if (op == LC.OR ) { v = ProcessorLib._bool2ui(ProcessorLib._ui2bool(mem[prog[idx+1]]) || ProcessorLib._ui2bool(mem[prog[idx+2]])); idx += 3; }
            else if (op == LC.NOT) { v = ProcessorLib._bool2ui(! ProcessorLib._ui2bool(mem[prog[idx+1]])); idx += 2; }
            else { revert("Illegal instruction"); }
            mem[opi] = v;
            opi += 1;
        }
        return ProcessorLib._ui2bool(mem[opi - 1]);
    }

    /**
     * @dev This function updates the tracker value with the information provided
     * @param _policyId Policy id being evaluated.
     * @param _trackerId ID of the tracker to update.
     * @param _trackerValue Value to update within the tracker
     */
    function _updateTrackerValue(uint256 _policyId, uint256 _trackerId, uint256 _trackerValue) internal{
        // retrieve the tracker
        Trackers storage trk = lib.getTrackerStorage().trackers[_policyId][_trackerId];
        if(trk.pType == PT.UINT) {
            trk.trackerValue = abi.encode(_trackerValue);
        } else if(trk.pType == PT.ADDR) {
            trk.trackerValue = abi.encode(ProcessorLib._ui2addr(_trackerValue));
        } else if(trk.pType == PT.BOOL) {
            trk.trackerValue = abi.encode(ProcessorLib._ui2bool(_trackerValue));
        } else if(trk.pType == PT.BYTES) {
            trk.trackerValue = ProcessorLib._ui2bytes(_trackerValue);
        } 
    }

    /**
     * @dev Internal function to update the value of a tracker associated with a specific policy.
     * @param _policyId The ID of the policy to which the tracker belongs.
     * @param _trackerId The ID of the tracker whose value is being updated.
     * @param _trackerValue The new value to be assigned to the tracker, encoded as bytes.
     */
    function _updateTrackerValue(uint256 _policyId, uint256 _trackerId, bytes memory _trackerValue) internal{
        // retrieve the tracker
        Trackers storage trk = lib.getTrackerStorage().trackers[_policyId][_trackerId];
        trk.trackerValue = _trackerValue;
    }


    
    /**
     * @notice Evaluates foreign calls within the rules engine processor.
     * @dev This function processes and evaluates calls to external contracts or systems
     *      as part of the rules engine's logic. Ensure that the necessary validations
     *      and security checks are in place when interacting with foreign calls.
     * @param _policyId Id of the policy.
     * @param callingFunctionArgs representation of the calling function arguments
     * @param foreignCallIndex Index of the foreign call.
     * @param retVals array of return values from previous foreign calls, trackers, etc.
     * @return returnValue The output of the foreign call.
     */
    function _evaluateForeignCalls(
        uint256 _policyId, 
        bytes calldata callingFunctionArgs, 
        uint256 foreignCallIndex,
        bytes[] memory retVals
    ) public returns(ForeignCallReturnValue memory returnValue) {
        // Load the Foreign Call data from storage
        ForeignCall memory foreignCall = lib.getForeignCallStorage().foreignCalls[_policyId][foreignCallIndex];
        if (foreignCall.set) {
            return evaluateForeignCallForRule(foreignCall, callingFunctionArgs, retVals);
        }
    }

    /**
     * @dev encodes the arguments and places a foreign call, returning the calls return value as long as it is successful
     * @param fc the Foreign Call structure
     * @param functionArguments the arguments of the rules calling function (to be passed to the foreign call as needed)
     * @return retVal the foreign calls return value
     */
    function evaluateForeignCallForRule(ForeignCall memory fc, bytes calldata functionArguments, bytes[] memory retVals) public returns (ForeignCallReturnValue memory retVal) {
        // First, calculate total size needed and positions of dynamic data
        bytes memory encodedCall = bytes.concat(bytes4(fc.signature));
        bytes memory dynamicData;

        uint256 lengthToAppend = 0;
        // First pass: calculate sizes
        for(uint256 i = 0; i < fc.parameterTypes.length; i++) {
            PT argType = fc.parameterTypes[i];
            uint256 typeSpecificIndex;
            bool isRetVal = false;
            bytes32 value;
            if (fc.typeSpecificIndices[i] < 0) {
                typeSpecificIndex = _getAbsoluteAssembly(fc.typeSpecificIndices[i]) - 1; // -1 because retVals is 0 indexed
                isRetVal = true;
                value = bytes32(retVals[typeSpecificIndex]);
                if (argType == PT.STR || argType == PT.BYTES) {
                    encodedCall = bytes.concat(encodedCall, bytes32(32 * (fc.parameterTypes.length) + lengthToAppend));
                    bytes memory stringData = ProcessorLib._extractStringData(retVals[typeSpecificIndex]);
                    dynamicData = bytes.concat(
                        dynamicData,
                        stringData      // data (already padded)
                    );
                    lengthToAppend += stringData.length;
                } else if (argType == PT.STATIC_TYPE_ARRAY || argType == PT.DYNAMIC_TYPE_ARRAY) {
                    // encode the static offset
                    encodedCall = bytes.concat(encodedCall, bytes32(32 * (fc.parameterTypes.length) + lengthToAppend));
                    bytes memory arrayData = ProcessorLib._extractDynamicArrayData(retVals[typeSpecificIndex]);
                    dynamicData = bytes.concat(dynamicData, arrayData);
                    lengthToAppend += arrayData.length;
                } else {
                    encodedCall = bytes.concat(encodedCall, value);
                }
            } else {
                typeSpecificIndex = _getAbsoluteAssembly(fc.typeSpecificIndices[i]);
                value = bytes32(functionArguments[typeSpecificIndex * 32: (typeSpecificIndex + 1) * 32]);
                if (argType == PT.STR || argType == PT.BYTES) {
                    // Add offset to head
                    uint256 dynamicOffset = 32 * (fc.parameterTypes.length) + lengthToAppend;
                    encodedCall = bytes.concat(encodedCall, bytes32(dynamicOffset));
                    // Get the dynamic data
                    uint256 length = uint256(bytes32(functionArguments[uint(value):uint(value) + 32]));
                    uint256 words = 32 + ((length / 32) + 1) * 32;
                    bytes memory dynamicValue = functionArguments[uint(value):uint(value) + words];
                    // Add length and data (data is already padded to 32 bytes)
                    dynamicData = bytes.concat(
                        dynamicData,
                        dynamicValue      // data (already padded)
                    );
                    lengthToAppend += words;  // 32 for length + 32 for padded data
                } else if (argType == PT.STATIC_TYPE_ARRAY) {
                    // encode the static offset
                    encodedCall = bytes.concat(encodedCall, bytes32(32 * (fc.parameterTypes.length) + lengthToAppend));
                    uint256 arrayLength = uint256(bytes32(functionArguments[uint(value):uint(value) + 32]));
                    // Get the static type array
                    bytes memory staticArray = new bytes(arrayLength * 32);
                    uint256 lengthToGrab = ((arrayLength + 1) * 32);
                    staticArray = functionArguments[uint(value):uint(value) + lengthToGrab];
                    dynamicData = bytes.concat(dynamicData, staticArray);
                    lengthToAppend += lengthToGrab;
                } else if (argType == PT.DYNAMIC_TYPE_ARRAY) {
                    // encode the dynamic offset
                    uint256 baseDynamicOffset = 32 * (fc.parameterTypes.length) + lengthToAppend;
                    encodedCall = bytes.concat(encodedCall, bytes32(baseDynamicOffset));
                    uint256 length = uint256(bytes32(functionArguments[uint(value):uint(value) + 32]));
                    lengthToAppend += 32;
                    dynamicData = bytes.concat(dynamicData, abi.encode(length));
                    (dynamicData, lengthToAppend) = _getDynamicValueArrayData(functionArguments, dynamicData, length, lengthToAppend, uint(value));
                }
                else {
                    encodedCall = bytes.concat(encodedCall, value);
                }
            }
        }

        bytes memory callData = bytes.concat(encodedCall, dynamicData);
        // Place the foreign call
        (bool response, bytes memory data) = fc.foreignCallAddress.call(callData);
    

        // Verify that the foreign call was successful
        if(response) {
            // Decode the return value based on the specified return value parameter type in the foreign call structure
            retVal.pType = fc.returnType;
            retVal.value = data;
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
     * @param callingFunctionArgs Encoded calldata containing arguments for the calling function.
     */
    function _doEffects(Rule storage rule, uint256 _policyId, Effect[] memory _effects, bytes calldata callingFunctionArgs) internal {

        // Load the Effect data from storage
        for(uint256 i = 0; i < _effects.length; i++) {
            Effect memory effect = _effects[i];
            if(effect.valid) {
                if (effect.effectType == ET.REVERT) { 
                    _doRevert(effect.errorMessage);
                } else if (effect.effectType == ET.EVENT) {
                    _buildEvent(rule, _effects[i].dynamicParam, _policyId, _effects[i].text, _effects[i], callingFunctionArgs);
                } else {
                    _evaluateExpression(rule, _policyId, callingFunctionArgs, effect.instructionSet);
                }
            }
        }
    }

    /**
     * @dev Define event to be fired 
     * @param rule the rule struct event is associated to 
     * @param isDynamicParam static or dynamic event parameters 
     * @param _policyId policy Id 
     * @param _message Event Message String 
     * @param effectStruct effect struct 
     * @param callingFunctionArgs calling function arguments 
     */
    function _buildEvent(Rule storage rule,
        bool isDynamicParam, 
        uint256 _policyId, 
        bytes32 _message, 
        Effect memory effectStruct, 
        bytes calldata callingFunctionArgs
        ) internal {
        // determine if we need to dynamically build event key 
        if (isDynamicParam){
            // fire event by param type based on return value 
            _fireDynamicEvent(rule, _policyId, _message, callingFunctionArgs);
        } else {
            _fireEvent(_policyId, _message, effectStruct);
        }
    }

    /**
     * @dev Fire dynamic Event  
     * @param rule the rule struct event is associated to 
     * @param _policyId policy Id 
     * @param _message Event Message String 
     * @param callingFunctionArgs calling function arguments 
     */
    function _fireDynamicEvent(Rule storage rule, uint256 _policyId, bytes32 _message, bytes calldata callingFunctionArgs) internal {
        // Build the effect arguments struct for event parameters:  
        (bytes[] memory effectArguments, Placeholder[] memory placeholders) = _buildArguments(rule, _policyId, callingFunctionArgs, true);
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
     * @dev Evaluate an effect expression
     * @param rule the rule structure containing the instruction set, with placeholders, to execute
     * @param _policyId the policy id
     * @param callingFunctionArgs arguments of the calling function
     * @param instructionSet instruction set 
     */
    function _evaluateExpression(Rule storage rule, uint256 _policyId, bytes calldata callingFunctionArgs, uint256[] memory instructionSet) internal {
        (bytes[] memory effectArguments, Placeholder[] memory placeholders) = _buildArguments(rule, _policyId, callingFunctionArgs, true);
        if(instructionSet.length > 1) {
            _run(instructionSet, placeholders, _policyId, effectArguments);
        }
    }

    function _getAbsoluteAssembly(int256 _number) public pure returns (uint256) {
        uint256 result;
        assembly {
            // If number is negative, negate it
            switch slt(_number, 0)
            case 1 { result := sub(0, _number) }
            default { result := _number }
        }
        return result;
    }
    
    /**
     * @notice Extracts a dynamic variable from the provided calldata at the specified index.
     * @dev This function is a pure function and does not modify state.
     * @param data The calldata containing the dynamic variables.
     * @param index The index of the dynamic variable to extract.
     * @return retVal The extracted dynamic variable as a bytes array.
     */
    function _getDynamicVariableFromCalldata(bytes calldata data, uint256 index) internal pure returns (bytes memory retVal) {
        // Get offset from parameter position, using index * 32 to get the correct position in the calldata
        uint256 offset = uint256(bytes32(data[index * 32:(index + 1) * 32]));
        // Get length from the offset position, using offset + 32 to get the correct position in the calldata
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        // Allocate memory for result: 32 (offset) + 32 (length) + data length
        bytes memory result = new bytes(64 + ((length + 31) / 32) * 32);
        assembly {
            // Store offset to length (0x20)
            mstore(add(result, 32), 0x20)
            
            // Store length
            mstore(add(result, 64), length)
            
            // Copy actual data
            calldatacopy(
                add(result, 96),           // destination (after offset+length)
                add(add(data.offset, offset), 32),  // source (after length in calldata)
                mul(div(add(length, 31),32), 32)                      // length of data
            )
        }
        return result;
    }
    
    /**
     * @notice Retrieves a portion of dynamic value array data from the provided inputs.
     * @dev This function extracts a segment of dynamic data based on the specified length and offset.
     * @param data The calldata input containing the original data.
     * @param dynamicData The memory input containing the dynamic data to process.
     * @param length The total length of the dynamic data array.
     * @param lengthToAppend The length of data to append to the result.
     * @param offset The starting position in the dynamic data array to begin extraction.
     * @return A tuple containing:
     *         - A bytes memory object representing the extracted data.
     *         - A uint256 value indicating the updated offset after extraction.
     */
    function _getDynamicValueArrayData(bytes calldata data, bytes memory dynamicData, uint length, uint lengthToAppend, uint256 offset) internal pure returns (bytes memory, uint256) {
        bytes memory arrayData;
        
        lengthToAppend += (length * 0x20);
        uint256 baseDynamicOffset = 32 + ((length - 1) * 32);
        for (uint256 j = 1; j <= length; j++) {
            // Add current offset to dynamic data
            dynamicData = bytes.concat(dynamicData, bytes32(baseDynamicOffset));
            
            uint getValueOffsetValue = offset + (j * 32);
            uint256 dynamicValueOffset = uint256(bytes32(data[getValueOffsetValue:getValueOffsetValue + 32])) + 32;
            
            // Get length of current string
            uint256 dynamicValueLength = uint256(bytes32(data[offset + dynamicValueOffset:offset + dynamicValueOffset + 32]));
            
            // Calculate padded length for this string's data
            uint256 paddedLength = 32 + ((dynamicValueLength + 31) / 32) * 32;
            
            // Get the string data (including length and value)
            bytes memory dynamicValue = data[offset+dynamicValueOffset:offset+dynamicValueOffset+paddedLength];

            // Next offset should point after current string's data
            baseDynamicOffset += paddedLength;
            
            lengthToAppend += paddedLength;
            arrayData = bytes.concat(arrayData, dynamicValue);
        }

        dynamicData = bytes.concat(dynamicData, arrayData);
        
        return (dynamicData, lengthToAppend);
    }

}
