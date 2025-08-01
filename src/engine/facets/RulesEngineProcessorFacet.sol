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
contract RulesEngineProcessorFacet is FacetCommonImports {
    // Global variable type constants
    uint8 constant GLOBAL_NONE = 0;
    uint8 constant GLOBAL_MSG_SENDER = 1;
    uint8 constant GLOBAL_BLOCK_TIMESTAMP = 2;
    uint8 constant GLOBAL_MSG_DATA = 3;
    uint8 constant GLOBAL_BLOCK_NUMBER = 4;
    uint8 constant GLOBAL_TX_ORIGIN = 5;

    string public constant version = "v1.0.0";

    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Rule Evaluation Functions
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Evaluates the conditions associated with all applicable rules and returns the result.
     * @dev Primary entry point for policy checks.
     * @param arguments Function arguments, including the function signature and the arguments to be passed to the function.
     */
    function checkPolicies(bytes calldata arguments) public {
        // Load the calling function data from storage
        // Data validation will always ensure policyIds.length will be less than MAX_LOOP
        PolicyAssociationStorage storage data = lib._getPolicyAssociationStorage();
        uint256[] memory policyIds = data.contractPolicyIdMap[msg.sender];
        // loop through all the active policies
        for (uint256 policyIdx = 0; policyIdx < policyIds.length; policyIdx++) _checkPolicy(policyIds[policyIdx], msg.sender, arguments);
    }

    /**
     * @notice Evaluates foreign calls within the rules engine processor.
     * @dev This function processes and evaluates calls to external contracts or systems
     *      as part of the rules engine's logic. Ensure that the necessary validations
     *      and security checks are in place when interacting with foreign calls.
     * @param policyId Id of the policy.
     * @param callingFunctionArgs representation of the calling function arguments
     * @param foreignCallIndex Index of the foreign call.
     * @param retVals array of return values from previous foreign calls, trackers, etc.
     * @return The output of the foreign call.
     */
    function evaluateForeignCalls(
        uint256 policyId,
        bytes calldata callingFunctionArgs,
        uint256 foreignCallIndex,
        bytes[] memory retVals,
        ForeignCallEncodedIndex[] memory metadata
    ) public returns (ForeignCallReturnValue memory) {
        // Load the Foreign Call data from storage
        ForeignCall memory foreignCall = lib._getForeignCallStorage().foreignCalls[policyId][foreignCallIndex];
        if (foreignCall.set) {
            return evaluateForeignCallForRule(foreignCall, callingFunctionArgs, retVals, metadata, policyId);
        }
    }

    /**
     * @dev encodes the arguments and places a foreign call, returning the calls return value as long as it is successful
     * @param fc the Foreign Call structure
     * @param functionArguments the arguments of the rules calling function (to be passed to the foreign call as needed)
     * @return retVal the foreign calls return value
     */
    function evaluateForeignCallForRule(
        ForeignCall memory fc,
        bytes calldata functionArguments,
        bytes[] memory retVals,
        ForeignCallEncodedIndex[] memory metadata,
        uint256 policyId
    ) public returns (ForeignCallReturnValue memory retVal) {
        // First, calculate total size needed and positions of dynamic data
        bytes memory encodedCall = bytes.concat(bytes4(fc.signature));
        bytes memory dynamicData = "";

        uint256 lengthToAppend = 0;
        uint256 mappedTrackerKeyIndex = 0;
        // calculate sizes
        // Data validation will always ensure fc.parameterTypes.length will be less than MAX_LOOP
        for (uint256 i = 0; i < fc.parameterTypes.length; i++) {
            ParamTypes argType = fc.parameterTypes[i];
            ForeignCallEncodedIndex memory encodedIndex = fc.encodedIndices[i];

            if (encodedIndex.eType == EncodedIndexType.MAPPED_TRACKER_KEY) {
                ForeignCallEncodedIndex memory mappedTrackerKeyEI = fc.mappedTrackerKeyIndices[mappedTrackerKeyIndex];
                uint256 parameterTypesLength = fc.parameterTypes.length;
                mappedTrackerKeyIndex++;
                (encodedCall, lengthToAppend, dynamicData) = evaluateForeignCallForRuleMappedTrackerKey(
                    functionArguments,
                    retVals,
                    policyId,
                    encodedIndex.index,
                    encodedCall,
                    lengthToAppend,
                    dynamicData,
                    mappedTrackerKeyEI,
                    parameterTypesLength
                );
            } else if (encodedIndex.eType != EncodedIndexType.ENCODED_VALUES) {
                (encodedCall, lengthToAppend, dynamicData) = evaluateForeignCallForRulePlaceholderValues(
                    fc,
                    retVals,
                    metadata,
                    encodedCall,
                    lengthToAppend,
                    i,
                    dynamicData
                );
            } else {
                (encodedCall, lengthToAppend, dynamicData) = evaluateForeignCallForRuleEncodedValues(
                    fc,
                    argType,
                    functionArguments,
                    encodedCall,
                    lengthToAppend,
                    dynamicData,
                    i
                );
            }
        }

        bytes memory callData = bytes.concat(encodedCall, dynamicData);
        // Place the foreign call
        (bool response, bytes memory data) = fc.foreignCallAddress.call(callData);
        // Verify that the foreign call was successful
        if (response) {
            // Decode the return value based on the specified return value parameter type in the foreign call structure
            retVal.pType = fc.returnType;
            retVal.value = data;
        }
    }

    function evaluateForeignCallForRuleMappedTrackerKey(
        bytes calldata functionArguments,
        bytes[] memory retVals,
        uint256 policyId,
        uint256 trackerIndex,
        bytes memory encodedCall,
        uint256 lengthToAppend,
        bytes memory dynamicData,
        ForeignCallEncodedIndex memory mappedTrackerKeyEI,
        uint256 parameterTypesLength
    ) public returns (bytes memory, uint256, bytes memory) {
        bytes memory mappedTrackerValue;
        ParamTypes typ = lib._getTrackerStorage().trackers[policyId][trackerIndex].trackerKeyType;

        (mappedTrackerValue, typ) = _foreignCallGetMappedTrackerValue(
            functionArguments,
            retVals,
            policyId,
            trackerIndex,
            mappedTrackerKeyEI,
            typ
        );

        (encodedCall, lengthToAppend, dynamicData) = concatenateCallOnMemory(
            encodedCall,
            lengthToAppend,
            dynamicData,
            mappedTrackerValue,
            typ,
            parameterTypesLength
        );
        return (encodedCall, lengthToAppend, dynamicData);
    }

    function _foreignCallGetMappedTrackerValue(
        bytes calldata functionArguments,
        bytes[] memory retVals,
        uint256 policyId,
        uint256 trackerIndex,
        ForeignCallEncodedIndex memory mappedTrackerKeyEI,
        ParamTypes typ
    ) internal returns (bytes memory mappedTrackerValue, ParamTypes valueType) {
        uint256 mappedTrackerKey;
        if (mappedTrackerKeyEI.eType == EncodedIndexType.ENCODED_VALUES) {
            if (typ == ParamTypes.STR || typ == ParamTypes.BYTES) {
                bytes memory dynamicVariable = _getDynamicVariableFromCalldata(functionArguments, mappedTrackerKeyEI.index);
                mappedTrackerKey = uint256(keccak256(dynamicVariable));
            } else {
                mappedTrackerKey = uint256(bytes32(functionArguments[mappedTrackerKeyEI.index * 32:(mappedTrackerKeyEI.index + 1) * 32]));
            }
            (mappedTrackerValue, valueType) = _getMappedTrackerValue(policyId, trackerIndex, mappedTrackerKey);
        } else {
            if (typ == ParamTypes.STR || typ == ParamTypes.BYTES) {
                mappedTrackerKey = uint256(keccak256(retVals[mappedTrackerKeyEI.index]));
            } else {
                mappedTrackerKey = uint256(bytes32(retVals[mappedTrackerKeyEI.index]));
            }
            (mappedTrackerValue, valueType) = _getMappedTrackerValue(policyId, trackerIndex, mappedTrackerKey);
        }
    }

    /**
     * @notice Processes encoded values from function arguments for foreign call encoding
     * @param fc The ForeignCall struct containing call configuration
     * @param argType The parameter type for the current argument
     * @param functionArguments The encoded arguments from the calling function
     * @param encodedCall Current encoded call data being built
     * @param lengthToAppend Current length of dynamic data to append
     * @param dynamicData Current dynamic data portion of the call
     * @param i Current parameter index being processed
     * @return encodedCall Updated encoded call data
     * @return lengthToAppend Updated length of dynamic data
     * @return dynamicData Updated dynamic data portion
     */
    function evaluateForeignCallForRuleEncodedValues(
        ForeignCall memory fc,
        ParamTypes argType,
        bytes calldata functionArguments,
        bytes memory encodedCall,
        uint256 lengthToAppend,
        bytes memory dynamicData,
        uint256 i
    ) public pure returns (bytes memory, uint256, bytes memory) {
        uint256 typeSpecificIndex = fc.encodedIndices[i].index;
        bytes32 value = bytes32(functionArguments[typeSpecificIndex * 32:(typeSpecificIndex + 1) * 32]);
        if (argType == ParamTypes.STR || argType == ParamTypes.BYTES) {
            // Add offset to head
            uint256 dynamicOffset = 32 * (fc.parameterTypes.length) + lengthToAppend;
            encodedCall = bytes.concat(encodedCall, bytes32(dynamicOffset));
            // Get the dynamic data - and bounds checking
            require(uint(value) < functionArguments.length, DYNDATA_OFFSET);
            require(uint(value) + 32 <= functionArguments.length, DYNDATA_OUTBNDS);
            uint256 length = uint256(bytes32(functionArguments[uint(value):uint(value) + 32]));
            // Calculate total bytes needed: 32 bytes for length prefix + padded data length (round up to nearest 32-byte boundary)
            uint256 words = 32 + ((length + 31) / 32) * 32;

            require(uint(value) + words <= functionArguments.length, DYNDATA_OUTBNDS);

            bytes memory dynamicValue = functionArguments[uint(value):uint(value) + words];
            // Add length and data (data is already padded to 32 bytes)
            dynamicData = bytes.concat(
                dynamicData,
                dynamicValue // data (already padded)
            );
            lengthToAppend += words; // 32 for length + 32 for padded data
        } else if (argType == ParamTypes.STATIC_TYPE_ARRAY) {
            // encode the static offset
            encodedCall = bytes.concat(encodedCall, bytes32(32 * (fc.parameterTypes.length) + lengthToAppend));
            uint256 arrayLength = uint256(bytes32(functionArguments[uint(value):uint(value) + 32]));
            // Get the static type array
            bytes memory staticArray = new bytes(arrayLength * 32);
            uint256 lengthToGrab = ((arrayLength + 1) * 32);
            staticArray = functionArguments[uint(value):uint(value) + lengthToGrab];
            dynamicData = bytes.concat(dynamicData, staticArray);
            lengthToAppend += lengthToGrab;
        } else if (argType == ParamTypes.DYNAMIC_TYPE_ARRAY) {
            uint256 baseDynamicOffset = 32 * (fc.parameterTypes.length) + lengthToAppend;
            encodedCall = bytes.concat(encodedCall, bytes32(baseDynamicOffset));
            uint256 length = uint256(bytes32(functionArguments[uint(value):uint(value) + 32]));
            lengthToAppend += 32;
            dynamicData = bytes.concat(dynamicData, abi.encode(length));
            (dynamicData, lengthToAppend) = _getDynamicValueArrayData(functionArguments, dynamicData, length, lengthToAppend, uint(value));
        } else {
            encodedCall = bytes.concat(encodedCall, value);
        }
        return (encodedCall, lengthToAppend, dynamicData);
    }

    /**
     * @notice Processes placeholder values for foreign call encoding
     * @param fc The ForeignCall struct containing call configuration
     * @param retVals Array of return values from previous operations
     * @param metadata Array of encoded index metadata for parameter resolution
     * @param encodedCall Current encoded call data being built
     * @param lengthToAppend Current length of dynamic data to append
     * @param i Current parameter index being processed
     * @param dynamicData Current dynamic data portion of the call
     * @return encodedCall Updated encoded call data
     * @return lengthToAppend Updated length of dynamic data
     * @return dynamicData Updated dynamic data portion
     */
    function evaluateForeignCallForRulePlaceholderValues(
        ForeignCall memory fc,
        bytes[] memory retVals,
        ForeignCallEncodedIndex[] memory metadata,
        bytes memory encodedCall,
        uint256 lengthToAppend,
        uint256 i,
        bytes memory dynamicData
    ) public view returns (bytes memory, uint256, bytes memory) {
        ParamTypes argType = fc.parameterTypes[i];
        uint256 index = fc.encodedIndices[i].index;
        // Handle global variables separately
        {
            EncodedIndexType eType = fc.encodedIndices[i].eType;
            if (eType == EncodedIndexType.GLOBAL_VAR) {
                return _handleGlobalVarForForeignCall(fc, argType, uint8(index), encodedCall, lengthToAppend, dynamicData);
            }
        }
        uint256 retValIndex;
        uint256 iter = 0;
        for (uint256 j = 0; j < metadata.length; j++) {
            if (metadata[j].index == index && metadata[j].eType == fc.encodedIndices[i].eType) {
                retValIndex = iter;
                break;
            }
            if (metadata[j].eType != EncodedIndexType.ENCODED_VALUES) {
                iter += 1;
            }
        }
        bytes memory value = retVals[retValIndex];
        uint256 parameterTypesLength = fc.parameterTypes.length;
        (encodedCall, lengthToAppend, dynamicData) = concatenateCallOnMemory(
            encodedCall,
            lengthToAppend,
            dynamicData,
            value,
            argType,
            parameterTypesLength
        );
        return (encodedCall, lengthToAppend, dynamicData);
    }

    function concatenateCallOnMemory(
        bytes memory encodedCall,
        uint256 lengthToAppend,
        bytes memory dynamicData,
        bytes memory value,
        ParamTypes argType,
        uint256 parameterTypesLength
    ) public pure returns (bytes memory, uint256, bytes memory) {
        if (argType == ParamTypes.STR || argType == ParamTypes.BYTES) {
            encodedCall = bytes.concat(encodedCall, bytes32(32 * (parameterTypesLength) + lengthToAppend));
            bytes memory stringData = ProcessorLib._extractStringData(value);
            dynamicData = bytes.concat(
                dynamicData,
                stringData // data (already padded)
            );
            lengthToAppend += stringData.length;
        } else if (argType == ParamTypes.STATIC_TYPE_ARRAY || argType == ParamTypes.DYNAMIC_TYPE_ARRAY) {
            // encode the static offset
            encodedCall = bytes.concat(encodedCall, bytes32(32 * (parameterTypesLength) + lengthToAppend));
            bytes memory arrayData = ProcessorLib._extractDynamicArrayData(value);
            dynamicData = bytes.concat(dynamicData, arrayData);
            lengthToAppend += arrayData.length;
        } else {
            encodedCall = bytes.concat(encodedCall, value);
        }
        return (encodedCall, lengthToAppend, dynamicData);
    }

    /**
     * @notice Handles global variable processing for foreign call encoding
     * @dev Internal function that processes global variable types and encodes them appropriately for foreign call arguments
     * @param fc The ForeignCall struct containing the call configuration and parameter types
     * @param argType The expected parameter type for the global variable in the foreign call
     * @param globalVarType An uint8 identifier representing which global variable to process:
     * @param encodedCall The current encoded call data being built for the foreign call
     * @param lengthToAppend The current length of dynamic data to be appended
     * @param dynamicData The current dynamic data portion of the encoded call
     * @return encodedCall The updated encoded call data with the global variable parameter added
     * @return lengthToAppend The updated length of dynamic data after processing
     * @return dynamicData The updated dynamic data portion after processing
     */
    function _handleGlobalVarForForeignCall(
        ForeignCall memory fc,
        ParamTypes argType,
        uint8 globalVarType,
        bytes memory encodedCall,
        uint256 lengthToAppend,
        bytes memory dynamicData
    ) private view returns (bytes memory, uint256, bytes memory) {
        if (globalVarType == GLOBAL_MSG_SENDER) {
            if (argType == ParamTypes.ADDR) {
                bytes32 value = bytes32(uint256(uint160(msg.sender)));
                encodedCall = bytes.concat(encodedCall, value);
            } else {
                revert(MSGSENDER_ONLY_ADDR);
            }
        } else if (globalVarType == GLOBAL_BLOCK_TIMESTAMP) {
            if (argType == ParamTypes.UINT) {
                bytes32 value = bytes32(block.timestamp);
                encodedCall = bytes.concat(encodedCall, value);
            } else {
                revert(BLOCKTIME_ONLY_UINT);
            }
        } else if (globalVarType == GLOBAL_MSG_DATA) {
            if (argType == ParamTypes.STR || argType == ParamTypes.BYTES) {
                encodedCall = bytes.concat(encodedCall, bytes32(32 * (fc.parameterTypes.length) + lengthToAppend));

                // Create properly encoded msg.data with length prefix
                bytes memory encodedMsgData = new bytes(msg.data.length + 32);

                // Store length in first 32 bytes
                uint256 msgDataLength = msg.data.length;
                assembly {
                    mstore(add(encodedMsgData, 32), msgDataLength)
                }

                // Copy the actual data
                for (uint256 j = 0; j < msg.data.length; j++) {
                    encodedMsgData[j + 32] = msg.data[j];
                }

                dynamicData = bytes.concat(dynamicData, encodedMsgData);
                lengthToAppend += encodedMsgData.length;
            } else {
                revert(MSGDTA_ONLY_STRING);
            }
        } else if (globalVarType == GLOBAL_BLOCK_NUMBER) {
            if (argType == ParamTypes.UINT) {
                bytes32 value = bytes32(block.number);
                encodedCall = bytes.concat(encodedCall, value);
            } else {
                revert(BLK_NUMBER_ONLY_UINT);
            }
        } else if (globalVarType == GLOBAL_TX_ORIGIN) {
            if (argType == ParamTypes.ADDR) {
                bytes32 value = bytes32(uint256(uint160(tx.origin)));
                encodedCall = bytes.concat(encodedCall, value);
            } else {
                revert(TX_ORG_ONLY_ADDR);
            }
        } else {
            revert(GLB_VAR_INV);
        }

        return (encodedCall, lengthToAppend, dynamicData);
    }

    /**
     * @notice Checks a specific policy for compliance.
     * @param _policyId The ID of the policy to check.
     * @param _contractAddress The address of the contract being evaluated.
     * @param _arguments Function arguments for the policy evaluation.
     * @return retVal True if the policy passes, false otherwise.
     */
    function _checkPolicy(uint256 _policyId, address _contractAddress, bytes calldata _arguments) internal returns (bool retVal) {
        _contractAddress; // added to remove wanring. TODO remove this once msg.sender testing is complete
        // Load the policy data from storage
        PolicyStorageSet storage policyStorageSet = lib._getPolicyStorage().policyStorageSets[_policyId];
        mapping(uint256 ruleId => RuleStorageSet) storage ruleData = lib._getRuleStorage().ruleStorageSets[_policyId];

        // Retrieve placeHolder[] for specific rule to be evaluated and translate function signature argument array
        // to rule specific argument array
        // note that arguments is being sliced, first 4 bytes are the function signature being passed (:4) and the rest (4:)
        // are all the arguments associated for the rule to be invoked. This saves on further calculations so that we don't need to factor in the signature.
        if (policyStorageSet.policy.policyType == PolicyType.DISABLED_POLICY) return true;
        retVal = _evaluateRulesAndExecuteEffects(
            ruleData,
            _policyId,
            _loadApplicableRules(ruleData, policyStorageSet.policy, bytes4(_arguments[:4])),
            _arguments[4:]
        );
    }

    /**
     * @notice Evaluates rules and executes their effects based on the evaluation results.
     * @param _ruleData The mapping of rule IDs to rule storage sets.
     * @param _policyId The ID of the policy being evaluated.
     * @param _applicableRules An array of applicable rule IDs.
     * @param _callingFunctionArgs The arguments for the calling function.
     * @return _retVal True if all rules pass, false otherwise.
     */
    function _evaluateRulesAndExecuteEffects(
        mapping(uint256 ruleId => RuleStorageSet) storage _ruleData,
        uint256 _policyId,
        uint256[] memory _applicableRules,
        bytes calldata _callingFunctionArgs
    ) internal returns (bool _retVal) {
        _retVal = true;
        uint256 ruleCount = _applicableRules.length;
        // Data validation will always ensure ruleCount will be less than MAX_LOOP
        for (uint256 i = 0; i < ruleCount; i++) {
            Rule storage rule = _ruleData[_applicableRules[i]].rule;
            if (!_evaluateIndividualRule(rule, _policyId, _callingFunctionArgs)) {
                _retVal = false;
                _doEffects(rule, _policyId, rule.negEffects, _callingFunctionArgs);
            } else {
                _doEffects(rule, _policyId, rule.posEffects, _callingFunctionArgs);
            }
        }
    }

    /**
     * @dev evaluates an individual rules condition(s)
     * @param _policyId Policy id being evaluated.
     * @param _rule the rule structure containing the instruction set, with placeholders, to execute
     * @param _callingFunctionArgs the values to replace the placeholders in the instruction set with.
     * @return response the result of the rule condition evaluation
     */
    function _evaluateIndividualRule(
        Rule storage _rule,
        uint256 _policyId,
        bytes calldata _callingFunctionArgs
    ) internal returns (bool response) {
        (bytes[] memory ruleArgs, Placeholder[] memory placeholders) = _buildArguments(_rule, _policyId, _callingFunctionArgs, false);
        response = _run(_rule.instructionSet, placeholders, _policyId, ruleArgs);
    }

    /**
     * @dev Constructs the arguments required for building the rule's place holders.
     * @param _rule The storage reference to the Rule struct containing the rule's details.
     * @param _policyId The unique identifier of the policy associated with the rule.
     * @param _callingFunctionArgs The calldata containing the arguments for the calling function.
     * @param _effect A boolean indicating whether the rule has an effect or not.
     * @return A tuple containing:
     *         - An array of bytes representing the constructed arguments.
     *         - An array of Placeholder structs used for argument substitution.
     */
    function _buildArguments(
        Rule storage _rule,
        uint256 _policyId,
        bytes calldata _callingFunctionArgs,
        bool _effect
    ) internal returns (bytes[] memory, Placeholder[] memory) {
        Placeholder[] memory placeHolders;
        if (_effect) {
            placeHolders = _rule.effectPlaceHolders;
        } else {
            placeHolders = _rule.placeHolders;
        }
        bytes[] memory retVals = new bytes[](placeHolders.length);
        // Data validation will alway ensure ruleCount will be less than MAX_LOOP
        ForeignCallEncodedIndex[] memory metadata = new ForeignCallEncodedIndex[](placeHolders.length);
        for (uint256 placeholderIndex = 0; placeholderIndex < placeHolders.length; placeholderIndex++) {
            // Determine if the placeholder represents the return value of a foreign call or a function parameter from the calling function
            Placeholder memory placeholder = placeHolders[placeholderIndex];

            // Extract flags using helper function
            (bool isTrackerValue, bool isForeignCall, uint8 globalVarType) = _extractFlags(placeholder);

            if (globalVarType != GLOBAL_NONE) {
                metadata[placeholderIndex].eType = EncodedIndexType.GLOBAL_VAR;
                metadata[placeholderIndex].index = globalVarType;
                (retVals[placeholderIndex], placeHolders[placeholderIndex].pType) = _handleGlobalVar(globalVarType);
            } else if (isForeignCall) {
                metadata[placeholderIndex].eType = EncodedIndexType.FOREIGN_CALL;
                metadata[placeholderIndex].index = placeholder.typeSpecificIndex;
                (retVals[placeholderIndex], placeHolders[placeholderIndex].pType) = _handleForeignCall(
                    _policyId,
                    _callingFunctionArgs,
                    placeholder.typeSpecificIndex,
                    retVals,
                    metadata
                );
            } else if (isTrackerValue) {
                metadata[placeholderIndex].eType = EncodedIndexType.TRACKER;
                metadata[placeholderIndex].index = placeholder.typeSpecificIndex;
                retVals[placeholderIndex] = _handleTrackerValue(_policyId, placeholder);
            } else {
                metadata[placeholderIndex].eType = EncodedIndexType.ENCODED_VALUES;
                metadata[placeholderIndex].index = 0;
                retVals[placeholderIndex] = _handleRegularParameter(_callingFunctionArgs, placeholder);
            }
        }
        return (retVals, placeHolders);
    }

    /**
     * @dev Internal function to decode the arguments and do the comparisons.
     * @param _prog An array of uint256 representing the program to be executed.
     * @param _placeHolders An array of Placeholder structs used within the program.
     * @param _policyId The ID of the policy associated with the program execution.
     * @param _arguments An array of bytes containing additional arguments for the program.
     * @return A boolean indicating the result of the program execution.
     */
    function _run(
        uint256[] memory _prog,
        Placeholder[] memory _placeHolders,
        uint256 _policyId,
        bytes[] memory _arguments
    ) internal returns (bool) {
        uint256[90] memory mem;
        uint256 idx = 0;
        uint256 opi = 0;

        while (idx < _prog.length) {
            uint256 v = 0;
            LogicalOp op = LogicalOp(_prog[idx]);

            if (op == LogicalOp.PLH || op == LogicalOp.PLHM) {
                // Placeholder format is: get the index of the argument in the array. For example, PLH 0 is the first argument in the arguments array and its type and value
                uint256 pli;
                bytes memory value;
                ParamTypes typ;
                if (op == LogicalOp.PLHM) {
                    uint key = mem[_prog[idx + 2]];
                    (value, typ) = _getMappedTrackerValue(_policyId, _prog[idx + 1], key);
                    idx += 3;
                } else {
                    pli = _prog[idx + 1];
                    value = _arguments[pli];
                    typ = _placeHolders[pli].pType;
                    idx += 2;
                }
                if (typ == ParamTypes.UINT || typ == ParamTypes.ADDR || typ == ParamTypes.BOOL) {
                    v = abi.decode(value, (uint256));
                } else if (typ == ParamTypes.STR || typ == ParamTypes.BYTES) {
                    // Convert string to uint256 for direct comparison using == and != operations
                    v = uint256(keccak256(value));
                } else if (typ == ParamTypes.STATIC_TYPE_ARRAY || typ == ParamTypes.DYNAMIC_TYPE_ARRAY) {
                    // length of array for direct comparison using == and != operations
                    v = abi.decode(value, (uint256));
                }
            } else if (op == LogicalOp.TRU) {
                // update the tracker value
                // If the Tracker Type == Place Holder, pull the data from the place holder, otherwise, pull it from Memory
                TrackerTypes tt = TrackerTypes(_prog[idx + 3]);
                if (tt == TrackerTypes.MEMORY) {
                    _updateTrackerValue(_policyId, _prog[idx + 1], mem[_prog[idx + 2]]);
                } else {
                    _updateTrackerValue(_policyId, _prog[idx + 1], _arguments[_prog[idx + 2]]);
                }
                idx += 4;
            } else if (op == LogicalOp.TRUM) {
                // update the tracker value
                /** 
                idx = TRUM opcode
                idx + 1 = tracker index
                idx + 2 = memory/argument index
                idx + 3 = index tracker key
                idx + 4 = type (memory vs argument)
                */
                // If the Tracker Type == Place Holder, pull the data from the place holder, otherwise, pull it from Memory
                TrackerTypes tt = TrackerTypes(_prog[idx + 4]);
                uint256 key = mem[_prog[idx + 3]];
                tt == TrackerTypes.MEMORY
                    ? _updateMappedTrackerValue(_policyId, _prog[idx + 1], mem[_prog[idx + 2]], key)
                    : _updateMappedTrackerValue(_policyId, _prog[idx + 1], _arguments[_prog[idx + 2]], key);
                idx += 5;
            } else if (op == LogicalOp.NUM) {
                v = _prog[idx + 1];
                idx += 2;
            } else if (op == LogicalOp.ADD) {
                v = mem[_prog[idx + 1]] + mem[_prog[idx + 2]];
                idx += 3;
            } else if (op == LogicalOp.SUB) {
                v = mem[_prog[idx + 1]] - mem[_prog[idx + 2]];
                idx += 3;
            } else if (op == LogicalOp.MUL) {
                v = mem[_prog[idx + 1]] * mem[_prog[idx + 2]];
                idx += 3;
            } else if (op == LogicalOp.DIV) {
                v = mem[_prog[idx + 1]] / mem[_prog[idx + 2]];
                idx += 3;
            } else if (op == LogicalOp.ASSIGN) {
                v = mem[_prog[idx + 2]];
                idx += 3;
            } else if (op == LogicalOp.LT) {
                v = ProcessorLib._boolToUint(mem[_prog[idx + 1]] < mem[_prog[idx + 2]]);
                idx += 3;
            } else if (op == LogicalOp.GT) {
                v = ProcessorLib._boolToUint(mem[_prog[idx + 1]] > mem[_prog[idx + 2]]);
                idx += 3;
            } else if (op == LogicalOp.EQ) {
                v = ProcessorLib._boolToUint(mem[_prog[idx + 1]] == mem[_prog[idx + 2]]);
                idx += 3;
            } else if (op == LogicalOp.NOTEQ) {
                v = ProcessorLib._boolToUint(mem[_prog[idx + 1]] != mem[_prog[idx + 2]]);
                idx += 3;
            } else if (op == LogicalOp.GTEQL) {
                v = ProcessorLib._boolToUint(mem[_prog[idx + 1]] >= mem[_prog[idx + 2]]);
                idx += 3;
            } else if (op == LogicalOp.LTEQL) {
                v = ProcessorLib._boolToUint(mem[_prog[idx + 1]] <= mem[_prog[idx + 2]]);
                idx += 3;
            } else if (op == LogicalOp.AND) {
                v = ProcessorLib._boolToUint(
                    ProcessorLib._uintToBool(mem[_prog[idx + 1]]) && ProcessorLib._uintToBool(mem[_prog[idx + 2]])
                );
                idx += 3;
            } else if (op == LogicalOp.OR) {
                v = ProcessorLib._boolToUint(
                    ProcessorLib._uintToBool(mem[_prog[idx + 1]]) || ProcessorLib._uintToBool(mem[_prog[idx + 2]])
                );
                idx += 3;
            } else if (op == LogicalOp.NOT) {
                v = ProcessorLib._boolToUint(!ProcessorLib._uintToBool(mem[_prog[idx + 1]]));
                idx += 2;
            } else {
                revert(INVALID_INSTRUCTION);
            }
            mem[opi] = v;
            opi += 1;
        }
        return ProcessorLib._uintToBool(mem[opi - 1]);
    }

    /**
     * @dev This function updates the tracker value with the information provided
     * @param _policyId Policy id being evaluated.
     * @param _trackerId ID of the tracker to update.
     * @param _trackerValue Value to update within the tracker
     */
    function _updateTrackerValue(uint256 _policyId, uint256 _trackerId, uint256 _trackerValue) internal {
        // retrieve the tracker
        Trackers storage trk = lib._getTrackerStorage().trackers[_policyId][_trackerId];
        if (trk.pType == ParamTypes.UINT || trk.pType == ParamTypes.ADDR || trk.pType == ParamTypes.BOOL) {
            trk.trackerValue = abi.encode(_trackerValue);
        } else if (trk.pType == ParamTypes.BYTES || trk.pType == ParamTypes.STR) {
            trk.trackerValue = ProcessorLib._uintToBytes(_trackerValue);
        } else {
            revert(INVALID_TYPE);
        }
    }

    /**
     * @dev Internal function to update the value of a tracker associated with a specific policy.
     * @param _policyId The ID of the policy to which the tracker belongs.
     * @param _trackerId The ID of the tracker whose value is being updated.
     * @param _trackerValue The new value to be assigned to the tracker, encoded as bytes.
     */
    function _updateTrackerValue(uint256 _policyId, uint256 _trackerId, bytes memory _trackerValue) internal {
        // retrieve the tracker
        Trackers storage trk = lib._getTrackerStorage().trackers[_policyId][_trackerId];
        trk.trackerValue = _trackerValue;
    }

    /**
     * @dev This function updates the tracker value with the information provided for a mapped tracker
     * @param _policyId Policy id being evaluated.
     * @param _trackerId ID of the tracker to update.
     * @param _trackerValue Value to update within the tracker
     */
    function _updateMappedTrackerValue(uint256 _policyId, uint256 _trackerId, uint256 _trackerValue, uint256 _mappedTrackerKey) internal {
        // retrieve the tracker
        Trackers storage trk = lib._getTrackerStorage().trackers[_policyId][_trackerId];
        // store the updated value to the tracker mapping
        bytes memory encodedValue;
        bytes memory encodedKey;

        // encode uint key to type
        if (trk.trackerKeyType == ParamTypes.UINT || trk.trackerKeyType == ParamTypes.ADDR || trk.trackerKeyType == ParamTypes.BOOL) {
            encodedKey = abi.encode(_mappedTrackerKey);
        } else if (trk.trackerKeyType == ParamTypes.BYTES || trk.trackerKeyType == ParamTypes.STR) {
            encodedKey = ProcessorLib._uintToBytes(_mappedTrackerKey);
        }

        if (trk.pType == ParamTypes.UINT || trk.pType == ParamTypes.ADDR || trk.pType == ParamTypes.BOOL) {
            encodedValue = abi.encode(_trackerValue);
        } else if (trk.pType == ParamTypes.BYTES || trk.pType == ParamTypes.STR) {
            encodedValue = ProcessorLib._uintToBytes(_trackerValue);
        }
        // re encode as bytes to mapping
        lib._getTrackerStorage().mappedTrackerValues[_policyId][_trackerId][encodedKey] = encodedValue;
    }

    function _getMappedTrackerValue(
        uint256 _policyId,
        uint256 _trackerId,
        uint256 _mappedTrackerKey
    ) internal view returns (bytes memory, ParamTypes) {
        assert(lib._getTrackerStorage().trackers[_policyId][_trackerId].mapped);
        ParamTypes keyType = lib._getTrackerStorage().trackers[_policyId][_trackerId].pType;
        bytes memory value = lib._getTrackerStorage().mappedTrackerValues[_policyId][_trackerId][abi.encode(_mappedTrackerKey)];
        if (value.length == 0) {
            return (abi.encode(0), keyType);
        }
        return (value, keyType);
    }

    /**
     * @dev Internal function to update the value of a mapped tracker associated with a specific policy.
     * @param _policyId The ID of the policy to which the tracker belongs.
     * @param _trackerId The ID of the tracker whose value is being updated.
     * @param _trackerValue The new value to be assigned to the tracker, encoded as bytes.
     */
    function _updateMappedTrackerValue(
        uint256 _policyId,
        uint256 _trackerId,
        bytes memory _trackerValue,
        uint256 _mappedTrackerKey
    ) internal {
        // retrieve the tracker
        Trackers storage trk = lib._getTrackerStorage().trackers[_policyId][_trackerId];
        bytes memory encodedKey = "";
        // encode uint key to type
        if (trk.trackerKeyType == ParamTypes.UINT || trk.trackerKeyType == ParamTypes.ADDR || trk.trackerKeyType == ParamTypes.BOOL) {
            encodedKey = abi.encode(_mappedTrackerKey);
        } else if (trk.trackerKeyType == ParamTypes.BYTES || trk.trackerKeyType == ParamTypes.STR) {
            encodedKey = ProcessorLib._uintToBytes(_mappedTrackerKey);
        } else {
            revert(INVALID_TRACKER_KEY_TYPE);
        }
        // store the tracker  value to the tracker mapping
        lib._getTrackerStorage().mappedTrackerValues[_policyId][_trackerId][encodedKey] = _trackerValue;
    }

    /**
     * @notice Loads applicable rules for a given calling function.
     * @param _ruleData The mapping of rule IDs to rule storage sets.
     * @param _policy The policy structure containing the rules.
     * @param _callingFunction The function signature to match rules against.
     * @return An array of applicable rule IDs.
     */
    function _loadApplicableRules(
        mapping(uint256 ruleId => RuleStorageSet) storage _ruleData,
        Policy storage _policy,
        bytes4 _callingFunction
    ) internal view returns (uint256[] memory) {
        // Load the applicable rule data from storage
        uint256[] memory applicableRules = new uint256[](_policy.callingFunctionsToRuleIds[_callingFunction].length);
        // Load the calling function data from storage
        uint256[] storage storagePointer = _policy.callingFunctionsToRuleIds[_callingFunction];
        for (uint256 i = 0; i < applicableRules.length; i++) {
            if (_ruleData[storagePointer[i]].set) {
                applicableRules[i] = storagePointer[i];
            }
        }
        return applicableRules;
    }

    /**
     * @notice Processes foreign calls within the rules engine
     * @dev Internal helper function that delegates to evaluateForeignCalls and extracts the return value and type
     *      This function is used during rules processing to execute external contract calls
     *      and retrieve their results for rule evaluation
     * @param _policyId The unique identifier of the policy associated with the foreign call
     * @param _callingFunctionArgs Arguments from the original function call, passed to the foreign call as needed
     * @param typeSpecificIndex Index referencing the specific foreign call configuration to execute
     * @param retVals Array containing previously computed return values that might be used as inputs for this call
     * @return The encoded return data from the foreign call
     * @return The parameter type of the foreign call's return value
     */
    function _handleForeignCall(
        uint256 _policyId,
        bytes calldata _callingFunctionArgs,
        uint256 typeSpecificIndex,
        bytes[] memory retVals,
        ForeignCallEncodedIndex[] memory metadata
    ) internal returns (bytes memory, ParamTypes) {
        ForeignCallReturnValue memory retVal = evaluateForeignCalls(_policyId, _callingFunctionArgs, typeSpecificIndex, retVals, metadata);
        return (retVal.value, retVal.pType);
    }

    /**
     * @notice Handles global variables in the rules engine
     * @dev Internal function that processes global variable types and returns their encoded values with corresponding parameter types
     * @dev Used to access blockchain context variables like msg.sender, block.timestamp, etc. during rule evaluation
     * @param globalVarType An uint8 identifier representing which global variable to retrieve
     *                     - GLOBAL_MSG_SENDER (1): The sender of the current call
     *                     - GLOBAL_BLOCK_TIMESTAMP (2): Current block timestamp
     *                     - GLOBAL_MSG_DATA (3): Complete calldata
     *                     - GLOBAL_BLOCK_NUMBER (4): Current block number
     *                     - GLOBAL_TX_ORIGIN (5): Original transaction sender
     * @return bytes Encoded value of the requested global variable
     * @return Parameter type enum value corresponding to the global variable
     */
    function _handleGlobalVar(uint256 globalVarType) internal view returns (bytes memory, ParamTypes) {
        if (globalVarType == GLOBAL_MSG_SENDER) {
            return (abi.encode(msg.sender), ParamTypes.ADDR);
        } else if (globalVarType == GLOBAL_BLOCK_TIMESTAMP) {
            return (abi.encode(block.timestamp), ParamTypes.UINT);
        } else if (globalVarType == GLOBAL_MSG_DATA) {
            // Important: Return msg.data properly formatted for dynamic bytes parameters
            // We need to create a properly encoded bytes value with length prefix
            bytes memory msgData = msg.data;
            bytes memory encodedData = new bytes(msg.data.length + 32);

            // Store length in first 32 bytes
            assembly {
                mstore(add(encodedData, 32), mload(msgData))
            }

            // Copy the actual data
            for (uint256 i = 0; i < msg.data.length; i++) {
                encodedData[i + 32] = msg.data[i];
            }

            return (encodedData, ParamTypes.BYTES);
        } else if (globalVarType == GLOBAL_BLOCK_NUMBER) {
            return (abi.encode(block.number), ParamTypes.UINT);
        } else if (globalVarType == GLOBAL_TX_ORIGIN) {
            return (abi.encode(tx.origin), ParamTypes.ADDR);
        } else {
            revert(GLB_VAR_INV);
        }
    }

    /**
     * @notice Retrieves tracker values from storage based on policy ID and placeholder information
     * @dev Internal function that fetches either a regular tracker value or a mapped tracker value
     *      depending on the tracker's configuration. For mapped trackers, it uses the placeholder's
     *      mappedTrackerKey to fetch the specific value from the mapping.
     * @param _policyId The unique identifier of the policy containing the tracker
     * @param placeholder A Placeholder struct containing metadata about the tracker:
     *                    - typeSpecificIndex: The ID of the tracker within the policy
     *                    - mappedTrackerKey: The key to use for mapped trackers (ignored for regular trackers)
     * @return bytes The encoded value of the requested tracker
     */
    function _handleTrackerValue(uint256 _policyId, Placeholder memory placeholder) internal view returns (bytes memory) {
        return lib._getTrackerStorage().trackers[_policyId][placeholder.typeSpecificIndex].trackerValue;
    }

    /**
     * @notice Extracts function parameters from calldata based on placeholder type information
     * @dev Internal pure function that handles different parameter types and retrieves their values from calldata
     *      - For dynamic types (strings, bytes): calls _getDynamicVariableFromCalldata to follow offsets
     *      - For arrays: extracts the length from the offset indicated in calldata
     *      - For value types: extracts 32 bytes directly from the specified position
     * @param _callingFunctionArgs The raw calldata containing encoded function arguments
     * @param placeholder A Placeholder struct containing:
     *                    - pType: Parameter type enum indicating how to decode the data
     *                    - typeSpecificIndex: Position in calldata to read from (slot index for value types)
     * @return bytes The extracted parameter value as bytes (must be decoded according to pType)
     */
    function _handleRegularParameter(
        bytes calldata _callingFunctionArgs,
        Placeholder memory placeholder
    ) internal pure returns (bytes memory) {
        if (placeholder.pType == ParamTypes.STR || placeholder.pType == ParamTypes.BYTES) {
            return _getDynamicVariableFromCalldata(_callingFunctionArgs, placeholder.typeSpecificIndex);
        } else if (placeholder.pType == ParamTypes.STATIC_TYPE_ARRAY || placeholder.pType == ParamTypes.DYNAMIC_TYPE_ARRAY) {
            bytes32 value = bytes32(_callingFunctionArgs[placeholder.typeSpecificIndex * 32:(placeholder.typeSpecificIndex + 1) * 32]);
            return abi.encode(uint256(bytes32(_callingFunctionArgs[uint(value):uint(value) + 32])));
        } else {
            return _callingFunctionArgs[placeholder.typeSpecificIndex * 32:(placeholder.typeSpecificIndex + 1) * 32];
        }
    }

    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Effect Execution Functions
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @dev Internal function to process the effects of a rule.
     * @param _rule The rule being processed, stored in the contract's storage.
     * @param _policyId The ID of the policy associated with the rule.
     * @param _effects An array of effects to be applied as part of the rule execution.
     * @param _callingFunctionArgs Encoded calldata containing arguments for the calling function.
     */
    function _doEffects(Rule storage _rule, uint256 _policyId, Effect[] memory _effects, bytes calldata _callingFunctionArgs) internal {
        // Load the Effect data from storage
        // Data validation will always ensure _effects.length will be less than MAX_LOOP
        for (uint256 i = 0; i < _effects.length; i++) {
            Effect memory effect = _effects[i];
            if (effect.valid) {
                if (effect.effectType == EffectTypes.REVERT) {
                    _doRevert(effect.errorMessage);
                } else if (effect.effectType == EffectTypes.EVENT) {
                    _buildEvent(_rule, _effects[i].dynamicParam, _policyId, _effects[i].text, _effects[i], _callingFunctionArgs);
                } else {
                    _evaluateExpression(_rule, _policyId, _callingFunctionArgs, effect.instructionSet);
                }
            }
        }
    }

    /**
     * @dev Define event to be fired
     * @param _rule the rule struct event is associated to
     * @param _isDynamicParam static or dynamic event parameters
     * @param _policyId policy Id
     * @param _message Event Message String
     * @param _effectStruct effect struct
     * @param _callingFunctionArgs calling function arguments
     */
    function _buildEvent(
        Rule storage _rule,
        bool _isDynamicParam,
        uint256 _policyId,
        bytes32 _message,
        Effect memory _effectStruct,
        bytes calldata _callingFunctionArgs
    ) internal {
        // determine if we need to dynamically build event key
        if (_isDynamicParam) {
            // fire event by param type based on return value
            _fireDynamicEvent(_rule, _policyId, _message, _callingFunctionArgs);
        } else {
            _fireEvent(_policyId, _message, _effectStruct);
        }
    }

    /**
     * @dev Fire dynamic Event
     * @param _rule the rule struct event is associated to
     * @param _policyId policy Id
     * @param _message Event Message String
     * @param _callingFunctionArgs calling function arguments
     */
    function _fireDynamicEvent(Rule storage _rule, uint256 _policyId, bytes32 _message, bytes calldata _callingFunctionArgs) internal {
        // Build the effect arguments struct for event parameters:
        (bytes[] memory effectArguments, Placeholder[] memory placeholders) = _buildArguments(_rule, _policyId, _callingFunctionArgs, true);
        // Data validation will always ensure effectArguments.length will be less than MAX_LOOP
        for (uint256 i = 0; i < effectArguments.length; i++) {
            // loop through parameter types and set eventParam
            if (placeholders[i].pType == ParamTypes.UINT) {
                uint256 uintParam = abi.decode(effectArguments[i], (uint));
                emit RulesEngineEvent(_policyId, _message, uintParam);
            } else if (placeholders[i].pType == ParamTypes.ADDR) {
                address addrParam = abi.decode(effectArguments[i], (address));
                emit RulesEngineEvent(_policyId, _message, addrParam);
            } else if (placeholders[i].pType == ParamTypes.BOOL) {
                bool boolParam = abi.decode(effectArguments[i], (bool));
                emit RulesEngineEvent(_policyId, _message, boolParam);
            } else if (placeholders[i].pType == ParamTypes.STR) {
                string memory textParam = abi.decode(effectArguments[i], (string));
                emit RulesEngineEvent(_policyId, _message, textParam);
            } else if (placeholders[i].pType == ParamTypes.BYTES) {
                bytes32 bytesParam = abi.decode(effectArguments[i], (bytes32));
                emit RulesEngineEvent(_policyId, _message, bytesParam);
            }
        }
    }

    /**
     * @dev Internal function to trigger an event based on the provided policy ID, message, and effect structure.
     * @param _policyId The unique identifier of the policy associated with the event.
     * @param _message A bytes32 message that provides context or details about the event.
     * @param _effectStruct A struct containing the effect data to be processed during the event.
     */
    function _fireEvent(uint256 _policyId, bytes32 _message, Effect memory _effectStruct) internal {
        if (_effectStruct.pType == ParamTypes.UINT) {
            uint256 uintParam = abi.decode(_effectStruct.param, (uint));
            emit RulesEngineEvent(_policyId, _message, uintParam);
        } else if (_effectStruct.pType == ParamTypes.ADDR) {
            address addrParam = abi.decode(_effectStruct.param, (address));
            emit RulesEngineEvent(_policyId, _message, addrParam);
        } else if (_effectStruct.pType == ParamTypes.BOOL) {
            bool boolParam = abi.decode(_effectStruct.param, (bool));
            emit RulesEngineEvent(_policyId, _message, boolParam);
        } else if (_effectStruct.pType == ParamTypes.STR) {
            string memory textParam = abi.decode(_effectStruct.param, (string));
            emit RulesEngineEvent(_policyId, _message, textParam);
        } else if (_effectStruct.pType == ParamTypes.BYTES) {
            bytes32 bytesParam = abi.decode(_effectStruct.param, (bytes32));
            emit RulesEngineEvent(_policyId, _message, bytesParam);
        }
    }

    /**
     * @dev Evaluate an effect expression
     * @param _rule the rule structure containing the instruction set, with placeholders, to execute
     * @param _policyId the policy id
     * @param _callingFunctionArgs arguments of the calling function
     * @param _instructionSet instruction set
     */
    function _evaluateExpression(
        Rule storage _rule,
        uint256 _policyId,
        bytes calldata _callingFunctionArgs,
        uint256[] memory _instructionSet
    ) internal {
        (bytes[] memory effectArguments, Placeholder[] memory placeholders) = _buildArguments(_rule, _policyId, _callingFunctionArgs, true);
        if (_instructionSet.length > 1) {
            _run(_instructionSet, placeholders, _policyId, effectArguments);
        }
    }

    /**
     * @dev Internal pure function to revert the transaction with a custom error message.
     * @param _message The custom error message to include in the revert.
     */
    function _doRevert(string memory _message) internal pure {
        revert(_message);
    }

    /**
     * @notice Extracts a dynamic variable from the provided calldata at the specified index.
     * @dev This function is a pure function and does not modify state.
     * @param _data The calldata containing the dynamic variables.
     * @param _index The index of the dynamic variable to extract.
     * @return The extracted dynamic variable as a bytes array.
     */
    function _getDynamicVariableFromCalldata(bytes calldata _data, uint256 _index) internal pure returns (bytes memory) {
        // Get offset from parameter position, using index * 32 to get the correct position in the calldata
        uint256 offset = uint256(bytes32(_data[_index * 32:(_index + 1) * 32]));
        // Get length from the offset position, using offset + 32 to get the correct position in the calldata
        uint256 length = uint256(bytes32(_data[offset:offset + 32]));
        // Allocate memory for result: 32 (offset) + 32 (length) + data length
        bytes memory result = new bytes(64 + ((length + 31) / 32) * 32);
        assembly {
            // Store offset to length (0x20)
            mstore(add(result, 32), 0x20)

            // Store length
            mstore(add(result, 64), length)

            // Copy actual data
            calldatacopy(
                add(result, 96), // destination (after offset+length)
                add(add(_data.offset, offset), 32), // source (after length in calldata)
                mul(div(add(length, 31), 32), 32) // length of data
            )
        }
        return result;
    }

    /**
     * @notice Retrieves a portion of dynamic value array data from the provided inputs.
     * @dev This function extracts a segment of dynamic data based on the specified length and offset.
     * @param _data The calldata input containing the original data.
     * @param _dynamicData The memory input containing the dynamic data to process.
     * @param _length The total length of the dynamic data array.
     * @param _lengthToAppend The length of data to append to the result.
     * @param _offset The starting position in the dynamic data array to begin extraction.
     * @return A tuple containing:
     *         - A bytes memory object representing the extracted data.
     *         - A uint256 value indicating the updated offset after extraction.
     */
    function _getDynamicValueArrayData(
        bytes calldata _data,
        bytes memory _dynamicData,
        uint _length,
        uint _lengthToAppend,
        uint256 _offset
    ) internal pure returns (bytes memory, uint256) {
        bytes memory arrayData;

        _lengthToAppend += (_length * 0x20);
        uint256 baseDynamicOffset = 32 + ((_length - 1) * 32);
        for (uint256 j = 1; j <= _length; j++) {
            // Add current offset to dynamic data
            _dynamicData = bytes.concat(_dynamicData, bytes32(baseDynamicOffset));

            uint getValueOffsetValue = _offset + (j * 32);
            uint256 dynamicValueOffset = uint256(bytes32(_data[getValueOffsetValue:getValueOffsetValue + 32])) + 32;

            // Get length of current string
            uint256 dynamicValueLength = uint256(bytes32(_data[_offset + dynamicValueOffset:_offset + dynamicValueOffset + 32]));

            // Calculate padded length for this string's data
            uint256 paddedLength = 32 + ((dynamicValueLength + 31) / 32) * 32;

            // Get the string data (including length and value)
            bytes memory dynamicValue = _data[_offset + dynamicValueOffset:_offset + dynamicValueOffset + paddedLength];

            // Next offset should point after current string's data
            baseDynamicOffset += paddedLength;

            _lengthToAppend += paddedLength;
            arrayData = bytes.concat(arrayData, dynamicValue);
        }

        _dynamicData = bytes.concat(_dynamicData, arrayData);

        return (_dynamicData, _lengthToAppend);
    }
}
