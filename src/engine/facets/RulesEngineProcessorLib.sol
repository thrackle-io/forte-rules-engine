// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;
import "src/engine/facets/FacetCommonImports.sol";
library RulesEngineProcessorLib {
    /**
     * @dev Constructs the arguments required for building the rule's place holders.
     * @param rule The storage reference to the Rule struct containing the rule's details.
     * @param _policyId The unique identifier of the policy associated with the rule.
     * @param functionSignatureArgs The calldata containing the arguments for the function signature.
     * @param effect A boolean indicating whether the rule has an effect or not.
     * @return A tuple containing:
     *         - An array of bytes representing the constructed arguments.
     *         - An array of Placeholder structs used for argument substitution.
     */
    function _buildArguments(Rule memory rule, uint256 _policyId, bytes calldata functionSignatureArgs, bool effect) internal returns (bytes[] memory, Placeholder[] memory) {
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
                    ForeignCallReturnValue memory retVal = evaluateForeignCalls(_policyId, functionSignatureArgs, placeholder.typeSpecificIndex);
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
                    retVals[placeholderIndex] = getDynamicVariableFromCalldata(functionSignatureArgs, placeholder.typeSpecificIndex);
                } else if (placeholder.pType == PT.STATIC_TYPE_ARRAY || placeholder.pType == PT.DYNAMIC_TYPE_ARRAY) {
                    // if the placeholder represents an array, determine the length and set lenth as placeholder value in ruleArgs 
                    bytes32 value = bytes32(functionSignatureArgs[placeholder.typeSpecificIndex * 32: (placeholder.typeSpecificIndex + 1) * 32]);
                    retVals[placeholderIndex] = abi.encode(uint256(bytes32(functionSignatureArgs[uint(value):uint(value) + 32])));
                } else {
                    // since this is not a dynamic value, we can safely assume that it is only 1 word, therefore we multiply
                    // the typeSpecificIndex by 32 to get the correct position in the functionSignatureArgs array
                    // and then add 1 and multiply by 32 to get the correct 32 byte word to get the value
                    retVals[placeholderIndex] = functionSignatureArgs[
                        placeholder.typeSpecificIndex * 32: (placeholder.typeSpecificIndex + 1) * 32
                    ];
                }
            }
        }
        return (retVals, placeHolders);
    }

    /**
     * @notice Evaluates foreign calls within the rules engine processor.
     * @dev This function processes and evaluates calls to external contracts or systems
     *      as part of the rules engine's logic. Ensure that the necessary validations
     *      and security checks are in place when interacting with foreign calls.
     * @param _policyId Id of the policy.
     * @param functionSignatureArgs representation of the function signature arguments
     * @param foreignCallIndex Index of the foreign call.
     * @return returnValue The output of the foreign call.
     */
    function evaluateForeignCalls(
        uint256 _policyId, 
        bytes calldata functionSignatureArgs, 
        uint256 foreignCallIndex
    ) internal returns(ForeignCallReturnValue memory returnValue) {
        // Load the Foreign Call data from storage
        ForeignCall memory foreignCall = lib.getForeignCallStorage().foreignCalls[_policyId][foreignCallIndex];
        if (foreignCall.set) {
            return evaluateForeignCallForRule(foreignCall, functionSignatureArgs);
        }
    }


    /**
     * @dev encodes the arguments and places a foreign call, returning the calls return value as long as it is successful
     * @param fc the Foreign Call structure
     * @param functionArguments the arguments of the rules calling function (to be passed to the foreign call as needed)
     * @return retVal the foreign calls return value
     */
    function evaluateForeignCallForRule(ForeignCall memory fc, bytes calldata functionArguments) internal returns (ForeignCallReturnValue memory retVal) {
        // First, calculate total size needed and positions of dynamic data
        bytes memory encodedCall = bytes.concat(bytes4(fc.signature));
        bytes memory dynamicData;

        uint256 lengthToAppend = 0;
        // First pass: calculate sizes
        for(uint256 i = 0; i < fc.parameterTypes.length; i++) {
            PT argType = fc.parameterTypes[i];
            uint256 typeSpecificIndex = fc.typeSpecificIndices[i];
            bytes32 value = bytes32(functionArguments[typeSpecificIndex * 32: (typeSpecificIndex + 1) * 32]);
            
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
                (dynamicData, lengthToAppend) = getDynamicValueArrayData(functionArguments, dynamicData, length, lengthToAppend, uint(value));
            }
            else {
                encodedCall = bytes.concat(encodedCall, value);
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
    function getDynamicValueArrayData(bytes calldata data, bytes memory dynamicData, uint length, uint lengthToAppend, uint256 offset) internal pure returns (bytes memory, uint256) {
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

    /**
     * @notice Extracts a dynamic variable from the provided calldata at the specified index.
     * @dev This function is a pure function and does not modify state.
     * @param data The calldata containing the dynamic variables.
     * @param index The index of the dynamic variable to extract.
     * @return retVal The extracted dynamic variable as a bytes array.
     */
    function getDynamicVariableFromCalldata(bytes calldata data, uint256 index) internal pure returns (bytes memory retVal) {
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
                    v = uint256(bool2ui((abi.decode(arguments[pli], (bool))))); idx += 2;
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
            else if (op == LC.LT) { v = bool2ui(mem[prog[idx+1]] < mem[prog[idx+2]]); idx += 3; }
            else if (op == LC.GT) { v = bool2ui(mem[prog[idx+1]] > mem[prog[idx+2]]); idx += 3; }
            else if (op == LC.EQ) { v = bool2ui(mem[prog[idx+1]] == mem[prog[idx+2]]); idx += 3; }
            else if (op == LC.GTEQL) { v = bool2ui(mem[prog[idx+1]] >= mem[prog[idx+2]]); idx += 3; }
            else if (op == LC.LTEQL) { v = bool2ui(mem[prog[idx+1]] <= mem[prog[idx+2]]); idx += 3; }
            else if (op == LC.AND) { v = bool2ui(ui2bool(mem[prog[idx+1]]) && ui2bool(mem[prog[idx+2]])); idx += 3; }
            else if (op == LC.OR ) { v = bool2ui(ui2bool(mem[prog[idx+1]]) || ui2bool(mem[prog[idx+2]])); idx += 3; }
            else if (op == LC.NOT) { v = bool2ui(! ui2bool(mem[prog[idx+1]])); idx += 2; }
            else { revert("Illegal instruction"); }
            mem[opi] = v;
            opi += 1;
        }
        return ui2bool(mem[opi - 1]);
    }
//-------------------------------------------------------------------------------------------------------------------------------------------------------
// Utility Functions
//-------------------------------------------------------------------------------------------------------------------------------------------------------
    /**
     * @dev converts a uint256 to a bool
     * @param x the uint256 to convert
     */
    function ui2bool(uint256 x) internal pure returns (bool ans) {
        return x == 1;
    }

    /**
     * @dev converts a bool to an uint256
     * @param x the bool to convert
     */
    function bool2ui(bool x) internal pure returns (uint256 ans) {
        return x ? 1 : 0;
    }


    /**
     * @dev converts a uint256 to an address
     * @param x the uint256 to convert
     */
    function ui2addr(uint256 x) internal pure returns (address ans) {
        return address(uint160(x));
    }

    /**
     * @dev converts a uint256 to a bytes
     * @param x the uint256 to convert
     */
    function ui2bytes(uint256 x) internal pure returns (bytes memory ans) {
        return abi.encode(x);
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
            trk.trackerValue = abi.encode(ui2addr(_trackerValue));
        } else if(trk.pType == PT.BOOL) {
            trk.trackerValue = abi.encode(ui2bool(_trackerValue));
        } else if(trk.pType == PT.BYTES) {
            trk.trackerValue = ui2bytes(_trackerValue);
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

}