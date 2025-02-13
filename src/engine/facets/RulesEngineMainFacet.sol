// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetCommonImports.sol";
import "forge-std/console.sol";

contract RulesEngineMainFacet is FacetCommonImports{
    /**
     * @dev Initializer params
     * @param _owner initial owner of the diamond
     */
    function initialize(address _owner) external {
        InitializedS storage init = lib.initializedStorage();
        if(init.initialized) revert ("AlreadyInitialized");
        callAnotherFacet(0xf2fde38b, abi.encodeWithSignature("transferOwnership(address)", _owner));
    }

    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    // Rule Evaluation Functions
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @dev evaluates the conditions associated with all applicable rules and returns the result
     * @dev PEP for policy checks
     * @param contractAddress the address of the rules-enabled contract, used to pull the applicable rules
     * @param arguments function arguments. Should included the function signature and the arguments to be passed to the function
     * TODO: refine the parameters to this function. contractAddress is not necessary as it's the message caller
     */
    function checkPolicies(address contractAddress, bytes calldata arguments) public returns (uint256 retVal) {  
        retVal = 1; 
        // Load the function signature data from storage
        PolicyAssociationS storage data = lib.getPolicyAssociationStorage();
        uint256[] memory policyIds = data.contractPolicyIdMap[contractAddress];
        // loop through all the active policies
        for(uint256 policyIdx = 0; policyIdx < policyIds.length; policyIdx++) {
            if(!_checkPolicy(policyIds[policyIdx], contractAddress, arguments)) {
                retVal = 0;
            }
        }
    }

    function _checkPolicy(uint256 _policyId, address _contractAddress, bytes calldata arguments) internal returns (bool retVal) {
        _contractAddress; // added to remove wanring. TODO remove this once msg.sender testing is complete 
        // Load the policy data from storage   
        PolicyStorageSet storage policyStorageSet = lib.getPolicyStorage().policyStorageSets[_policyId];
        RuleS storage ruleData = lib.getRuleStorage();

        // Retrieve placeHolder[] for specific rule to be evaluated and translate function signature argument array 
        // to rule specific argument array
        // note that arguments is being sliced, first 4 bytes are the function signature being passed (:4) and the rest (4:) 
        // are all the arguments associated for the rule to be invoked. This saves on further calculations so that we don't need to factor in the signature.
        retVal = evaluateRulesAndExecuteEffects(ruleData ,_policyId, _loadApplicableRules(ruleData,policyStorageSet.policy, bytes4(arguments[:4])), arguments[4:]);
    }

    function _loadApplicableRules(RuleS storage ruleData, Policy storage policy, bytes4 functionSignature) internal view returns(uint256[] memory){
        // Load the policy data from storage
        uint256[] memory applicableRules = new uint256[](policy.signatureToRuleIds[functionSignature].length);
        uint256[] storage storagePointer = policy.signatureToRuleIds[functionSignature];
        // Load the function signature data from storage
        // RuleS storage ruleData = lib.getRuleStorage();
        // uint256 gasBefore = gasleft();
        for(uint256 i = 0; i < applicableRules.length; i++) {
            if(ruleData.ruleStorageSets[storagePointer[i]].set) {
                applicableRules[i] = storagePointer[i];
            }
        }
        // uint256 gasUsed = gasBefore - gasleft();
        // console.log("gasUsed in _loadApplicableRules: ", gasUsed);
        return applicableRules;
    }
    
    
    function evaluateRulesAndExecuteEffects(RuleS storage ruleData, uint256 _policyId, uint256[] memory applicableRules, bytes calldata functionSignatureArgs) internal returns (bool retVal) {
        retVal = true;
        
        for(uint256 i = 0; i < applicableRules.length; i++) {
            Rule storage rule = ruleData.ruleStorageSets[applicableRules[i]].rule;
            if(!evaluateIndividualRule(rule, _policyId, functionSignatureArgs)) {
                retVal = false;
                doEffects(rule, _policyId, rule.negEffects, functionSignatureArgs);
            } else{
                doEffects(rule, _policyId, rule.posEffects, functionSignatureArgs);

            }
        }
    }

    /**
     * @dev evaluates an individual rules condition(s)
     * @param _policyId Policy id being evaluated.
     * @param rule the rule structure containing the instruction set, with placeholders, to execute
     * @param functionSignatureArgs the values to replace the placeholders in the instruction set with.
     * @return response the result of the rule condition evaluation 
     * TODO: Look into the relationship between policy and foreign calls
     */
    function evaluateIndividualRule(Rule storage rule, uint256 _policyId, bytes calldata functionSignatureArgs) internal returns (bool response) {
        (bytes[] memory ruleArgs, Placeholder[] memory placeholders) = buildArguments(rule, _policyId, functionSignatureArgs, false);
        response = run(rule.instructionSet, placeholders, _policyId, ruleArgs);
    }

    function buildArguments(Rule storage rule, uint256 _policyId, bytes calldata functionSignatureArgs, bool effect) internal returns (bytes[] memory, Placeholder[] memory) {
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
                    ForeignCallReturnValue memory retVal = evaluateForeignCalls(_policyId, placeHolders, functionSignatureArgs, placeholder.typeSpecificIndex);
                    // Set the placeholders value and type based on the value returned by the foreign call
                    retVals[placeholderIndex] = retVal.value;
            } else if (placeholder.trackerValue) {
                // Load the Tracker data from storage
                Trackers memory tracker = lib.getTrackerStorage().trackers[_policyId][placeholder.typeSpecificIndex];
                retVals[placeholderIndex] = tracker.trackerValue;
            } else {
                // The placeholder represents a parameter from the calling function, set the value in the ruleArgs struct to the correct parameter
                if(placeholder.pType == PT.STR || placeholder.pType == PT.BYTES) {
                    retVals[placeholderIndex] = getDynamicVariableFromCalldata(functionSignatureArgs, placeholder.typeSpecificIndex);
                } else {
                    // since this is not a dynamic value, we can assume that it is only 1 word, therefore we multiply
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

    function run(uint256[] memory prog, Placeholder[] memory placeHolders, uint256 _policyId, bytes[] memory arguments) internal returns (bool ans) {
        uint256[90] memory mem;
        uint256 idx = 0;
        uint256 opi = 0;
        while (idx < prog.length) {
            uint256 v = 0;
            LC op = LC(prog[idx]);
            if(op == LC.PLH) {
                // Placeholder format is: get the index of the argument in the array. For example, PLH 0 is get the first argument in the arguments array and get its type and value
                uint256 pli = prog[idx+1];
                PT typ = placeHolders[pli].pType;
                if(typ == PT.ADDR) {
                    // Convert address to uint256 for direct comparison using == and != operations
                    v = uint256(uint160(address(abi.decode(arguments[pli], (address))))); idx += 2;
                } else if(typ == PT.UINT) {
                    v = abi.decode(arguments[pli], (uint256)); idx += 2;
                } else if(typ == PT.STR) {
                    // Convert string to uint256 for direct comparison using == and != operations
                    v = uint256(keccak256(abi.encode(abi.decode(arguments[pli], (string))))); idx += 2;
                }
            } else if(op == LC.TRU) {
                // Tracker Update format will be:
                // TRU, tracker index, mem index
                // TODO: Update to account for type
                // Load the Tracker data from storage
                Trackers storage set = lib.getTrackerStorage().trackers[_policyId][prog[idx + 1]];
                if(set.pType == PT.UINT) {
                    set.trackerValue = abi.encode(mem[prog[idx+2]]);
                }

                idx += 3;

            } else if (op == LC.NUM) { v = prog[idx+1]; idx += 2; }
            else if (op == LC.ADD) { v = mem[prog[idx+1]] + mem[prog[idx+2]]; idx += 3; }
            else if (op == LC.SUB) { v = mem[prog[idx+1]] - mem[prog[idx+2]]; idx += 3; }
            else if (op == LC.MUL) { v = mem[prog[idx+1]] * mem[prog[idx+2]]; idx += 3; }
            else if (op == LC.DIV) { v = mem[prog[idx+1]] / mem[prog[idx+2]]; idx += 3; }
            else if (op == LC.LT ) { v = bool2ui(mem[prog[idx+1]] < mem[prog[idx+2]]); idx += 3; }
            else if (op == LC.GT ) { v = bool2ui(mem[prog[idx+1]] > mem[prog[idx+2]]); idx += 3; }
            else if (op == LC.EQ ) { v = bool2ui(mem[prog[idx+1]] == mem[prog[idx+2]]); idx += 3; }
            else if (op == LC.AND) { v = bool2ui(ui2bool(mem[prog[idx+1]]) && ui2bool(mem[prog[idx+2]])); idx += 3; }
            else if (op == LC.OR ) { v = bool2ui(ui2bool(mem[prog[idx+1]]) || ui2bool(mem[prog[idx+2]])); idx += 3; }
            else if (op == LC.NOT) { v = bool2ui(! ui2bool(mem[prog[idx+1]])); idx += 2; }
            else { revert("Illegal instruction"); }
            mem[opi] = v;
            opi += 1;
        }
        return ui2bool(mem[opi - 1]);
    }


    function evaluateForeignCalls(
        uint256 _policyId, 
        Placeholder[] memory placeHolders,
        bytes calldata functionSignatureArgs, 
        uint256 foreignCallIndex
    ) public returns(ForeignCallReturnValue memory returnValue) {
        // Load the Foreign Call data from storage
        ForeignCall memory foreignCall = lib.getForeignCallStorage().foreignCalls[_policyId][foreignCallIndex];
        if (foreignCall.set) {
            return evaluateForeignCallForRule(foreignCall, functionSignatureArgs);
        }
    }

    /**
     * @dev encodes the arguments and places a foreign call, returning the calls return value as long as it is successful
     * @param fc the Foreign Call structure
     * @param functionArguments the argument mappings for the foreign call (function arguments and tracker values)
     * @param functionArguments the arguments of the rules calling funciton (to be passed to the foreign call as needed)
     * @return retVal the foreign calls return value
     */
    function evaluateForeignCallForRule(ForeignCall memory fc, bytes calldata functionArguments) public returns (ForeignCallReturnValue memory retVal) {
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
                // encode the dynamic offset
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

    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Effect Execution Functions
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @dev Loop through effects for a given rule and execute them
     * @param _effects list of effects
     */
    function doEffects(Rule storage rule, uint256 _policyId, Effect[] memory _effects, bytes calldata functionSignatureArgs) internal {

        // Load the Effect data from storage
        for(uint256 i = 0; i < _effects.length; i++) {
            Effect memory effect = _effects[i];
            if(effect.valid) {
                if (effect.effectType == ET.REVERT) { 
                    doRevert(effect.errorMessage);
                } else if (effect.effectType == ET.EVENT) {
                    buildEvent(rule, _effects[i].dynamicParam, _policyId, _effects[i].text, _effects[i], functionSignatureArgs);
                } else {
                    evaluateExpression(rule, _policyId, functionSignatureArgs, effect.instructionSet);
                }
            }
        }
    }

    /**
     * @dev Define event to be fired 
     */
    function buildEvent(Rule storage rule,
        bool isDynamicParam, 
        uint256 _policyId, 
        bytes32 _message, 
        Effect memory effectStruct, 
        bytes calldata functionSignatureArgs
        ) internal {
        // determine if we need to dynamically build event key 
        if (isDynamicParam){
            // fire event by param type based on return value 
            fireDynamicEvent(rule, _policyId, _message, functionSignatureArgs);
        } else {
            fireEvent(_policyId, _message, effectStruct);
        }
    }

    function fireDynamicEvent(Rule storage rule, uint256 _policyId, bytes32 _message, bytes calldata functionSignatureArgs) internal {
        // Build the effect arguments struct for event parameters:  
        (bytes[] memory effectArguments, Placeholder[] memory placeholders) = buildArguments(rule, _policyId, functionSignatureArgs, true);
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

    function fireEvent(uint256 _policyId, bytes32 _message, Effect memory effectStruct) internal { 
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
     * @dev Reverts the transaction
     * @param _message the reversion message
     */
    function doRevert(string memory _message) internal pure{
        revert(_message);
    }

    /**
     * @dev Evaluate an effect expression
     * @param _policyId the policy id
     * @param rule the rule structure containing the instruction set, with placeholders, to execute
     * @param functionSignatureArgs arguments of the function signature
     * @param instructionSet instruction set 
     */
    function evaluateExpression(Rule storage rule, uint256 _policyId, bytes calldata functionSignatureArgs, uint256[] memory instructionSet) internal {
        (bytes[] memory effectArguments, Placeholder[] memory placeholders) = buildArguments(rule, _policyId, functionSignatureArgs, true);
        if(instructionSet.length > 1) {
            run(instructionSet, placeholders, _policyId, effectArguments);
        }
    }

    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    // Utility Functions
    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    /**
     * @dev converts a uint256 to a bool
     * @param x the uint256 to convert
     */
    function ui2bool(uint256 x) public pure returns (bool ans) {
        return x == 1;
    }

    /**
     * @dev converts a bool to an uint256
     * @param x the bool to convert
     */
    function bool2ui(bool x) public pure returns (uint256 ans) {
        return x ? 1 : 0;
    }


    function stringToBytes32(string memory source) internal pure returns (bytes32 result) {
        assembly {
            result := mload(add(source, 32))
        }
    }

    function getDynamicVariableFromCalldata(bytes calldata data, uint256 index) public pure returns (bytes memory retVal) {
        // Get offset from parameter position, using index * 32 to get the correct position in the calldata
        uint256 offset = uint256(bytes32(data[index * 32:(index + 1) * 32]));
        // Get length from the offset position, using offset + 32 to get the correct position in the calldata
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        
        // Allocate memory for result: 32 (offset) + 32 (length) + data length
        bytes memory result = new bytes(64 + length);
    
        assembly {
            // Store offset to length (0x20)
            mstore(add(result, 32), 0x20)
            
            // Store length
            mstore(add(result, 64), length)
            
            // Copy actual data
            calldatacopy(
                add(result, 96),           // destination (after offset+length)
                add(add(data.offset, offset), 32),  // source (after length in calldata)
                length                     // length of data
            )
        }
        
        return result;
    }

    /**
     * @dev Retrieves the instruction set and raw string representations of a value 
     * @param _ruleId the id of the rule the values belong to
     * @param instructionSetId the index into the instruction set where the converted value lives
     */
    function retrieveRawStringFromInstructionSet(uint256 _ruleId, uint256 instructionSetId) public view returns (StringVerificationStruct memory retVal) {
        (uint256 instructionSetValue, bytes memory encoded) = retreiveRawEncodedFromInstructionSet(_ruleId, instructionSetId, PT.STR);
        retVal.rawData = abi.decode(encoded, (string));
        retVal.instructionSetValue = instructionSetValue;
    }


    /**
     * @dev Retrieves the instruction set and raw address representations of a value 
     * @param _ruleId the id of the rule the values belong to
     * @param instructionSetId the index into the instruction set where the converted value lives
     */
    function retrieveRawAddressFromInstructionSet(uint256 _ruleId, uint256 instructionSetId) public view returns (AddressVerificationStruct memory retVal) {
        (uint256 instructionSetValue, bytes memory encoded) = retreiveRawEncodedFromInstructionSet(_ruleId, instructionSetId, PT.ADDR);
        retVal.rawData = abi.decode(encoded, (address));
        retVal.instructionSetValue = instructionSetValue;
    }

    /**
     * @dev Retrieves the instruction set and raw representations of a value (raw data abi encoded)
     * @param _ruleId the id of the rule the values belong to
     * @param instructionSetId the index into the instruction set where the converted value lives
     * @param pType the parameter type of the value
     */
    function retreiveRawEncodedFromInstructionSet(uint256 _ruleId, uint256 instructionSetId, PT pType) internal view returns (uint256 instructionSetValue, bytes memory encoded) {
        RuleStorageSet memory _ruleStorage = lib.getRuleStorage().ruleStorageSets[_ruleId];
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

    function getDynamicValueArrayData(bytes calldata data, bytes memory dynamicData, uint length, uint lengthToAppend, uint256 offset) public pure returns (bytes memory, uint256) {
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
