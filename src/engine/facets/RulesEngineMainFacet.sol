// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetCommonImports.sol";

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
        retVal = evaluateRulesAndExecuteEffects(ruleData ,_policyId, _loadApplicableRules(ruleData,policyStorageSet.policy, bytes4(arguments[:4])), arguments[4:]);
    }

    function _loadApplicableRules(RuleS storage ruleData, Policy storage policy, bytes4 functionSignature) internal view returns(uint256[] memory){
        // Load the policy data from storage
        uint256[] memory applicableRules = new uint256[](policy.signatureToRuleIds[functionSignature].length);

        // Load the function signature data from storage
        // RuleS storage ruleData = lib.getRuleStorage();

        for(uint256 i = 0; i < applicableRules.length; i++) {
            if(ruleData.ruleStorageSets[policy.signatureToRuleIds[functionSignature][i]].set) {
                applicableRules[i] = policy.signatureToRuleIds[functionSignature][i];
            }
        }
        return applicableRules;
    }
    
    
    function evaluateRulesAndExecuteEffects(RuleS storage ruleData, uint256 _policyId, uint256[] memory applicableRules, bytes calldata functionSignatureArgs) internal returns (bool retVal) {
        retVal = true;
        
        for(uint256 i = 0; i < applicableRules.length; i++) { 
            if(!evaluateIndividualRule(ruleData, _policyId, applicableRules[i], functionSignatureArgs)) {
                retVal = false;
                doEffects(ruleData, _policyId, applicableRules[i], ruleData.ruleStorageSets[applicableRules[i]].rule.negEffects, functionSignatureArgs);
            } else{
                doEffects(ruleData, _policyId, applicableRules[i], ruleData.ruleStorageSets[applicableRules[i]].rule.posEffects, functionSignatureArgs);

            }
        }
    }

    /**
     * @dev evaluates an individual rules condition(s)
     * @param _policyId Policy id being evaluated.
     * @param applicableRule the rule structure containing the instruction set, with placeholders, to execute
     * @param functionSignatureArgs the values to replace the placeholders in the instruction set with.
     * @return response the result of the rule condition evaluation 
     * TODO: Look into the relationship between policy and foreign calls
     */
    function evaluateIndividualRule(RuleS storage ruleData, uint256 _policyId, uint256 applicableRule, bytes calldata functionSignatureArgs) internal returns (bool response) {
        (bytes[] memory ruleArgs, Placeholder[] memory placeholders) = buildArguments(ruleData, _policyId, applicableRule, functionSignatureArgs, false);
        response = run(ruleData.ruleStorageSets[applicableRule].rule.instructionSet, placeholders, _policyId, ruleArgs);
    }

    function buildArguments(RuleS storage ruleData, uint256 _policyId, uint256 applicableRule, bytes calldata functionSignatureArgs, bool effect) internal returns (bytes[] memory, Placeholder[] memory) {
        Placeholder[] memory placeHolders;

        if(effect) {
            placeHolders = ruleData.ruleStorageSets[applicableRule].rule.effectPlaceHolders;
        } else {
            placeHolders = ruleData.ruleStorageSets[applicableRule].rule.placeHolders;
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
                Trackers memory tracker = lib.getTrackerStorage().trackerValueSets[_policyId].trackers[placeholder.typeSpecificIndex];
                retVals[placeholderIndex] = tracker.trackerValue;
            } else {
                // The placeholder represents a parameter from the calling function, set the value in the ruleArgs struct to the correct parameter
                if(placeholder.pType == PT.STR || placeholder.pType == PT.BYTES) {
                    retVals[placeholderIndex] = getDynamicVariableFromCalldata(functionSignatureArgs, placeholder.typeSpecificIndex);
                } else {
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
                TrackerValuesSet storage set = lib.getTrackerStorage().trackerValueSets[_policyId];
                if(set.trackers[prog[idx + 1]].pType == PT.UINT) {
                    set.trackers[prog[idx + 1]].trackerValue = abi.encode(mem[prog[idx+2]]);
                    lib.getTrackerStorage().trackerValueSets[_policyId] = set;
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
                (bytes memory dynamicValue, uint256 dynamicLength) = getDynamicVariableFromCalldataNoOffset(functionArguments, typeSpecificIndex);
                uint256 dynamicOffset = (fc.parameterTypes.length * 32) + lengthToAppend;
                encodedCall = bytes.concat(encodedCall, bytes32(dynamicOffset));
                dynamicData = bytes.concat(dynamicData, dynamicValue);
                uint dynamicLengthToWordLength = (dynamicLength + 31) / 32 * 32;
                lengthToAppend += dynamicLengthToWordLength;
            } else {
                encodedCall = bytes.concat(encodedCall, value);
            }
        }

        // Place the foreign call
        (bool response, bytes memory data) = fc.foreignCallAddress.call(bytes.concat(encodedCall, dynamicData));
    

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
    function doEffects(RuleS storage ruleData, uint256 _policyId, uint256 applicableRule, Effect[] memory _effects, bytes calldata functionSignatureArgs) internal {

        // Load the Effect data from storage
        for(uint256 i = 0; i < _effects.length; i++) {
            Effect memory effect = _effects[i];
            if(effect.valid) {
                if (effect.effectType == ET.REVERT) { 
                    doRevert(effect.text);
                } else if (effect.effectType == ET.EVENT) {
                    doEvent(effect.text);
                } else {
                    evaluateExpression(ruleData, _policyId, applicableRule, functionSignatureArgs, effect.instructionSet);
                }
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

    function evaluateExpression(RuleS storage ruleData, uint256 _policyId, uint256 applicableRule, bytes calldata functionSignatureArgs, uint256[] memory instructionSet) internal {
        (bytes[] memory effectArguments, Placeholder[] memory placeholders) = buildArguments(ruleData, _policyId, applicableRule, functionSignatureArgs, true);
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

    /**
     * @dev Uses assembly to encode a variable length array of variable type arguments so they can be used in a foreign call
     * @param parameterTypes the parameter types of the arguments in order
     * @param values the values to be encoded
     * @param selector the selector of the function to be called
     * @param dynamicVarLengths the lengths of the dynamic variables to be encoded
     * @return encoded the encoded arguments
     */
    function assemblyEncode(PT[] memory parameterTypes, bytes[] memory values, bytes4 selector, uint[] memory dynamicVarLengths) public pure returns (bytes memory encoded) {
        assert(parameterTypes.length == values.length);
        assert(dynamicVarLengths.length <= parameterTypes.length);
        uint256 headSize = parameterTypes.length * 32;
        uint256 tailSize = dynamicVarLengths.length * 32;
        for (uint i; i < dynamicVarLengths.length; ++i) {
            tailSize += (dynamicVarLengths[i] + 31) / 32 * 32;
        }

        assembly {
            let totalSize := add(4, add(headSize, tailSize))
            encoded := mload(0x40)
            mstore(encoded, totalSize)
            mstore(add(encoded, 0x20), selector)
            // Update the free memory pointer to the end of the encoded data
            mstore(0x40, add(encoded, add(0x20, totalSize)))

            let headPtr := 4  // Start after selector
            let tailPtr := add(headSize, 4)  // Dynamic data starts after head
            let dynamicValuesIndex := 0

            // Main encoding loop
            for { let i := 0 } lt(i, mload(parameterTypes)) { i := add(i, 1) } {
                // Load the parameter type
                let pType := mload(add(add(parameterTypes, 0x20), mul(i, 0x20)))
                
                // Get the current value pointer
                let valuePtr := mload(add(add(values, 0x20), mul(i, 0x20)))

                // Handle each type
                switch pType
                // Address (0)
                case 0 {
                    mstore(
                        add(add(encoded, 0x20), headPtr),
                        and(mload(add(valuePtr, 0x20)), 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
                    )
                }
                // String (1)
                case 1 {
                    // Store offset in head
                    mstore(add(add(encoded, 0x20), headPtr), sub(tailPtr, 4))
        
                    // Get the source bytes value
                    let bytesValue := mload(add(add(values, 0x20), mul(i, 0x20)))
                    
                    // Get string length - need to read from the correct position
                    // bytesValue points to the bytes array which contains our encoded string
                    // The actual string length is at bytesValue + 0x40 (skip two words)
                    let strLength := mload(add(bytesValue, 0x40))
                    
                    // Store length at tail position
                    mstore(add(add(encoded, 0x20), tailPtr), strLength)
                    
                    // Copy the actual string data
                    let srcPtr := add(bytesValue, 0x60)  // skip to actual string data
                    let destPtr := add(add(encoded, 0x20), add(tailPtr, 0x20))
                    let wordCount := div(add(strLength, 31), 32)
                    
                    // Copy each word
                    for { let j := 0 } lt(j, wordCount) { j := add(j, 1) } {
                        let word := mload(add(srcPtr, mul(j, 0x20)))
                        mstore(add(destPtr, mul(j, 0x20)), word)
                    }
        
                    // Update tail pointer
                    tailPtr := add(tailPtr, add(0x20, mul(wordCount, 0x20)))    
                    dynamicValuesIndex := add(dynamicValuesIndex, 1)
                }
                // Uint (2)
                case 2 {
                    mstore(
                        add(add(encoded, 0x20), headPtr),
                        mload(add(valuePtr, 0x20))
                    )
                }
                headPtr := add(headPtr, 32)
            }
        }
    }


    function stringToBytes32(string memory source) internal pure returns (bytes32 result) {
        assembly {
            result := mload(add(source, 32))
        }
    }

    function getDynamicVariableFromCalldata(bytes calldata data, uint256 index) public pure returns (bytes memory retVal) {
        // Get offset from parameter position
        uint256 offset = uint256(bytes32(data[index * 32:(index + 1) * 32]));
        // Get length from the offset position
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

    function getDynamicVariableFromCalldataNoOffset(bytes calldata data, uint256 index) public pure returns (bytes memory, uint256) {
        // Get offset from parameter position
        uint256 offset = uint256(bytes32(data[index * 32:(index + 1) * 32]));
        // Get length from the offset position
        uint256 length = uint256(bytes32(data[offset:offset + 32]));
        
        // Allocate memory for result: 32 (length) + data length
        bytes memory result = new bytes(32 + length);
        
        assembly {
            // Store length
            mstore(add(result, 32), length)
            
            // Copy actual data
            calldatacopy(
                add(result, 64),           // destination (after length)
                add(add(data.offset, offset), 32),  // source (after length in calldata)
                length                     // length of data
            )
        }
        
        return (result, length);
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
    
}
