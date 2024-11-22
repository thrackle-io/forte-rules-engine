// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "src/RulesStorageStructure.sol";
import "src/IRulesEngine.sol";
import "src/effects/EffectStructures.sol";

/**
 * @title Rules Engine Run Logic
 * @dev This contract provides the ability to evaluate rules when intiated
 * by a transaction involving a rules-enabled contract
 * @author @mpetersoCode55 
 */
contract RulesEngineRunLogic is IRulesEngine {
    // Contract Address to policy Id's 
    // TODO: Add capability for multiple policies per contract
    mapping (address contractAddress => uint256[]) contractPolicyIdMap; 
    // policy Id's to policy storage
    mapping (uint256 policyId => RulesStorageStructure.PolicyStorageStructure) policyStorage;
    // rule Id's to rule storage
    mapping(uint256 ruleId => RulesStorageStructure.RuleStorageStructure) ruleStorage;
    // function Id's to function storage
    mapping(uint256 functionId => RulesStorageStructure.FunctionSignatureStorageStructure) functionSignatureStorage;
    mapping(uint256 policyId => RulesStorageStructure.ForeignCallStorage) foreignCalls;
    mapping(uint256 policyId => RulesStorageStructure.TrackerValuesStorage) trackerStorage;

    // Loading helper mappings
    // mapping (bytes => uint256) functionSignatureIdMap;
    // mapping (bytes => uint256[]) signatureToRuleIds;
    RulesStorageStructure.Policy policy;

    uint256 foreignCallIndex;
    uint256 policyId;
    uint256 ruleId;
    uint256 functionSignatureId;

    /// Effect structures
    mapping(uint256=>EffectStructures.Effect) effectStorage;
    uint256 effectTotal;

    // Storage Modification Functions
    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    /**
     * Add a Policy to Storage
     * @param _policyId id of of the policy 
     * @param _signatures all signatures in the policy
     * @param functionSignatureIds corresponding signature ids in the policy. The elements in this array are one to one matches of the elements in _signatures array. They store the functionSignatureId for each of the signatures in _signatures array.
     * @param ruleIds two dimensional array of the rules. This array contains a simple count at first level and the second level is the array of ruleId's within the policy.
     * @return policyId generated policyId
     * @dev The parameters had to be complex because nested structs are not allowed for externally facing functions
     */
    function updatePolicy(uint256 _policyId, bytes[] calldata _signatures, uint256[] calldata functionSignatureIds, uint256[][] calldata ruleIds) public returns(uint256){
        // signature length must match the signature id length
        if (_signatures.length != functionSignatureIds.length) revert("Signatures and signature id's are inconsistent"); 
        // increment the policyId if necessary
        if (_policyId == 0) {
            unchecked{
                ++policyId;
            }
            _policyId = policyId;
            policyStorage[_policyId].set = true;
        }

        if (ruleIds.length > 0) {
            // Loop through all the passed in signatures for the policy      
            for (uint256 i = 0; i < _signatures.length; i++) {
                // make sure that all the function signatures exist
                if(!functionSignatureStorage[functionSignatureIds[i]].set) revert("Invalid Signature");
                // Load into the mapping
                policyStorage[_policyId].policy.functionSignatureIdMap[_signatures[i]] = functionSignatureIds[i];
                // make sure that all the rules attached to each function signature exist
                for (uint256 j = 0; j < ruleIds[i].length; j++) {
                    RulesStorageStructure.RuleStorageStructure memory ruleStore = ruleStorage[ruleIds[i][j]];
                    if(!ruleStore.set) revert("Invalid Rule");
                    for (uint256 k = 0; k < ruleStore.rule.placeHolders.length; k++) {
                        if(ruleStore.rule.placeHolders[k].foreignCall) {
                            require(foreignCalls[_policyId].set, "Foreign Call referenced in rule not set");
                        } else if (ruleStore.rule.placeHolders[k].trackerValue) {
                            require(trackerStorage[_policyId].set, "Tracker referenced in rule not set");
                        }
                    }
                }
                policyStorage[_policyId].policy.signatureToRuleIds[_signatures[i]] = ruleIds[i];
            }
        } else {
            // Solely loop through and add signatures to the policy
            for (uint256 i = 0; i < _signatures.length; i++) {
                // make sure that all the function signatures exist
                if(!functionSignatureStorage[functionSignatureIds[i]].set) revert("Invalid Signature");
                // Load into the mapping
                policyStorage[_policyId].policy.functionSignatureIdMap[_signatures[i]] = functionSignatureIds[i];
            }
        }    
        
        return _policyId;
    }

    /**
     * Apply the policies to the contracts.
     * @param _contractAddress address of the contract to have policies applied
     * @param _policyId the rule to add 
     */
    function applyPolicy(address _contractAddress, uint256[] calldata _policyId) public {
        // TODO: atomic setting function plus an addToAppliedPolicies?
        contractPolicyIdMap[_contractAddress] = new uint256[](_policyId.length);
        for(uint256 i = 0; i < _policyId.length; i++) {
           contractPolicyIdMap[_contractAddress][i] = _policyId[i];
        }
    }

    /**
     * Add a rule to the ruleStorage mapping.
     * @param _ruleId the id of the rule
     * @param rule the rule to add 
     * @return ruleId the generated ruleId
     */
    function updateRule(uint256 _ruleId, RulesStorageStructure.Rule calldata rule) public returns(uint256) {
        // TODO: Add validations for rule
        // increment the ruleId if necessary
        if (_ruleId == 0) {
            unchecked{
                ++ruleId;
            }
            _ruleId = ruleId;
        } 
        ruleStorage[_ruleId].set = true;
        ruleStorage[_ruleId].rule = rule;
        return ruleId;        
    }

    /**
     * Add a function signature to the storage.
     * @param _functionSignatureId functionSignatureId
     * @param functionSignature the string representation of the function signature
     * @param pTypes the types of the parameters for the function in order
     * @return ruleId generated rule Id 
     */
    function updateFunctionSignature(uint256 _functionSignatureId, bytes4 functionSignature, RulesStorageStructure.PT[] memory pTypes) public returns(uint256) {
        // TODO: Add validations for function signatures
        // increment the functionSignatureId if necessary
        if (_functionSignatureId == 0) {
            unchecked{
                ++functionSignatureId;
            }
            _functionSignatureId = functionSignatureId;
        }
        functionSignatureStorage[_functionSignatureId].set = true;
        functionSignatureStorage[_functionSignatureId].signature = functionSignature;   
        functionSignatureStorage[_functionSignatureId].parameterTypes = pTypes;
        return _functionSignatureId;
    }

    /**
     * Add a tracker to the trackerStorage mapping.
     * @param _policyId the policyId the trackerStorage is associated with
     * @param tracker the tracker to add 
     */
    function addTracker(uint256 _policyId, RulesStorageStructure.Trackers calldata tracker) public {
        trackerStorage[_policyId].set = true;
        trackerStorage[_policyId].trackers.push(tracker);
    }

    /**
     * Function to update tracker in trackerStorage mapping.
     * @param _policyId the policyId the trackerStorage is associated with
     * @param updatedUintTracker uint256 tracker update 
     * @param updatedAddressTracker address tracker update 
     * @param updatedStringTracker string tracker update 
     * @param updatedBoolTracker bool tracker update 
     * @param updatedBytesTracker bytes tracker update 
     */
    function updateTracker(uint256 _policyId, uint256 updatedUintTracker, address updatedAddressTracker, string memory updatedStringTracker, bool updatedBoolTracker, bytes memory updatedBytesTracker) public {
        trackerStorage[_policyId].set = true;
        for(uint256 i = 0; i < trackerStorage[_policyId].trackers.length; i++){
            if (trackerStorage[_policyId].trackers[i].pType == RulesStorageStructure.PT.UINT) trackerStorage[_policyId].trackers[i].trackerValue = abi.encode(updatedUintTracker);
            else if (trackerStorage[_policyId].trackers[i].pType == RulesStorageStructure.PT.ADDR) trackerStorage[_policyId].trackers[i].trackerValue = abi.encode(updatedAddressTracker);
            else if (trackerStorage[_policyId].trackers[i].pType == RulesStorageStructure.PT.STR) trackerStorage[_policyId].trackers[i].trackerValue = abi.encode(updatedStringTracker);
            else if (trackerStorage[_policyId].trackers[i].pType == RulesStorageStructure.PT.BOOL) trackerStorage[_policyId].trackers[i].trackerValue = abi.encode(updatedBoolTracker);
            else if (trackerStorage[_policyId].trackers[i].pType == RulesStorageStructure.PT.BYTES) trackerStorage[_policyId].trackers[i].trackerValue = abi.encode(updatedBytesTracker);
        }
    }

    /**
     * Return a tracker from the trackerStorage.
     * @param _policyId the policyId the trackerStorage is associated with
     * @param index postion of the tracker to return 
     * @return trackers
     */
    function getTracker(uint256 _policyId, uint256 index) public view returns (RulesStorageStructure.Trackers memory trackers) {
        // return trackers for contract address at speficic index  
        return trackerStorage[_policyId].trackers[index];
    }

    /**
     * @dev Update an effect
     * @param _effect the Effect to update
     */
    function updateEffect(EffectStructures.Effect calldata _effect) external returns (uint256 _effectId){
        if (_effect.effectId > 0){
            effectStorage[_effect.effectId] = _effect;
            _effectId = _effect.effectId;
        } else {
            effectTotal++;
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

    /**
     * @dev Builds a foreign call structure and adds it to the contracts storage, mapped to the contract address it is associated with
     * @param _policyId the policy Id of the policy the foreign call will be mapped to
     * @param foreignContractAddress the address of the contract where the foreign call exists
     * @param functionSignature the string representation of the function signature of the foreign call
     * @param returnType the parameter type of the foreign calls return value
     * @param arguments the parameter types of the foreign calls arguments in order
     * @return fc the foreign call structure 
     */
    function updateForeignCall(uint256 _policyId, address foreignContractAddress, string memory functionSignature, RulesStorageStructure.PT returnType, RulesStorageStructure.PT[] memory arguments) public returns (RulesStorageStructure.ForeignCall memory fc) {
        fc.foreignCallAddress = foreignContractAddress;
        // Convert the string representation of the function signature to a selector
        fc.signature = bytes4(keccak256(bytes(functionSignature)));
        fc.foreignCallIndex = foreignCallIndex;
        foreignCallIndex++;
        fc.returnType = returnType;
        fc.parameterTypes = new RulesStorageStructure.PT[](arguments.length);
        for(uint256 i = 0; i < arguments.length; i++) {
            fc.parameterTypes[i] = arguments[i];
        }

        // If the foreign call structure already exists in the mapping update it, otherwise add it
        foreignCalls[_policyId].foreignCalls.push(fc);
        foreignCalls[_policyId].set = true;
    }

    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    // Rule Evaluation Functions
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @dev evaluates the conditions associated with all applicable rules and returns the result
     * @dev PEP for policy checks
     * @param contractAddress the address of the rules-enabled contract, used to pull the applicable rules
     * @param functionSignature the signature of the function that initiated the transaction, used to pull the applicable rules.
     * @param arguments function arguments
     * TODO: refine the parameters to this function. contractAddress is not necessary as it's the message caller
     */
    function checkPolicies(address contractAddress, bytes calldata functionSignature, bytes calldata arguments) public returns (uint256 retVal) {  
        retVal = 1; 
        // loop through all the active policies
        for(uint256 policyIdx = 0; policyIdx < contractPolicyIdMap[contractAddress].length; policyIdx++) {
            if(!_checkPolicy(contractPolicyIdMap[contractAddress][policyIdx], contractAddress, functionSignature, arguments)) {
                retVal = 0;
            }
        }
    }

    function _checkPolicy(uint256 _policyId, address contractAddress, bytes calldata functionSignature, bytes calldata arguments) internal returns (bool retVal) {
        // Decode arguments from function signature
        RulesStorageStructure.PT[] memory functionSignaturePlaceholders;
        if(policyStorage[_policyId].set) {
            if(functionSignatureStorage[policyStorage[_policyId].policy.functionSignatureIdMap[functionSignature]].set) {
                functionSignaturePlaceholders = new RulesStorageStructure.PT[](functionSignatureStorage[policyStorage[_policyId].policy.functionSignatureIdMap[functionSignature]].parameterTypes.length);
                for(uint256 i = 0; i < functionSignaturePlaceholders.length; i++) {
                    functionSignaturePlaceholders[i] = functionSignatureStorage[policyStorage[_policyId].policy.functionSignatureIdMap[functionSignature]].parameterTypes[i];
                }
            }
        }
        
        RulesStorageStructure.Arguments memory functionSignatureArgs = abi.decode(arguments, (RulesStorageStructure.Arguments));

        RulesStorageStructure.Rule[] memory applicableRules = new RulesStorageStructure.Rule[](policyStorage[_policyId].policy.signatureToRuleIds[functionSignature].length);
        for(uint256 i = 0; i < applicableRules.length; i++) {
            if(ruleStorage[policyStorage[_policyId].policy.signatureToRuleIds[functionSignature][i]].set) {
                applicableRules[i] = ruleStorage[policyStorage[_policyId].policy.signatureToRuleIds[functionSignature][i]].rule;
            }
        }

        // Retrieve placeHolder[] for specific rule to be evaluated and translate function signature argument array 
        // to rule specific argument array
        retVal = evaluateRulesAndExecuteEffects(_policyId, applicableRules, functionSignatureArgs);
    }

    function evaluateRulesAndExecuteEffects(uint256 _policyId, RulesStorageStructure.Rule[] memory applicableRules, RulesStorageStructure.Arguments memory functionSignatureArgs) public returns (bool retVal) {
        retVal = true;
        for(uint256 i = 0; i < applicableRules.length; i++) { 
            RulesStorageStructure.ForeignCallStorage memory foreignStorage = foreignCalls[_policyId];
            if(!evaluateIndividualRule(_policyId, applicableRules[i], functionSignatureArgs)) {
                retVal = false;
                this.doEffects(_policyId, applicableRules[i].negEffects, applicableRules[i], functionSignatureArgs);
            } else{
                this.doEffects(_policyId, applicableRules[i].posEffects, applicableRules[i], functionSignatureArgs);
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
    function evaluateIndividualRule(uint256 _policyId, RulesStorageStructure.Rule memory applicableRule, RulesStorageStructure.Arguments memory functionSignatureArgs) internal returns (bool response) {
            RulesStorageStructure.Arguments memory ruleArgs = buildArguments(_policyId, applicableRule.placeHolders, applicableRule.fcArgumentMappingsConditions, functionSignatureArgs);
            response = this.run(_policyId, applicableRule.instructionSet, ruleArgs);
    }

    function buildArguments(uint256 _policyId, RulesStorageStructure.Placeholder[] memory placeHolders, RulesStorageStructure.ForeignCallArgumentMappings[] memory fcArgs, RulesStorageStructure.Arguments memory functionSignatureArgs) public returns (RulesStorageStructure.Arguments memory) {
        RulesStorageStructure.Arguments memory ruleArgs;
        ruleArgs.argumentTypes = new RulesStorageStructure.PT[](placeHolders.length);
        ruleArgs.values = new bytes[](placeHolders.length);
        uint256 overallIter = 0;

        for(uint256 placeholderIndex = 0; placeholderIndex < placeHolders.length; placeholderIndex++) {
            // Determine if the placeholder represents the return value of a foreign call or a function parameter from the calling function
            if(placeHolders[placeholderIndex].foreignCall) {
                    RulesStorageStructure.ForeignCallReturnValue memory retVal = evaluateForeignCalls(_policyId, placeHolders, fcArgs, functionSignatureArgs, placeholderIndex);
                    // Set the placeholders value and type based on the value returned by the foreign call
                    ruleArgs.argumentTypes[overallIter] = retVal.pType;
                    ruleArgs.values[overallIter] = retVal.value;
                    ++overallIter;
            } else if (placeHolders[placeholderIndex].trackerValue) {
                // Loop through tracker storage for invoking address  
                for(uint256 trackerValueIndex = 0; trackerValueIndex < trackerStorage[_policyId].trackers.length; trackerValueIndex++) {
                    // determine pType of tracker
                    ruleArgs.argumentTypes[overallIter] = trackerStorage[_policyId].trackers[trackerValueIndex].pType;
                    // replace the placeholder value with the tracker value 
                    ruleArgs.values[overallIter] = trackerStorage[_policyId].trackers[trackerValueIndex].trackerValue;
                    ++overallIter;
                }
            } else {
                // The placeholder represents a parameter from the calling function, set the value in the ruleArgs struct to the correct parameter
                if(placeHolders[placeholderIndex].pType == RulesStorageStructure.PT.ADDR) {
                    ruleArgs.argumentTypes[overallIter] = RulesStorageStructure.PT.ADDR;
                } else if(placeHolders[placeholderIndex].pType == RulesStorageStructure.PT.UINT) {
                    ruleArgs.argumentTypes[overallIter] = RulesStorageStructure.PT.UINT;
                } else if(placeHolders[placeholderIndex].pType == RulesStorageStructure.PT.STR) {
                    ruleArgs.argumentTypes[overallIter] = RulesStorageStructure.PT.STR;
                }
                ruleArgs.values[overallIter] = functionSignatureArgs.values[placeHolders[placeholderIndex].typeSpecificIndex];
                ++overallIter;
            }
        }
        return ruleArgs;
    }

    /**
     * @dev Evaluates the instruction set and returns an answer to the condition
     * @param prog The instruction set, with placeholders, to be run.
     * @param arguments the values to replace the placeholders in the instruction set with.
     * @return ans the result of evaluating the instruction set
     */
    function run(uint256 _policyId, uint256[] calldata prog, RulesStorageStructure.Arguments calldata arguments) public returns (bool ans) {
        uint256[64] memory mem;
        uint256 idx = 0;
        uint256 opi = 0;
        while (idx < prog.length) {
            uint256 v = 0;
            RulesStorageStructure.LC op = RulesStorageStructure.LC(prog[idx]);
            if(op == RulesStorageStructure.LC.PLH) {
                // Placeholder format is: get the index of the argument in the array. For example, PLH 0 is get the first argument in the arguments array and get its type and value
                uint256 pli = prog[idx+1];

                RulesStorageStructure.PT typ = arguments.argumentTypes[pli];
                if(typ == RulesStorageStructure.PT.ADDR) {
                    // Convert address to uint256 for direct comparison using == and != operations
                    v = uint256(uint160(address(abi.decode(arguments.values[pli], (address))))); idx += 2;
                } else if(typ == RulesStorageStructure.PT.UINT) {
                    v = abi.decode(arguments.values[pli], (uint256)); idx += 2;
                } else if(typ == RulesStorageStructure.PT.STR) {
                    // Convert string to uint256 for direct comparison using == and != operations
                    v = uint256(keccak256(abi.encode(abi.decode(arguments.values[pli], (string))))); idx += 2;
                }
            } else if(op == RulesStorageStructure.LC.TRU) {
                // Tracker Update format will be:
                // TRU, tracker index, mem index
                // TODO: Update to account for type
                if(trackerStorage[_policyId].trackers[prog[idx + 1]].pType == RulesStorageStructure.PT.UINT) {
                    trackerStorage[_policyId].trackers[prog[idx + 1]].trackerValue = abi.encode(mem[prog[idx+2]]);
                }
                idx += 3;

            } else if (op == RulesStorageStructure.LC.NUM) { v = prog[idx+1]; idx += 2; }
            else if (op == RulesStorageStructure.LC.ADD) { v = mem[prog[idx+1]] + mem[prog[idx+2]]; idx += 3; }
            else if (op == RulesStorageStructure.LC.SUB) { v = mem[prog[idx+1]] - mem[prog[idx+2]]; idx += 3; }
            else if (op == RulesStorageStructure.LC.MUL) { v = mem[prog[idx+1]] * mem[prog[idx+2]]; idx += 3; }
            else if (op == RulesStorageStructure.LC.DIV) { v = mem[prog[idx+1]] / mem[prog[idx+2]]; idx += 3; }
            else if (op == RulesStorageStructure.LC.LT ) { v = bool2ui(mem[prog[idx+1]] < mem[prog[idx+2]]); idx += 3; }
            else if (op == RulesStorageStructure.LC.GT ) { v = bool2ui(mem[prog[idx+1]] > mem[prog[idx+2]]); idx += 3; }
            else if (op == RulesStorageStructure.LC.EQ ) { v = bool2ui(mem[prog[idx+1]] == mem[prog[idx+2]]); idx += 3; }
            else if (op == RulesStorageStructure.LC.AND) { v = bool2ui(ui2bool(mem[prog[idx+1]]) && ui2bool(mem[prog[idx+2]])); idx += 3; }
            else if (op == RulesStorageStructure.LC.OR ) { v = bool2ui(ui2bool(mem[prog[idx+1]]) || ui2bool(mem[prog[idx+2]])); idx += 3; }
            else if (op == RulesStorageStructure.LC.NOT) { v = bool2ui(! ui2bool(mem[prog[idx+1]])); idx += 2; }
            else { revert("Illegal instruction"); }
            mem[opi] = v;
            opi += 1;
        }
        return ui2bool(mem[opi - 1]);
    }


    function evaluateForeignCalls(uint256 _policyId, RulesStorageStructure.Placeholder[] memory placeHolders, RulesStorageStructure.ForeignCallArgumentMappings[] memory fcArgumentMappings, RulesStorageStructure.Arguments memory functionSignatureArgs, uint256 placeholderIndex) public returns(RulesStorageStructure.ForeignCallReturnValue memory) {
        // Loop through the foreign call structures associated with the calling contracts address
        for(uint256 foreignCallsIdx = 0; foreignCallsIdx < foreignCalls[_policyId].foreignCalls.length; foreignCallsIdx++) {
            // Check if the index for this placeholder matches the foreign calls index
            if(foreignCalls[_policyId].foreignCalls[foreignCallsIdx].foreignCallIndex == placeHolders[placeholderIndex].typeSpecificIndex) {
                // Place the foreign call
                RulesStorageStructure.ForeignCallReturnValue memory retVal = evaluateForeignCallForRule(foreignCalls[_policyId].foreignCalls[foreignCallsIdx], fcArgumentMappings, functionSignatureArgs);
                return retVal;
            }
        }
    }

    /**
     * @dev encodes the arguments and places a foreign call, returning the calls return value as long as it is successful
     * @param fc the Foreign Call structure
     * @param functionArguments the argument mappings for the foreign call (function arguments and tracker values)
     * @param functionArguments the arguments of the rules calling funciton (to be passed to the foreign call as needed)
     * @return retVal the foreign calls return value
     */
    function evaluateForeignCallForRule(RulesStorageStructure.ForeignCall memory fc, RulesStorageStructure.ForeignCallArgumentMappings[] memory fcArgumentMappings, RulesStorageStructure.Arguments memory functionArguments) internal returns (RulesStorageStructure.ForeignCallReturnValue memory retVal) {
        // First, calculate total size needed and positions of dynamic data
        uint dynamicVarCount = 0;
        uint[] memory dynamicVarLengths = new uint[](functionArguments.values.length);
        bytes[] memory values = new bytes[](functionArguments.values.length);
        RulesStorageStructure.PT[] memory parameterTypes = new RulesStorageStructure.PT[](functionArguments.values.length);

        // First pass: calculate sizes
        for(uint256 i = 0; i < fcArgumentMappings.length; i++) {
            if(fcArgumentMappings[i].foreignCallIndex == fc.foreignCallIndex) {
                for(uint256 j = 0; j < fcArgumentMappings[i].mappings.length; j++) {
                    // Check the parameter type and set the values in the encode arrays accordingly 
                    RulesStorageStructure.PT argType = fcArgumentMappings[i].mappings[j].functionCallArgumentType;
                    bytes memory value = functionArguments.values[fcArgumentMappings[i].mappings[j].functionSignatureArg.typeSpecificIndex];
                    parameterTypes[j] = argType;
                    values[j] = value;
                    if (argType == RulesStorageStructure.PT.STR) {
                        dynamicVarLengths[dynamicVarCount] = value.length;
                        ++dynamicVarCount;
                    }
                }
            }
        }

        bytes memory encodedCall = assemblyEncode(parameterTypes, values, fc.signature, dynamicVarLengths);
        // Place the foreign call
        (bool response, bytes memory data) = fc.foreignCallAddress.call(encodedCall);
    

        // Verify that the foreign call was successful
        if(response) {
            // Decode the return value based on the specified return value parameter type in the foreign call structure
            if(fc.returnType == RulesStorageStructure.PT.BOOL) {
                retVal.pType = RulesStorageStructure.PT.BOOL;
            } else if(fc.returnType == RulesStorageStructure.PT.UINT) {
                retVal.pType = RulesStorageStructure.PT.UINT;
            } else if(fc.returnType == RulesStorageStructure.PT.STR) {
                retVal.pType = RulesStorageStructure.PT.STR;
            } else if(fc.returnType == RulesStorageStructure.PT.ADDR) {
                retVal.pType = RulesStorageStructure.PT.ADDR;
            } else if(fc.returnType == RulesStorageStructure.PT.VOID) {
                retVal.pType = RulesStorageStructure.PT.VOID;
            }
            retVal.value = data;
        }
    }

    //-------------------------------------------------------------------------------------------------------------------------------------------------------


    // Effect Execution Functions
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @dev Loop through effects for a given rule and execute them
     * @param _effectIds list of effects
     */
    function doEffects(uint256 _policyId, uint256[] calldata _effectIds, RulesStorageStructure.Rule memory applicableRule, RulesStorageStructure.Arguments memory functionSignatureArgs) public {
        for(uint256 i = 0; i < _effectIds.length; i++) {
            if(_effectIds[i] > 0){// only ref Id's greater than 0 are valid
                EffectStructures.Effect memory effect = effectStorage[_effectIds[i]];
                if (effect.effectType == EffectStructures.ET.REVERT) { 
                    doRevert(effect.text);
                } else if (effect.effectType == EffectStructures.ET.EVENT) {
                     doEvent(effect.text);
                } else {
                    evaluateExpression(_policyId, applicableRule, functionSignatureArgs, effect.instructionSet);
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
        emit EffectStructures.RulesEngineEvent(_message);
    }

    function evaluateExpression(uint256 _policyId, RulesStorageStructure.Rule memory applicableRule, RulesStorageStructure.Arguments memory functionSignatureArgs, uint256[] memory instructionSet) public {
        RulesStorageStructure.Arguments memory effectArguments = buildArguments( _policyId, applicableRule.effectPlaceHolders, applicableRule.fcArgumentMappingsEffects, functionSignatureArgs);
        if(instructionSet.length > 1) {
            this.run(_policyId, instructionSet, effectArguments);
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
    function assemblyEncode(RulesStorageStructure.PT[] memory parameterTypes, bytes[] memory values, bytes4 selector, uint[] memory dynamicVarLengths) internal pure returns (bytes memory encoded) {
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

    /**
     * @dev Retrieves the instruction set and raw string representations of a value 
     * @param _ruleId the id of the rule the values belong to
     * @param instructionSetId the index into the instruction set where the converted value lives
     */
    function retrieveRawStringFromInstructionSet(uint256 _ruleId, uint256 instructionSetId) public view returns (RulesStorageStructure.StringVerificationStruct memory retVal) {
        (uint256 instructionSetValue, bytes memory encoded) = retreiveRawEncodedFromInstructionSet(_ruleId, instructionSetId, RulesStorageStructure.PT.STR);
        retVal.rawData = abi.decode(encoded, (string));
        retVal.instructionSetValue = instructionSetValue;
    }


    /**
     * @dev Retrieves the instruction set and raw address representations of a value 
     * @param _ruleId the id of the rule the values belong to
     * @param instructionSetId the index into the instruction set where the converted value lives
     */
    function retrieveRawAddressFromInstructionSet(uint256 _ruleId, uint256 instructionSetId) public view returns (RulesStorageStructure.AddressVerificationStruct memory retVal) {
        (uint256 instructionSetValue, bytes memory encoded) = retreiveRawEncodedFromInstructionSet(_ruleId, instructionSetId, RulesStorageStructure.PT.ADDR);
        retVal.rawData = abi.decode(encoded, (address));
        retVal.instructionSetValue = instructionSetValue;
    }

    /**
     * @dev Retrieves the instruction set and raw representations of a value (raw data abi encoded)
     * @param _ruleId the id of the rule the values belong to
     * @param instructionSetId the index into the instruction set where the converted value lives
     * @param pType the parameter type of the value
     */
    function retreiveRawEncodedFromInstructionSet(uint256 _ruleId, uint256 instructionSetId, RulesStorageStructure.PT pType) internal view returns (uint256 instructionSetValue, bytes memory encoded) {
        RulesStorageStructure.RuleStorageStructure memory _ruleStorage = ruleStorage[_ruleId];
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
