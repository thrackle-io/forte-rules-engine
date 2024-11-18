// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "src/RulesEngineStructures.sol";
import "src/IRulesEngine.sol";
import "src/ExpressionParsingLibrary.sol";
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
    address effectProcessor;

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
     * Add a Policy to Storage
     * @param _policyId id of of the policy 
     * @param _signatures all signatures in the policy
     * @param functionSignatureIds corresponding signature ids in the policy. The elements in this array are one to one matches of the elements in _signatures array. They store the functionSignatureId for each of the signatures in _signatures array.
     * @param ruleIds two dimensional array of the rules. This array contains a simple count at first level and the second level is the array of ruleId's within the policy.
     * @return policyId generated policyId
     * @dev The parameters had to be complex because nested structs are not allowed for externally facing functions
     */
    function updatePolicy(uint256 _policyId, bytes[] calldata _signatures, uint256[] calldata functionSignatureIds, uint256[][] calldata ruleIds) public returns(uint256){
        // increment the policyId if necessary
        if (_policyId == 0) {
            unchecked{
                ++policyId;
            }
        } else {
            policyId = _policyId;            
        }
        // validate the policy data 
        // signature length must match the signature id length
        if (_signatures.length != functionSignatureIds.length) revert("Signatures and signature id's are inconsistent"); 
        // Loop through all the passed in signatures for the policy      
        for (uint256 i = 0; i < _signatures.length; i++) {
            // make sure that all the function signatures exist
            if(!functionSignatureStorage[functionSignatureIds[i]].set) revert("Invalid Signature");
            // Load into the mapping
            policyStorage[policyId].policy.functionSignatureIdMap[_signatures[i]] = functionSignatureIds[i];
            // make sure that all the rules attached to each function signature exist
            for (uint256 j = 0; j < ruleIds[i].length; j++) {
                if(!ruleStorage[ruleIds[i][j]].set) revert("Invalid Rule");
            }
            policyStorage[policyId].policy.signatureToRuleIds[_signatures[i]] = ruleIds[i];
        }        
        policyStorage[policyId].set = true;
        return policyId;
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
        } else {
            ruleId = _ruleId;            
        }
        ruleStorage[ruleId].set = true;
        ruleStorage[ruleId].rule = rule;
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
        } else {
            functionSignatureId = _functionSignatureId;            
        }
        functionSignatureStorage[functionSignatureId].set = true;
        functionSignatureStorage[functionSignatureId].signature = functionSignature;   
        functionSignatureStorage[functionSignatureId].parameterTypes = pTypes;
        return functionSignatureId;
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
        // Open to feedback on this if there is a better way to update the struct members based on type 
        trackerStorage[_policyId].set = true;
        for(uint256 i = 0; i < trackerStorage[_policyId].trackers.length; i++){
            if (trackerStorage[_policyId].trackers[i].pType == RulesStorageStructure.PT.UINT) trackerStorage[_policyId].trackers[i].uintTracker = updatedUintTracker;
            if (trackerStorage[_policyId].trackers[i].pType == RulesStorageStructure.PT.ADDR) trackerStorage[_policyId].trackers[i].addressTracker = updatedAddressTracker;
            if (trackerStorage[_policyId].trackers[i].pType == RulesStorageStructure.PT.STR) trackerStorage[_policyId].trackers[i].stringTracker = updatedStringTracker;
            if (trackerStorage[_policyId].trackers[i].pType == RulesStorageStructure.PT.BOOL) trackerStorage[_policyId].trackers[i].boolTracker = updatedBoolTracker;
            if (trackerStorage[_policyId].trackers[i].pType == RulesStorageStructure.PT.BYTES) trackerStorage[_policyId].trackers[i].bytesTracker = updatedBytesTracker;
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
     * @dev evaluates the conditions associated with all applicable rules and returns the result
     * @dev PEP for policy checks
     * @param contractAddress the address of the rules-enabled contract, used to pull the applicable rules
     * @param functionSignature the signature of the function that initiated the transaction, used to pull the applicable rules.
     * @param arguments function arguments
     * TODO: refine the parameters to this function. contractAddress is not necessary as it's the message caller
     */
    function checkPolicies(address contractAddress, bytes calldata functionSignature, bytes calldata arguments) public returns (bool) {        
        // loop through all the active policies
        for(uint256 policyIdx = 0; policyIdx < contractPolicyIdMap[contractAddress].length; policyIdx++) {
            _checkPolicy(contractPolicyIdMap[contractAddress][policyIdx], contractAddress, functionSignature, arguments);
        }
    }

    function _checkPolicy(uint256 _policyId, address contractAddress, bytes calldata functionSignature, bytes calldata arguments) internal {

        // Decode arguments from function signature
        RulesStorageStructure.PT[] memory functionSignaturePlaceholders;
        if(ruleStorage[contractAddress].set) {
            if(ruleStorage[contractAddress].functionSignatureMap[functionSignature].set) {
                functionSignaturePlaceholders = new RulesStorageStructure.PT[](ruleStorage[contractAddress].functionSignatureMap[functionSignature].parameterTypes.length);
                for(uint256 i = 0; i < functionSignaturePlaceholders.length; i++) {
                    functionSignaturePlaceholders[i] = ruleStorage[contractAddress].functionSignatureMap[functionSignature].parameterTypes[i];
                }
            }
        }
        
        RulesStorageStructure.Arguments memory functionSignatureArgs = ExpressionParsingLibrary.decodeFunctionSignatureArgs(functionSignaturePlaceholders, arguments);

        RulesStorageStructure.Rule[] memory applicableRules;
        if(ruleStorage[contractAddress].set) {
            if(ruleStorage[contractAddress].ruleMap[functionSignature].set) {
                applicableRules = new RulesStorageStructure.Rule[](ruleStorage[contractAddress].ruleMap[functionSignature].rules.length);
                for(uint256 i = 0; i < applicableRules.length; i++) {
                    applicableRules[i] = ruleStorage[contractAddress].ruleMap[functionSignature].rules[i];
                }
            } 
        }


        // Retrieve placeHolder[] for specific rule to be evaluated and translate function signature argument array 
        // to rule specific argument array
        for(uint256 i = 0; i < applicableRules.length; i++) { 
            RulesStorageStructure.foreignCallStorage memory foreignStorage = foreignCalls[contractAddress];
            if(!evaluateIndividualRule(applicableRules[i], functionSignatureArgs, contractAddress)) {
                this.doEffects(applicableRules[i].negEffects, applicableRules[i], functionSignatureArgs, contractAddress);
                return false;
            } else{
                this.doEffects(applicableRules[i].posEffects, applicableRules[i], functionSignatureArgs, contractAddress);
            }
        }
        return true;
    }

    /**
     * @dev evaluates an individual rules condition(s)
     * @param _policyId Policy id being evaluated.
     * @param applicableRule the rule structure containing the instruction set, with placeholders, to execute
     * @param functionSignatureArgs the values to replace the placeholders in the instruction set with.
     * @return response the result of the rule condition evaluation 
     * TODO: Look into the relationship between policy and foreign calls
     */
    function evaluateIndividualRule(int256 _policyId, RulesStorageStructure.Rule memory applicableRule, RulesStorageStructure.Arguments memory functionSignatureArgs) internal returns (bool response) {
            RulesStorageStructure.Arguments memory ruleArgs = buildArguments(applicableRule.placeHolders, applicableRule.fcArgumentMappingsConditions, functionSignatureArgs, contractAddress);
            response = this.run(applicableRule.instructionSet, ruleArgs, contractAddress);
    }

    function buildArguments(RulesStorageStructure.Placeholder[] memory placeHolders, RulesStorageStructure.ForeignCallArgumentMappings[] memory fcArgs, RulesStorageStructure.Arguments memory functionSignatureArgs, address contractAddress) public returns (RulesStorageStructure.Arguments memory) {
        RulesStorageStructure.Arguments memory ruleArgs;
        ruleArgs.argumentTypes = new RulesStorageStructure.PT[](placeHolders.length);
        // Initializing each to the max size to avoid the cost of iterating through to determine how many of each type exist
        ruleArgs.addresses = new address[](placeHolders.length);
        ruleArgs.ints = new uint256[](placeHolders.length);
        ruleArgs.strings = new string[](placeHolders.length);
        uint256 overallIter = 0;
        uint256 addressIter = 0;
        uint256 intIter = 0;
        uint256 stringIter = 0;

        for(uint256 placeholderIndex = 0; placeholderIndex < placeHolders.length; placeholderIndex++) {
            // Determine if the placeholder represents the return value of a foreign call or a function parameter from the calling function
            if(placeHolders[placeholderIndex].foreignCall) {
                    RulesStorageStructure.ForeignCallReturnValue memory retVal = ExpressionParsingLibrary.evaluateForeignCalls(placeHolders, fcArgs, functionSignatureArgs, contractAddress, placeholderIndex, foreignCalls);
                    // Set the placeholders value and type based on the value returned by the foreign call
                    ruleArgs.argumentTypes[overallIter] = retVal.pType;
                    if(retVal.pType == RulesStorageStructure.PT.ADDR) {
                        ruleArgs.addresses[addressIter] = retVal.addr;
                        overallIter += 1;
                        addressIter += 1;
                    } else if(retVal.pType == RulesStorageStructure.PT.STR) {
                        ruleArgs.strings[stringIter] = retVal.str;
                        overallIter += 1;
                        stringIter += 1;
                    } else if(retVal.pType == RulesStorageStructure.PT.UINT) {
                        ruleArgs.ints[intIter] = retVal.intValue;
                        overallIter += 1;
                        intIter += 1;
                    }
            } else {
                // Determine if the placeholder represents the return value of a tracker 
                if (placeHolders[placeholderIndex].trackerValue) {
                    // Loop through tracker storage for invoking address  
                    for(uint256 trackerValueIndex = 0; trackerValueIndex < trackerStorage[contractAddress].trackers.length; trackerValueIndex++) {
                        // determine pType of tracker
                        ruleArgs.argumentTypes[overallIter] = trackerStorage[contractAddress].trackers[trackerValueIndex].pType;
                        // replace the placeholder value with the tracker value 
                        if(ruleArgs.argumentTypes[overallIter] == RulesStorageStructure.PT.ADDR){
                            ruleArgs.addresses[addressIter] = trackerStorage[contractAddress].trackers[trackerValueIndex].addressTracker;
                            overallIter += 1;
                            addressIter += 1;
                        } else if(ruleArgs.argumentTypes[overallIter] == RulesStorageStructure.PT.UINT) {
                            ruleArgs.ints[intIter] = trackerStorage[contractAddress].trackers[trackerValueIndex].uintTracker;
                            overallIter += 1;
                            intIter += 1;
                        } else if(ruleArgs.argumentTypes[overallIter] == RulesStorageStructure.PT.STR) {
                            ruleArgs.strings[stringIter] = trackerStorage[contractAddress].trackers[trackerValueIndex].stringTracker;
                            overallIter += 1;
                            stringIter += 1;
                        }
                    }
                } else {
                    // The placeholder represents a parameter from the calling function, set the value in the ruleArgs struct to the correct parameter
                    if(placeHolders[placeholderIndex].pType == RulesStorageStructure.PT.ADDR) {
                        ruleArgs.argumentTypes[overallIter] = RulesStorageStructure.PT.ADDR;
                        ruleArgs.addresses[addressIter] = functionSignatureArgs.addresses[placeHolders[placeholderIndex].typeSpecificIndex];
                        overallIter += 1;
                        addressIter += 1;
                    } else if(placeHolders[placeholderIndex].pType == RulesStorageStructure.PT.UINT) {
                        ruleArgs.argumentTypes[overallIter] = RulesStorageStructure.PT.UINT;
                        ruleArgs.ints[intIter] = functionSignatureArgs.ints[placeHolders[placeholderIndex].typeSpecificIndex];
                        overallIter += 1;
                        intIter += 1;
                    } else if(placeHolders[placeholderIndex].pType == RulesStorageStructure.PT.STR) {
                        ruleArgs.argumentTypes[overallIter] = RulesStorageStructure.PT.STR;
                        ruleArgs.strings[stringIter] = functionSignatureArgs.strings[placeHolders[placeholderIndex].typeSpecificIndex];
                        overallIter += 1;
                        stringIter += 1;
                    }
                }
            }
        }
        return ruleArgs;
    }

    /**
     * @dev Loop through effects for a given rule and execute them
     * @param _effectIds list of effects
     */
    function doEffects(uint256[] calldata _effectIds, RulesStorageStructure.Rule memory applicableRule, RulesStorageStructure.Arguments memory functionSignatureArgs, address contractAddress) public {
        for(uint256 i = 0; i < _effectIds.length; i++) {
            if(_effectIds[i] > 0){// only ref Id's greater than 0 are valid
                EffectStructures.Effect memory effect = effectStorage[_effectIds[i]];
                if (effect.effectType == EffectStructures.ET.REVERT) { 
                    doRevert(effect.text);
                } else if (effect.effectType == EffectStructures.ET.EVENT) {
                     doEvent(effect.text);
                } else {
                    evaluateExpression(applicableRule, functionSignatureArgs, effect.instructionSet, contractAddress);
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

    function evaluateExpression(RulesStorageStructure.Rule memory applicableRule, RulesStorageStructure.Arguments memory functionSignatureArgs, uint256[] memory instructionSet, address contractAddress) public {
        RulesStorageStructure.Arguments memory effectArguments = buildArguments(applicableRule.effectPlaceHolders, applicableRule.fcArgumentMappingsEffects, functionSignatureArgs, contractAddress);
        if(instructionSet.length > 1) {
            this.run(instructionSet, effectArguments, contractAddress);
        }

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

    /**
     * @dev Evaluates the instruction set and returns an answer to the condition
     * @param prog The instruction set, with placeholders, to be run.
     * @param arguments the values to replace the placeholders in the instruction set with.
     * @return ans the result of evaluating the instruction set
     */
    function run(uint256[] calldata prog, RulesStorageStructure.Arguments calldata arguments, address contractAddress) public returns (bool ans) {
        uint256[64] memory mem;
        uint256 idx = 0;
        uint256 opi = 0;
        while (idx < prog.length) {
            uint256 v = 0;
            RulesStorageStructure.LC op = RulesStorageStructure.LC(prog[idx]);

            if(op == RulesStorageStructure.LC.PLH) {
                // Placeholder format will be:
                // PLH, arguments array index, argument type specific array index
                // For example if the Placeholder is the 3rd argument in the Arguments structure, which is the first address type argument:
                // PLH, 2, 0
                uint256 pli = prog[idx+1];
                uint256 spci = prog[idx+2];
                RulesStorageStructure.PT typ = arguments.argumentTypes[pli];
                if(typ == RulesStorageStructure.PT.ADDR) {
                    // Convert address to uint256 for direct comparison using == and != operations
                    v = uint256(uint160(arguments.addresses[spci])); idx += 3;
                } else if(typ == RulesStorageStructure.PT.UINT) {
                    v = arguments.ints[spci]; idx += 3;
                } else if(typ == RulesStorageStructure.PT.STR) {
                    // Convert string to uint256 for direct comparison using == and != operations
                    v = uint256(keccak256(abi.encode(arguments.strings[spci]))); idx += 3;
                }
            } else if(op == RulesStorageStructure.LC.TRU) {
                // Tracker Update format will be:
                // TRU, tracker index, mem index
                // TODO: Update to account for type
                if(trackerStorage[contractAddress].trackers[prog[idx + 1]].pType == RulesStorageStructure.PT.UINT) {
                    trackerStorage[contractAddress].trackers[prog[idx + 1]].uintTracker = mem[prog[idx+2]];
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
        foreignCallIndex += 1;
        fc.returnType = returnType;
        fc.parameterTypes = new RulesStorageStructure.PT[](arguments.length);
        for(uint256 i = 0; i < arguments.length; i++) {
            fc.parameterTypes[i] = arguments[i];
        }

        // If the foreign call structure already exists in the mapping update it, otherwise add it
        if(foreignCalls[_policyId].set) {
            foreignCalls[_policyId].foreignCalls.push(fc);
        } else {
            foreignCalls[_policyId].set = true;
            foreignCalls[_policyId].foreignCalls.push(fc);
        }
    }

    function setEffectProcessor(address _address) external {
        effectProcessor = _address;
    }
}
