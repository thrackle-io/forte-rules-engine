// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "src/RulesEngineStructures.sol";
import "src/IRulesEngine.sol";
import "src/effects/EffectProcessor.sol";

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
    mapping (uint256 policyId => RulesStorageStructure.policyStorageStructure) policyStorage;
    // rule Id's to rule storage
    mapping(uint256 ruleId => RulesStorageStructure.ruleStorageStructure) ruleStorage;
    // function Id's to function storage
    mapping(uint256 functionId => RulesStorageStructure.functionSignatureStorageStructure) functionSignatureStorage;
    mapping(address => RulesStorageStructure.foreignCallStorage) foreignCalls;
    mapping(address => RulesStorageStructure.trackerValuesStorage) trackerStorage;

    // Loading helper mappings
    // mapping (bytes => uint256) functionSignatureIdMap;
    // mapping (bytes => uint256[]) signatureToRuleIds;
    RulesStorageStructure.Policy policy;

    uint256 foreignCallIndex;
    uint256 policyId;
    uint256 ruleId;
    uint256 functionSignatureId;

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
     * @param functionSignatureIds corresponding signature ids in the policy
     * @param ruleIds two dimensional array of the rules
     * @return policyId generated policyId
     * @dev The parameters had to be complex because nested structs are not allowed for externally facing functions
     */
    function updatePolicy(uint256 _policyId, bytes[] calldata _signatures, uint256[] calldata functionSignatureIds, uint256[][] calldata ruleIds) public returns(uint256){
        // increment the policyId if necessary
        if (_policyId == 0) {
            policyId+=1;
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
     * Apply the policeis to the contracts.
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
            ruleId+=1;
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
            functionSignatureId+=1;
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
     * @param contractAddress the address of the contract the trackerStorage is associated with
     * @param tracker the tracker to add 
     */
    function addTracker(address contractAddress, RulesStorageStructure.trackers calldata tracker) public {
        trackerStorage[contractAddress].set = true;
        trackerStorage[contractAddress].trackers.push(tracker);
    }

    /**
     * Function to update tracker in trackerStorage mapping.
     * @param contractAddress the address of the contract the function signature is associated with
     * @param updatedUintTracker uint256 tracker update 
     * @param updatedAddressTracker address tracker update 
     * @param updatedStringTracker string tracker update 
     * @param updatedBoolTracker bool tracker update 
     * @param updatedBytesTracker bytes tracker update 
     */
    function updateTracker(address contractAddress, uint256 updatedUintTracker, address updatedAddressTracker, string memory updatedStringTracker, bool updatedBoolTracker, bytes memory updatedBytesTracker) public {
        // Open to feedback on this if there is a better way to update the struct members based on type 
        trackerStorage[contractAddress].set = true;
        for(uint256 i = 0; i < trackerStorage[contractAddress].trackers.length; i++){
            if (trackerStorage[contractAddress].trackers[i].pType == RulesStorageStructure.PT.UINT) trackerStorage[contractAddress].trackers[i].uintTracker = updatedUintTracker;
            if (trackerStorage[contractAddress].trackers[i].pType == RulesStorageStructure.PT.ADDR) trackerStorage[contractAddress].trackers[i].addressTracker = updatedAddressTracker;
            if (trackerStorage[contractAddress].trackers[i].pType == RulesStorageStructure.PT.STR) trackerStorage[contractAddress].trackers[i].stringTracker = updatedStringTracker;
            if (trackerStorage[contractAddress].trackers[i].pType == RulesStorageStructure.PT.BOOL) trackerStorage[contractAddress].trackers[i].boolTracker = updatedBoolTracker;
            if (trackerStorage[contractAddress].trackers[i].pType == RulesStorageStructure.PT.BYTES) trackerStorage[contractAddress].trackers[i].bytesTracker = updatedBytesTracker;
        }
    }

    /**
     * Return a tracker from the trackerStorage.
     * @param contractAddress the address of the contract the trackerStorage is associated with
     * @param index postion of the tracker to return 
     * @return trackers
     */
    function getTracker(address contractAddress, uint256 index) public view returns (RulesStorageStructure.trackers memory trackers) {
        // return trackers for contract address at speficic index  
        return trackerStorage[contractAddress].trackers[index];
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
        return true;
    }

     /**
     * @dev evaluates the conditions associated with all applicable rules and returns the result
     * @param _policyId the address of the rules-enabled contract, used to pull the applicable rules
     * @param contractAddress the address of the rules-enabled contract, used to pull the applicable rules
     * @param functionSignature the signature of the function that initiated the transaction, used to pull the applicable rules.
     * @param arguments function arguments
     */
    function _checkPolicy(uint256 _policyId, address contractAddress, bytes calldata functionSignature, bytes calldata arguments) internal {
        // Decode arguments from function signature
        RulesStorageStructure.PT[] memory functionSignaturePlaceholders;
        // Check to make sure the policy is set
            if(policyStorage[_policyId].set) {
                // Get the function 
                if(functionSignatureStorage[policyStorage[_policyId].policy.functionSignatureIdMap[functionSignature]].set) {
                    functionSignaturePlaceholders = new RulesStorageStructure.PT[](functionSignatureStorage[policyStorage[_policyId].policy.functionSignatureIdMap[functionSignature]].parameterTypes.length);
                    for(uint256 i = 0; i < functionSignaturePlaceholders.length; i++) {
                        functionSignaturePlaceholders[i] = functionSignatureStorage[policyStorage[_policyId].policy.functionSignatureIdMap[functionSignature]].parameterTypes[i];
                    }
                }
            }
            
            RulesStorageStructure.Arguments memory functionSignatureArgs = decodeFunctionSignatureArgs(functionSignaturePlaceholders, arguments);

            RulesStorageStructure.Rule[] memory applicableRules = new RulesStorageStructure.Rule[](policyStorage[_policyId].policy.signatureToRuleIds[functionSignature].length);
            for(uint256 i = 0; i < applicableRules.length; i++) {
                if(ruleStorage[policyStorage[_policyId].policy.signatureToRuleIds[functionSignature][i]].set) {
                    applicableRules[i] = ruleStorage[policyStorage[_policyId].policy.signatureToRuleIds[functionSignature][i]].rule;
                }
            }


            // Retrieve placeHolder[] for specific rule to be evaluated and translate function signature argument array 
            // to rule specific argument array

            for(uint256 i = 0; i < applicableRules.length; i++) { 
                if(!evaluateIndividualRule(applicableRules[i], functionSignatureArgs, contractAddress)) {
                    EffectProcessor(effectProcessor).doEffects(applicableRules[i].negEffects);
                } else{
                    EffectProcessor(effectProcessor).doEffects(applicableRules[i].posEffects);
                }
            }

    }

    /**
     * @dev Decodes the encoded function arguments and fills out an Arguments struct to represent them
     * @param functionSignaturePTs the parmeter types of the arguments in the function in order, pulled from storage
     * @param arguments the encoded arguments 
     * @return functionSignatureArgs the Arguments struct containing the decoded function arguments
     */
    function decodeFunctionSignatureArgs(RulesStorageStructure.PT[] memory functionSignaturePTs, bytes calldata arguments) internal pure returns (RulesStorageStructure.Arguments memory functionSignatureArgs) {
        uint256 placeIter = 32;
        uint256 addressIter = 0;
        uint256 intIter = 0;
        uint256 stringIter = 0;
        uint256 overallIter = 0;
        
        functionSignatureArgs.argumentTypes = new RulesStorageStructure.PT[](functionSignaturePTs.length);
        // Initializing each to the max size to avoid the cost of iterating through to determine how many of each type exist
        functionSignatureArgs.addresses = new address[](functionSignaturePTs.length);
        functionSignatureArgs.ints = new uint256[](functionSignaturePTs.length);
        functionSignatureArgs.strings = new string[](functionSignaturePTs.length);

        for(uint256 i = 0; i < functionSignaturePTs.length; i++) {
            if(functionSignaturePTs[i] == RulesStorageStructure.PT.ADDR) {
                // address data = abi.decode(arguments, (address));
                address data = i == 0 ? abi.decode(arguments[:32], (address)) : abi.decode(arguments[placeIter:(placeIter + 32)], (address));
                if(i != 0) {
                    placeIter += 32;
                }
                functionSignatureArgs.argumentTypes[overallIter] = RulesStorageStructure.PT.ADDR;
                functionSignatureArgs.addresses[addressIter] = data;
                overallIter += 1;
                addressIter += 1;
            } else if(functionSignaturePTs[i] == RulesStorageStructure.PT.UINT) {
                uint256 data = abi.decode(arguments[32:64], (uint256));
                if(i != 0) {
                    placeIter += 32;
                }
                functionSignatureArgs.argumentTypes[overallIter] = RulesStorageStructure.PT.UINT;
                functionSignatureArgs.ints[intIter] = data;
                overallIter += 1;
                intIter += 1;
            } else if(functionSignaturePTs[i] == RulesStorageStructure.PT.STR) {
                string memory data = i == 0 ? abi.decode(arguments[:32], (string)) : abi.decode(arguments[placeIter:(placeIter + 32)], (string));
                if(i != 0) {
                    placeIter += 32;
                }
                functionSignatureArgs.argumentTypes[overallIter] = RulesStorageStructure.PT.STR;
                functionSignatureArgs.strings[stringIter] = data;
                overallIter += 1;
                stringIter += 1;
            }
        }
    }

    /**
     * @dev evaluates an individual rules condition(s)
     * @param applicableRule the rule structure containing the instruction set, with placeholders, to execute
     * @param functionSignatureArgs the values to replace the placeholders in the instruction set with.
     * @return response the result of the rule condition evaluation 
     * TODO: Look into the relationship between policy and foreign calls
     */
    function evaluateIndividualRule(RulesStorageStructure.Rule memory applicableRule, RulesStorageStructure.Arguments memory functionSignatureArgs, address contractAddress) internal returns (bool response) {
        RulesStorageStructure.Arguments memory ruleArgs;
        ruleArgs.argumentTypes = new RulesStorageStructure.PT[](applicableRule.placeHolders.length);
        // Initializing each to the max size to avoid the cost of iterating through to determine how many of each type exist
        ruleArgs.addresses = new address[](applicableRule.placeHolders.length);
        ruleArgs.ints = new uint256[](applicableRule.placeHolders.length);
        ruleArgs.strings = new string[](applicableRule.placeHolders.length);
        uint256 overallIter = 0;
        uint256 addressIter = 0;
        uint256 intIter = 0;
        uint256 stringIter = 0;

        for(uint256 placeholderIndex = 0; placeholderIndex < applicableRule.placeHolders.length; placeholderIndex++) {
            // Determine if the placeholder represents the return value of a foreign call or a function parameter from the calling function
            if(applicableRule.placeHolders[placeholderIndex].foreignCall) {
                // Loop through the foreign call structures associated with the calling contracts address
                for(uint256 foreignCallsIdx = 0; foreignCallsIdx < foreignCalls[contractAddress].foreignCalls.length; foreignCallsIdx++) {
                    // Check if the index for this placeholder matches the foreign calls index
                    if(foreignCalls[contractAddress].foreignCalls[foreignCallsIdx].foreignCallIndex == applicableRule.placeHolders[placeholderIndex].typeSpecificIndex) {
                        // Place the foreign call
                        RulesStorageStructure.ForeignCallReturnValue memory retVal = evaluateForeignCallForRule(foreignCalls[contractAddress].foreignCalls[foreignCallsIdx], applicableRule, functionSignatureArgs);
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
                    }
                }
            } else {
                // Determine if the placeholder represents the return value of a tracker 
                if (applicableRule.placeHolders[placeholderIndex].trackerValue) {
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
                if(applicableRule.placeHolders[placeholderIndex].pType == RulesStorageStructure.PT.ADDR) {
                    ruleArgs.argumentTypes[overallIter] = RulesStorageStructure.PT.ADDR;
                    ruleArgs.addresses[addressIter] = functionSignatureArgs.addresses[applicableRule.placeHolders[placeholderIndex].typeSpecificIndex];
                    overallIter += 1;
                    addressIter += 1;
                } else if(applicableRule.placeHolders[placeholderIndex].pType == RulesStorageStructure.PT.UINT) {
                    ruleArgs.argumentTypes[overallIter] = RulesStorageStructure.PT.UINT;
                    ruleArgs.ints[intIter] = functionSignatureArgs.ints[applicableRule.placeHolders[placeholderIndex].typeSpecificIndex];
                    overallIter += 1;
                    intIter += 1;
                } else if(applicableRule.placeHolders[placeholderIndex].pType == RulesStorageStructure.PT.STR) {
                    ruleArgs.argumentTypes[overallIter] = RulesStorageStructure.PT.STR;
                    ruleArgs.strings[stringIter] = functionSignatureArgs.strings[applicableRule.placeHolders[placeholderIndex].typeSpecificIndex];
                    overallIter += 1;
                    stringIter += 1;
                }
            }
        }
            response = this.run(applicableRule.instructionSet, ruleArgs);
        }
    }

    /**
     * @dev Evaluates the instruction set and returns an answer to the condition
     * @param prog The instruction set, with placeholders, to be run.
     * @param arguments the values to replace the placeholders in the instruction set with.
     * @return ans the result of evaluating the instruction set
     */
    function run(uint256[] calldata prog, RulesStorageStructure.Arguments calldata arguments) public pure returns (bool ans) {
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
     * @param contractAddress the address of the contract the foreign call will be mapped to
     * @param foreignContractAddress the address of the contract where the foreign call exists
     * @param functionSignature the string representation of the function signature of the foreign call
     * @param returnType the parameter type of the foreign calls return value
     * @param arguments the parameter types of the foreign calls arguments in order
     * @return fc the foreign call structure 
     */
    function updateForeignCall(address contractAddress, address foreignContractAddress, string memory functionSignature, RulesStorageStructure.PT returnType, RulesStorageStructure.PT[] memory arguments) public returns (RulesStorageStructure.ForeignCall memory fc) {
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
        if(foreignCalls[contractAddress].set) {
            foreignCalls[contractAddress].foreignCalls.push(fc);
        } else {
            foreignCalls[contractAddress].set = true;
            foreignCalls[contractAddress].foreignCalls.push(fc);
        }
    }

    /**
     * @dev encodes the arguments and places a foreign call, returning the calls return value as long as it is successful
     * @param fc the Foreign Call structure
     * @param rule the Rule that is placing the foreign call
     * @param functionArguments the arguments of the rules calling funciton (to be passed to the foreign call as needed)
     * @return retVal the foreign calls return value
     */
    function evaluateForeignCallForRule(RulesStorageStructure.ForeignCall memory fc, RulesStorageStructure.Rule memory rule, RulesStorageStructure.Arguments memory functionArguments) internal returns (RulesStorageStructure.ForeignCallReturnValue memory retVal) {
        // Arrays used to hold the parameter types and values to be encoded
        uint256[] memory paramTypeEncode = new uint256[](fc.parameterTypes.length);
        uint256[] memory uintEncode = new uint256[](fc.parameterTypes.length);
        address[] memory addressEncode = new address[](fc.parameterTypes.length);
        string[] memory stringEncode = new string[](fc.parameterTypes.length);
        // Iterators for the various types to make sure the correct indexes in each array are populated
        uint256 uintIter = 0;
        uint256 addrIter = 0;
        uint256 strIter = 0;

        // Iterate over the foreign call argument mappings contained within the rule structure
        for(uint256 i = 0; i < rule.fcArgumentMappings.length; i++) {
            // verify this mappings foreign call index matches that of the foreign call structure
            if(rule.fcArgumentMappings[i].foreignCallIndex == fc.foreignCallIndex) {
                // Iterate through the array of mappings between calling function arguments and foreign call arguments
                for(uint256 j = 0; j < rule.fcArgumentMappings[i].mappings.length; j++) {
                    // Check the parameter type and set the values in the encode arrays accordingly 
                    if(rule.fcArgumentMappings[i].mappings[j].functionCallArgumentType == RulesStorageStructure.PT.ADDR) {
                        paramTypeEncode[j] = 1; 
                        addressEncode[addrIter] = functionArguments.addresses[rule.fcArgumentMappings[i].mappings[j].functionSignatureArg.typeSpecificIndex];
                        addrIter += 1;
                    } else if(rule.fcArgumentMappings[i].mappings[j].functionCallArgumentType == RulesStorageStructure.PT.UINT) {
                        paramTypeEncode[j] = 0;
                        uintEncode[uintIter] = functionArguments.ints[rule.fcArgumentMappings[i].mappings[j].functionSignatureArg.typeSpecificIndex];
                        uintIter += 1;
                    } else if(rule.fcArgumentMappings[i].mappings[j].functionCallArgumentType == RulesStorageStructure.PT.STR) {
                        paramTypeEncode[j] = 2;
                        stringEncode[strIter] = functionArguments.strings[rule.fcArgumentMappings[i].mappings[j].functionSignatureArg.typeSpecificIndex];
                        strIter += 1;
                    }
                }
            }
        }

        // Encode the arugments
        bytes memory argsEncoded = assemblyEncode(paramTypeEncode, uintEncode, addressEncode, stringEncode);

        // Build the bytes object with the function selector and the encoded arguments
        bytes memory encoded;
        encoded = bytes.concat(encoded, fc.signature);
        encoded = bytes.concat(encoded, argsEncoded);

        // place the foreign call
        (bool response, bytes memory data) = fc.foreignCallAddress.call(encoded);

        // Verify that the foreign call was successful
        if(response) {
            // Decode the return value based on the specified return value parameter type in the foreign call structure
            if(fc.returnType == RulesStorageStructure.PT.BOOL) {
                retVal.pType = RulesStorageStructure.PT.BOOL;
                retVal.boolValue = abi.decode(data, (bool));
            } else if(fc.returnType == RulesStorageStructure.PT.UINT) {
                retVal.pType = RulesStorageStructure.PT.UINT;
                retVal.intValue = abi.decode(data, (uint256));
            } else if(fc.returnType == RulesStorageStructure.PT.STR) {
                retVal.pType = RulesStorageStructure.PT.STR;
                retVal.str = abi.decode(data, (string));
            } else if(fc.returnType == RulesStorageStructure.PT.ADDR) {
                retVal.pType = RulesStorageStructure.PT.ADDR;
                retVal.addr = abi.decode(data, (address));
            } else if(fc.returnType == RulesStorageStructure.PT.VOID) {
                retVal.pType = RulesStorageStructure.PT.VOID;
            }
        }
    }

    /**
     * @dev Uses assembly to encode a variable length array of variable type arguments so they can be used in a foreign call
     * @param parameterTypes the parameter types of the arguments in order
     * @param ints the uint256 parameters to be encoded
     * @param addresses the address parameters to be encoded
     * @param strings the string parameters to be encoded
     * @return res the encoded arguments
     */
    function assemblyEncode(uint256[] memory parameterTypes, uint256[] memory ints, address[] memory addresses, string[] memory strings) internal pure returns (bytes memory res) {
        uint256 len = parameterTypes.length;
        uint256 strCount = 0;
        uint256 remainingCount = 0;
        uint256[] memory strLengths = new uint256[](strings.length); 
        bytes32[] memory convertedStrings = new bytes32[](strings.length);
        for(uint256 i = 0; i < convertedStrings.length; i++) {
            strLengths[i] = bytes(strings[i]).length;
            convertedStrings[i] = stringToBytes32(strings[i]);
            strCount += 1;
        }
        remainingCount = parameterTypes.length - strCount;

        uint256 strStartLoc = parameterTypes.length;

        assembly {
            // Iterator for the uint256 array
            let intIter := 1
            // Iterator for the address array
            let addrIter := 1
            // Iterator for the string array
            let strIter := 1
            // get free memory pointer
            res := mload(0x40)        
            // set length based on size of parameter array                
            mstore(res, add(mul(0x20, remainingCount), mul(0x60, strCount))) 

            let i := 1
            for {} lt(i, add(len, 1)) {} {
                // Retrieve the next parameter type
                let pType := mload(add(parameterTypes, mul(0x20, i)))

                // If parameter type is integer encode the uint256
                if eq(pType, 0) {
                    let value := mload(add(ints, mul(0x20, intIter)))
                    mstore(add(res, mul(0x20, i)), value)
                    intIter := add(intIter, 1) 
                } 

                // If parameter type is address encode the address
                if eq(pType, 1) {
                    let value := mload(add(addresses, mul(0x20, addrIter)))
                    value := and(value, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
                    mstore(add(res, mul(0x20, i)), value)
                    addrIter := add(addrIter, 1)
                }

                if eq(pType, 2) {
                    mstore(add(res, mul(0x20, i)), mul(0x20, strStartLoc))
                    strStartLoc := add(strStartLoc, 2)
                }

                // Increment global iterators 
                i := add(i, 1)
            }

            let j := 0
            for {} lt(j, strCount) {} {
                let value := mload(add(convertedStrings, mul(0x20, strIter)))
                let leng := mload(add(strLengths, mul(0x20, strIter)))
                mstore(add(res, mul(0x20, i)), leng)   
                mstore(add(res, add(mul(0x20, i), 0x20)), value)
                i := add(i, 1)
                i := add(i, 1)
                strIter := add(strIter, 1)
                j := add(j, 1)
            }
            // update free memory pointer
            mstore(0x40, add(res, mul(0x20, i)))
        }
        
    }

    function stringToBytes32(string memory source) internal pure returns (bytes32 result) {
        assembly {
            result := mload(add(source, 32))
        }
    
}

    function setEffectProcessor(address _address) external {
        effectProcessor = _address;
    }
}
