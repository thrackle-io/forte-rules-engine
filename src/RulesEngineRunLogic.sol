// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "src/RulesEngineStructures.sol";
import "src/IRulesEngine.sol";

/**
 * @title Rules Engine Run Logic
 * @dev This contract provides the ability to evaluate rules when intiated
 * by a transaction involving a rules-enabled contract
 * @author @mpetersoCode55 
 */
contract RulesEngineRunLogic is IRulesEngine {

    mapping(address => RulesStorageStructure.functionSignatureToRuleMapping) ruleStorage;

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
     * Add a rule to the ruleStorage mapping.
     * @param contractAddress the address of the contract the rule is associated with
     * @param functionSignature the string representation of the function signature the rule is associated with
     * @param rule the rule to add 
     */
    function addRule(address contractAddress, bytes calldata functionSignature, RulesStorageStructure.Rule calldata rule) public {
        if(ruleStorage[contractAddress].set) {
            RulesStorageStructure.functionSignatureToRuleMapping storage topLayerMap = ruleStorage[contractAddress];
            if(topLayerMap.ruleMap[functionSignature].set) {
                RulesStorageStructure.ruleStorageStructure storage innerMap = topLayerMap.ruleMap[functionSignature];
                innerMap.rules.push(rule);
            } else {
                topLayerMap.ruleMap[functionSignature].set = true;
                topLayerMap.ruleMap[functionSignature].rules.push(rule);
            }
        } else {
            ruleStorage[contractAddress].set = true;
            ruleStorage[contractAddress].ruleMap[functionSignature].set = true;
            ruleStorage[contractAddress].ruleMap[functionSignature].rules.push(rule); 
        }
    }

    /**
     * Add a function signature to the ruleStorage mapping.
     * @param contractAddress the address of the contract the function signature is associated with
     * @param functionSignature the string representation of the function signature
     * @param pTypes the types of the parameters for the function in order 
     */
    function addFunctionSignature(address contractAddress, bytes calldata functionSignature, RulesStorageStructure.PT[] memory pTypes) public {
        if(ruleStorage[contractAddress].set) {
            RulesStorageStructure.functionSignatureToRuleMapping storage topLayerMap = ruleStorage[contractAddress];
            if(topLayerMap.functionSignatureMap[functionSignature].set) {
                RulesStorageStructure.functionSignatureStorage storage innerMap = topLayerMap.functionSignatureMap[functionSignature];
                for(uint256 i = 0; i < pTypes.length; i++) {
                    innerMap.parameterTypes.push(pTypes[i]);
                }
            } else {
                topLayerMap.functionSignatureMap[functionSignature].set = true;
                for(uint256 i = 0; i < pTypes.length; i++) {
                    topLayerMap.functionSignatureMap[functionSignature].parameterTypes.push(pTypes[i]);
                }
            }
        } else {
            ruleStorage[contractAddress].set = true;
            ruleStorage[contractAddress].functionSignatureMap[functionSignature].set = true;
            for(uint256 i = 0; i < pTypes.length; i++) {
                ruleStorage[contractAddress].functionSignatureMap[functionSignature].parameterTypes.push(pTypes[i]); 
            }
        }
    }

    /**
     * @dev evaluates the conditions associated with all applicable rules and returns the result
     * @param contractAddress the address of the rules-enabled contract, used to pull the applicable rules
     * @param functionSignature the signature of the function that initiated the transaction, used to pull the applicable rules.
     */
    function checkRules(address contractAddress, bytes calldata functionSignature, bytes calldata arguments) public view returns (bool) {

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
        
        RulesStorageStructure.Arguments memory functionSignatureArgs = decodeFunctionSignatureArgs(functionSignaturePlaceholders, arguments);

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
            if(!evaluateIndividualRule(applicableRules[i], functionSignatureArgs)) {
                return false;
            }
        }
        return true;
    }

    /**
     * @dev Decodes the encoded function arguments and fills out an Arguments struct to represent them
     * @param functionSignaturePTs the parmeter types of the arguments in the function in order, pulled from storage
     * @param arguments the encoded arguments 
     * @return functionSignatureArgs the Arguments struct containing the decoded function arguments
     */
    function decodeFunctionSignatureArgs(RulesStorageStructure.PT[] memory functionSignaturePTs, bytes calldata arguments) public pure returns (RulesStorageStructure.Arguments memory functionSignatureArgs) {
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
     */
    function evaluateIndividualRule(RulesStorageStructure.Rule memory applicableRule, RulesStorageStructure.Arguments memory functionSignatureArgs) public view returns (bool response) {
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

        for(uint256 i = 0; i < applicableRule.placeHolders.length; i++) {
            if(applicableRule.placeHolders[i].pType == RulesStorageStructure.PT.ADDR) {
                ruleArgs.argumentTypes[overallIter] = RulesStorageStructure.PT.ADDR;
                ruleArgs.addresses[addressIter] = functionSignatureArgs.addresses[applicableRule.placeHolders[i].typeSpecificIndex];
                overallIter += 1;
                addressIter += 1;
            } else if(applicableRule.placeHolders[i].pType == RulesStorageStructure.PT.UINT) {
                ruleArgs.argumentTypes[overallIter] = RulesStorageStructure.PT.UINT;
                ruleArgs.ints[intIter] = functionSignatureArgs.ints[applicableRule.placeHolders[i].typeSpecificIndex];
                overallIter += 1;
                intIter += 1;
            } else if(applicableRule.placeHolders[i].pType == RulesStorageStructure.PT.STR) {
                ruleArgs.argumentTypes[overallIter] = RulesStorageStructure.PT.STR;
                ruleArgs.strings[stringIter] = functionSignatureArgs.strings[applicableRule.placeHolders[i].typeSpecificIndex];
                overallIter += 1;
                stringIter += 1;
            }
        }

        response = this.run(applicableRule.instructionSet, ruleArgs);
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

       function assemblyEncode(uint256[] memory parameterTypes, uint256[] memory ints, address[] memory addresses, string[] memory strings) public pure returns (bytes memory res) {
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

    function stringToBytes32(string memory source) public pure returns (bytes32 result) {
        assembly {
            result := mload(add(source, 32))
        }
    }
}