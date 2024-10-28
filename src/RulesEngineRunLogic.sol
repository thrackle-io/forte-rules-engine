// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "src/RulesEngineStructures.sol";
import {IRulesEngine} from "src/IRulesEngine.sol";

/**
 * @title Rules Engine Run Logic
 * @dev This contract provides the ability to evaluate rules when intiated
 * by a transaction involving a rules-enabled contract
 * @author @mpetersoCode55 
 */
contract RulesEngineRunLogic is IRulesEngine {
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
     * @dev evaluates the conditions associated with all applicable rules and returns the result
     * @param contractAddress the address of the rules-enabled contract, used to pull the applicable rules
     * @param functionSignature the signature of the function that initiated the transaction, used to pull the applicable rules.
     * @return responses the results from evaluating all associated rule conditions (Should be updated to be a single boolean after testing)
     */
    function checkRules(address contractAddress, string calldata functionSignature, bytes calldata arguments) public view returns (uint256[] memory responses) {

        // Decode arguments from function signature
        //-----------------------------------------------------------------------------------------------------------------

        // TODO: Pull function signature struct from storage
        PT[] memory functionSignaturePlaceholders;

        Arguments memory functionSignatureArgs = decodeFunctionSignatureArgs(functionSignaturePlaceholders, arguments);

        //-----------------------------------------------------------------------------------------------------------------

        // TODO: poll mapping for applicable rules based on token address and function signature
        // Loop through the below logic for each rule (each having it's own rulePlaceholders structure pulled from storage) 
        rule[] memory applicableRules = new rule[](1);

        responses = new uint256[](applicableRules.length);

        // Retrieve placeHolder[] for specific rule to be evaluated and translate function signature argument array 
        // to rule specific argument array
        //-----------------------------------------------------------------------------------------------------------------
        for(uint256 i = 0; i < applicableRules.length; i++) {
            responses[i] = evaluateIndividualRule(applicableRules[i], functionSignatureArgs);
        }
        //-----------------------------------------------------------------------------------------------------------------
    }

    /**
     * @dev Decodes the encoded function arguments and fills out an Arguments struct to represent them
     * @param functionSignaturePTs the parmeter types of the arguments in the function in order, pulled from storage
     * @param arguments the encoded arguments 
     * @return functionSignatureArgs the Arguments struct containing the decoded function arguments
     */
    function decodeFunctionSignatureArgs(PT[] memory functionSignaturePTs, bytes calldata arguments) public pure returns (Arguments memory functionSignatureArgs) {
        uint256 placeIter = 32;
        uint256 addressIter = 0;
        uint256 intIter = 0;
        uint256 stringIter = 0;
        uint256 overallIter = 0;
        
        functionSignatureArgs.argumentTypes = new PT[](functionSignaturePTs.length);
        // Initializing each to the max size to avoid the cost of iterating through to determine how many of each type exist
        functionSignatureArgs.addresses = new address[](functionSignaturePTs.length);
        functionSignatureArgs.ints = new uint256[](functionSignaturePTs.length);
        functionSignatureArgs.strings = new string[](functionSignaturePTs.length);

        for(uint256 i = 0; i < functionSignaturePTs.length; i++) {
            if(functionSignaturePTs[i] == PT.ADDR) {
                address data = i == 0 ? abi.decode(arguments[:32], (address)) : abi.decode(arguments[placeIter:32], (address));
                if(i != 0) {
                    placeIter += 32;
                }
                functionSignatureArgs.argumentTypes[overallIter] = PT.ADDR;
                functionSignatureArgs.addresses[addressIter] = data;
                overallIter += 1;
                addressIter += 1;
            } else if(functionSignaturePTs[i] == PT.UINT) {
                uint256 data = i == 0 ? abi.decode(arguments[:32], (uint256)) : abi.decode(arguments[placeIter:32], (uint256));
                if(i != 0) {
                    placeIter += 32;
                }
                functionSignatureArgs.argumentTypes[overallIter] = PT.UINT;
                functionSignatureArgs.ints[intIter] = data;
                overallIter += 1;
                intIter += 1;
            } else if(functionSignaturePTs[i] == PT.STR) {
                string memory data = i == 0 ? abi.decode(arguments[:32], (string)) : abi.decode(arguments[placeIter:32], (string));
                if(i != 0) {
                    placeIter += 32;
                }
                functionSignatureArgs.argumentTypes[overallIter] = PT.STR;
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
    function evaluateIndividualRule(rule memory applicableRule, Arguments memory functionSignatureArgs) public view returns (uint256 response) {
        Arguments memory ruleArgs;
        ruleArgs.argumentTypes = new PT[](applicableRule.placeHolders.length);
        // Initializing each to the max size to avoid the cost of iterating through to determine how many of each type exist
        ruleArgs.addresses = new address[](applicableRule.placeHolders.length);
        ruleArgs.ints = new uint256[](applicableRule.placeHolders.length);
        ruleArgs.strings = new string[](applicableRule.placeHolders.length);
        uint256 overallIter = 0;
        uint256 addressIter = 0;
        uint256 intIter = 0;
        uint256 stringIter = 0;

        for(uint256 i = 0; i < applicableRule.placeHolders.length; i++) {
            if(applicableRule.placeHolders[i].pType == PT.ADDR) {
                ruleArgs.argumentTypes[overallIter] = PT.ADDR;
                ruleArgs.addresses[addressIter] = functionSignatureArgs.addresses[applicableRule.placeHolders[i].typeSpecificIndex];
                overallIter += 1;
                addressIter += 1;
            } else if(applicableRule.placeHolders[i].pType == PT.UINT) {
                ruleArgs.argumentTypes[overallIter] = PT.UINT;
                ruleArgs.ints[intIter] = functionSignatureArgs.ints[applicableRule.placeHolders[i].typeSpecificIndex];
                overallIter += 1;
                intIter += 1;
            } else if(applicableRule.placeHolders[i].pType == PT.STR) {
                ruleArgs.argumentTypes[overallIter] = PT.STR;
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
    function run(uint256[] calldata prog, Arguments calldata arguments) public pure returns (uint256 ans) {
        uint256[64] memory mem;
        uint256 idx = 0;
        uint256 opi = 0;
        while (idx < prog.length) {
            uint256 v = 0;
            LC op = LC(prog[idx]);

            if(op == LC.PLH) {
                // Placeholder format will be:
                // PLH, arguments array index, argument type specific array index
                // For example if the Placeholder is the 3rd argument in the function signature, which is the first address type argument:
                // PLH, 2, 0
                uint256 pli = prog[idx+1];
                uint256 spci = prog[idx+2];
                PT typ = arguments.argumentTypes[pli];
                if(typ == PT.ADDR) {
                    // Convert address to uint256 for direct comparison using == and != operations
                    v = uint256(uint160(arguments.addresses[spci])); idx += 3;
                } else if(typ == PT.UINT) {
                    v = arguments.ints[spci]; idx += 3;
                } else if(typ == PT.STR) {
                    // Convert string to uint256 for direct comparison using == and != operations
                    v = uint256(keccak256(abi.encode(arguments.strings[spci]))); idx += 3;
                }
            }

            if (op == LC.NUM) { v = prog[idx+1]; idx += 2; }
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
        return mem[opi - 1];
    }
}