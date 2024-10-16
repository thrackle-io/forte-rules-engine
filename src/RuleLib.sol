// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "lib/solady/src/utils/LibString.sol";
import "src/Rule.sol";

/**
 * @title Library for converting rule strings to Rule structs
 * @author @mpetersoCode55 
 * @dev Converts strings in the Rules Engine Syntax into the Rule struct defined in Rule.sol
 */
library RuleLib {
    // using strings for *;
    using LibString for *;

    /**
     * @dev Parses the expressions from the string and fills in the expression structures
     * @param rule the Rule structure currently being modified
     * @param expressions the expressions portion of the original full Rules Engine Syntax string
     */
    function parseExpressions(Rule rule, string memory expressions) public {
        // Parse individual expressions
        //-------------------------------------------------------------------------
        // Remove brackets [] from expressions statement
        string memory noParentheses = removeBrackets(expressions);
        // Create an array of the expressions that have been AND'd together
        string[] memory withoutANDs = splitString(noParentheses, " AND ");

        // // Further refine the array to separate expressions that have been OR'd together
        string memory orDelimiter = " OR ";
        uint256 countA = noParentheses.indicesOf(" OR ").length;
        // uint256 countA = noParentheses.toSlice().count(orDelimiter.toSlice());

        bytes[] memory culm = new bytes[](withoutANDs.length + countA);
        uint256 index = 0;
        for(uint256 i = 0; i < withoutANDs.length; i++) {
            string[] memory withoutORs = splitString(withoutANDs[i], " OR ");
            
            for(uint256 j = 0; j < withoutORs.length; j++) {
                culm[index] = abi.encodePacked(withoutORs[j]);
                index += 1;
            }
        }

        string[] memory expressionArray = new string[](culm.length);
        for(uint256 i = 0; i < culm.length; i++) {
            expressionArray[i] = string(culm[i]);
        }

        // Parse each individual expression
        for(uint256 i = 0; i < expressionArray.length; i++) {
            // strings.slice memory s = expressionArray[i].toSlice();  
            if(expressionArray[i].contains("== ")) {
                string[] memory split = splitString(expressionArray[i], "== ");
                if(split.length == 2) {
                    Expression memory exp;
                    exp.lhs = split[0];
                    exp.rhs = split[1];
                    exp.comparator = "==";
                    exp.lhsComp = buildExpressionComponents(exp.lhs);
                    exp.rhsComp = buildExpressionComponents(exp.rhs);
                    rule.addExpression(exp);
                }
            } else if(expressionArray[i].contains("> ")) {
                string[] memory split = splitString(expressionArray[i], "> ");
                if(split.length == 2) {
                    Expression memory exp;
                    exp.lhs = split[0];
                    exp.rhs = split[1];
                    exp.comparator = ">";
                    exp.lhsComp = buildExpressionComponents(exp.lhs);
                    exp.rhsComp = buildExpressionComponents(exp.rhs);
                    rule.addExpression(exp);
                }
            }
        }
        //-------------------------------------------------------------------------


        // Parse the overall logical structure of the expression statement
        //-------------------------------------------------------------------------
        string memory finalLogical = expressions;

        for(uint256 i = 0; i < expressionArray.length; i++) {
            finalLogical = finalLogical.replace(expressionArray[i], i.toString());
        }  
        rule.setLogicalStructure(finalLogical);
        //-------------------------------------------------------------------------
    }

    /**
     * @dev Parses the effects from the string and fills in the effects structures
     * @param rule the Rule structure currently being modified
     * @param effects the effects portion of the original full Rules Engine Syntax string
     */
    function parseEffects(Rule rule, string memory effects) public {
        string[] memory effectsWithoutANDs = splitString(effects, " AND ");
        for (uint256 i = 0; i < effectsWithoutANDs.length; i++) {
            Effect memory effect;
            effect.effect = effectsWithoutANDs[i];
            rule.addEffect(effect);
        }
    } 

    /**
     * @dev builds the Expression component structure for each individual operand (lhs and rhs)
     * @param operand the string representation of the operand to be parsed
     */
    function buildExpressionComponents(string memory operand) public pure returns (ExpressionComponents memory) {
            uint256 value = 0;
            string[] memory plusSplit = splitString(operand, " + ");
            uint256 countA = operand.indicesOf(" - ").length;
            uint256 countB = operand.indicesOf(" * ").length;
            uint256 countC = operand.indicesOf(" / ").length;
            bytes[] memory culmination = new bytes[](plusSplit.length + countA + countB + countC);
            uint256 index = 0;
            for(uint256 i = 0; i < plusSplit.length; i++) {
                string[] memory minusSplit = splitString(plusSplit[i], " - ");
            
                for(uint256 j = 0; j < minusSplit.length; j++) {
                    string[] memory multiSplit = splitString(minusSplit[j], " * ");

                    for(uint256 k = 0; k < multiSplit.length; k++) {
                        string[] memory divSplit = splitString(multiSplit[k], " / ");

                        for(uint256 l = 0; l < divSplit.length; l++) {
                            culmination[index] = abi.encodePacked(divSplit[l]);
                            index += 1;
                        }
                    }
                }
            }

        ExpressionComponents memory components;

        components.operands = new string[](culmination.length);
        for(uint256 i = 0; i < culmination.length; i++) {
            components.operands[i] = string(culmination[i]);
        }     

        //determine operators (in order)

        uint256 count = operand.indicesOf('+').length;
        count += operand.indicesOf('-').length;
        count += operand.indicesOf('*').length;
        count += operand.indicesOf('/').length;
        components.operators = new string[](count);
        uint256 opIndex = 0;
        bytes memory sBytes = bytes(operand);
        for(uint256 i = 0; i < sBytes.length; i++) {
            if(sBytes[i] == '+') {
                components.operators[opIndex] = '+';
                opIndex += 1;
            } else if(sBytes[i] == '-') {
                components.operators[opIndex] = '-';
                opIndex += 1;
            } else if(sBytes[i] == '*') {
                components.operators[opIndex] = '*';
                opIndex += 1;
            } else if(sBytes[i] == '/') {
                components.operators[opIndex] = '/';
                opIndex += 1;
            }
        }
        return components;
    }

    /**
     * @dev determine the integer value of an ExpressionComponent 
     * @param components the ExpressionComponents structure to determine the value of
     * @param transactionInfo the additional information provided about the transaction
     */
    function determineOperationValue(ExpressionComponents memory components, TransactionInfo memory transactionInfo) public returns (uint256) {
        uint256[] memory values = determineOperandValue(components.operands);
        // Loop through operators and equate 
        // Current deficiency evaluating left to right, not accounting for PEMDAS or []
        uint256 initialValue = values[0];
        uint256 equationIndex = 1;
        for(uint256 i = 0; i < components.operators.length; i++) {
            if(components.operators[i].eq('+')) {
                initialValue += values[equationIndex];
            } else if(components.operators[i].eq('-')) {
                initialValue -= values[equationIndex];
            } else if(components.operators[i].eq('*')) {
                initialValue *= values[equationIndex];
            } else if(components.operators[i].eq('/')) {
                initialValue /= values[equationIndex];
            }

            equationIndex += 1;
        }

        return initialValue;

    }

    /**
     * @dev determine the value of the operands used in an operation
     * @param operands the string representation of all of the operands in the operation
     */
    function determineOperandValue(string[] memory operands) public returns (uint256[] memory) {
        uint256[] memory retVal = new uint256[](operands.length);

        for(uint256 i = 0; i < operands.length; i++) {
            if(operands[i].contains("FC:")) {

            } else if(operands[i].contains("TR:")) {

            } else if(operands[i].eq("senderAddress")) {

            } else {
                retVal[i] = stringToUint(operands[i]);
            }
        }

        return retVal;
    }

    // Utility Functions
    //-----------------------------------------------------------------------------------------------------------

    /** 
     * @dev returns the same string with all brackets [] removed
     * @param toModify the string to modify
     */
    function removeBrackets(string memory toModify) public pure returns (string memory) {
        string[] memory withoutOpening = splitString(toModify, "[");
        string memory withoutOpeningCombined = "";
        for(uint256 i = 0; i < withoutOpening.length; i++) {
            withoutOpeningCombined = string(abi.encodePacked(withoutOpeningCombined, withoutOpening[i]));        
        }

        string[] memory withoutEither = splitString(withoutOpeningCombined, "]");
        string memory retVal = "";
        for(uint256 i = 0; i < withoutEither.length; i++) {
            retVal = string(abi.encodePacked(retVal, withoutEither[i]));        
        }
        return retVal;
    }

    /**
     * @dev splits a string into an array of strings based on the specified delimiter
     * @param toSplit the string to split
     * @param delimiter the delimiter to split the string by
     */
    function splitString(string memory toSplit, string memory delimiter) public pure returns(string[] memory) {                                                
        if(toSplit.contains(delimiter)) {
            return toSplit.split(delimiter);
        } else {
            string[] memory parts = new string[](1);
            parts[0] = toSplit;
            return parts;
        }                              
    } 

    /**
     * @dev convert a string representation of an integer to a uint
     * @param s the string to convert
     */
    function stringToUint(string memory s) public pure returns (uint) {
        bytes memory b = bytes(s);
        uint result = 0;
        for (uint256 i = 0; i < b.length; i++) {
            uint256 c = uint256(uint8(b[i]));
            if (c >= 48 && c <= 57) {
                result = result * 10 + (c - 48);
            }
        }
        return result;
    }
}