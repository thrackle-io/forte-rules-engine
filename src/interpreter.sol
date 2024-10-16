// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "lib/solady/src/utils/LibString.sol";
import "src/RuleLib.sol";


/**
 * @title Interpreter
 * @author @mpetersoCode55
 */
contract Interpreter {
    using LibString for *;

    mapping ( address => innerMapping) rules;

    /**
     * @dev retrieves all of the rules associated with a tokenAddress and trigger
     * @param tokenAddress the tokenAddress the rules are mapped to
     * @param trigger the trigger (function signature) the rules are mapped to
     */
    function getRules(address tokenAddress, string memory trigger) public view returns (Rule[] memory) {
        return rules[tokenAddress].rules[trigger].rules;
    }

    /**
     * @dev Build a Rule structure from the string and add it to the mapping
     * @param syntax the string to interpret
     * @param tokenAddress the address of the token the rule is mapped to
     */
    function interpretSyntaxRule(string calldata syntax, address tokenAddress) public {
        string[] memory initial = RuleLib.splitString(syntax, " --> ");
        Rule rule = new Rule();
        rule.setTriggerType(initial[2]);

        RuleLib.parseExpressions(rule, initial[0]);
        RuleLib.parseEffects(rule, initial[1]);

        pushRule(tokenAddress, initial[2], rule);
    }

    /**
     * @dev push the rule structure into the mapping
     * @param tokenAddress address of the token for the top level mapping
     * @param trigger function signature for the second level mapping
     * rule the Rule structure to add to the mapping
     */
    function pushRule(address tokenAddress, string memory trigger, Rule rule) public {
        ruleStorage memory ruleSt;
        ruleSt.hasBeenSet = true;
        ruleSt.rules = new Rule[](1);
        ruleSt.rules[0] = rule;
        if(rules[tokenAddress].hasBeenSet) {
            if(rules[tokenAddress].rules[trigger].hasBeenSet) {
                rules[tokenAddress].rules[trigger].rules.push(rule);
            } else {
                rules[tokenAddress].rules[trigger] = ruleSt;
            }
        } else {
            rules[tokenAddress].rules[trigger] = ruleSt;
            rules[tokenAddress].hasBeenSet = true;
        }
    }

    /**
     * @dev check all rules that apply to the transaction
     * @param transactionInfo the additional information provided about the transaction that initiated the rule check
     */
    function checkRule(TransactionInfo memory transactionInfo) public returns (bool) {

        Rule[] memory setRules = getRules(transactionInfo.tokenAddress, transactionInfo.functionSignature);

        for(uint256 i = 0; i < setRules.length; i++) {
            Rule retVal = setRules[i];
            bool[] memory values = new bool[](retVal.getExpressions().length);
            for(uint256 j = 0; j < retVal.getExpressions().length; j++) {
                uint256 leftHandValue = RuleLib.determineOperationValue(retVal.getExpressions()[j].lhsComp, transactionInfo);
                uint256 rightHandValue = RuleLib.determineOperationValue(retVal.getExpressions()[j].rhsComp, transactionInfo);

                if(retVal.getExpressions()[j].comparator.contains("==")) {
                    values[j] = (leftHandValue == rightHandValue);
                }

            }
            //TODO: use logical structure to determine if overall expression true or false
            for(uint256 j = 0; j < values.length; j++) {
                if(!values[j]) {
                    return false;
                }
            }
        }

        return true;
    }

}