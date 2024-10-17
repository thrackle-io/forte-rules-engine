// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/** 
 * Structure that makes up the components of an individual expression
 */
struct ExpressionComponents {
    string[] operands;
    string[] operators;
}

/**
 * Structure for the individual expressions
 */
struct Expression {
    string lhs;
    ExpressionComponents lhsComp;
    string comparator;
    string rhs;
    ExpressionComponents rhsComp;
}

/**
 * Structure for the individual effects
 */
struct Effect {
    string effect;
}

/**
 * Structure for the information provided with the transaction
 */
struct TransactionInfo {
    address tokenAddress;
    string functionSignature;
    address senderAddress;
    address receiverAddress;
}

/** 
 * Structure to hold the inner map 
 * inner map consists of triggers (function signatures) mapped to an array of rules
 */
struct innerMapping {
    bool hasBeenSet;
    mapping ( string => ruleStorage) rules;
}

/** 
 * Structure to hold the array of rules in the inner map
 */
struct ruleStorage {
    bool hasBeenSet;
    Rule[] rules;
}

/**
 * @title Structure to hold an individual rule
 * @author @mpetersoCode55
 */
contract Rule {
    Expression[] expressions;
    string expressionLogicalStructure;
    string triggerType;
    Effect[] effects;

    function getExpressions() public view returns (Expression[] memory) {
        return expressions;
    }


    function addExpression(Expression memory exp) public {
        expressions.push(exp);
    }

    function setTriggerType(string memory str) public {
        triggerType = str;
    }

    function setLogicalStructure(string memory str) public {
        expressionLogicalStructure = str;
    }

    function getLogicalStructure() public view returns (string memory) {
        return expressionLogicalStructure;
    }

    function addEffect(Effect memory effect) public {
        effects.push(effect);
    }
}