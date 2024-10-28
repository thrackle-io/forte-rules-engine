// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

enum LC { NUM, ADD, SUB, MUL, DIV, LT, GT, EQ, AND, OR, NOT, PLH }

// Supported Parameter Types
enum PT { ADDR, STR, UINT, BOOL }

/**
 * Structure used to represent the placeholders in the rule instruction set
 * provides the information needed to fill them in with values at run time.
 */
struct Placeholder {
    // The type of parameter the placeholder represents
    PT pType;
    // The index in the specific array for the specified type;
    uint256 typeSpecificIndex;
}

/**
 * Structure used to hold the decoded arguments.
 * Used to hold both the decoded arguments for a function signature in order,
 * and the arguments for a rules placeholders in order.
 */
struct Arguments {
        // Parameter types of arguments in order
        PT[] argumentTypes;
        // Address arguments in order
        address[] addresses;
        // uint256 arguments in order
        uint256[] ints;
        // string arguments in order
        string[] strings;
    }

/**
 * Structure used to represent an individual rule
 */
struct rule {
    // The instruction set that will be run at rule evaluation
    uint256[] instructionSet;
    
    // List of all placeholders used in the rule in order
    // Needs to contain the type, and index (zero based) of the particular type in the function signature 
    // For example if the argument in question is the 2nd address in the function signature the placeHolder would be:
    // pType = parameterType.ADDR index = 1
    Placeholder[] placeHolders;
}