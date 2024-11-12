// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface RulesStorageStructure {

    enum LC { NUM, ADD, SUB, MUL, DIV, LT, GT, EQ, AND, OR, NOT, PLH, FC }

    // Supported Parameter Types
    enum PT { ADDR, STR, UINT, BOOL, VOID }

    /**
    * Structure used to represent the placeholders in the rule instruction set
    * provides the information needed to fill them in with values at run time.
    */
    struct Placeholder {
        // The type of parameter the placeholder represents
        PT pType;
        // The index in the specific array for the specified type;
        uint256 typeSpecificIndex;
        // Used to determine whether this Placeholder represents the value returned from a foreign call
        bool foreignCall;
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
    struct Rule {
        // The instruction set that will be run at rule evaluation
        uint256[] instructionSet;
        
        // List of all placeholders used in the rule in order
        // Needs to contain the type, and index (zero based) of the particular type in the function signature 
        // For example if the argument in question is the 2nd address in the function signature the placeHolder would be:
        // pType = parameterType.ADDR index = 1
        Placeholder[] placeHolders;

        // Mapping between the Foreigns Calls arguments and the arguments of the function signature this rule is associated with
        ForeignCallArgumentMappings[] fcArgumentMappings;
        // List of all positive effects
        uint256[] posEffects;
        // List of all positive effects
        uint256[] negEffects;
    }

   /**
    * Structure used to represent the return value of a Foreign Call
    */
    struct ForeignCallReturnValue {
        // Parameter type of the return value
        PT pType;
        // Set if Parameter type is address
        address addr;
        // Set if Parameter type is string
        string str;
        // Set if Parameter type is int
        uint256 intValue;
        // Set if Parameter type is bool
        bool boolValue;
    }


    /**
     * Structure used to represent the mapping of arguments between a Rules 
     * Function Call Arguments and the Foreign Calls Arguments.
     */
    struct ForeignCallArgumentMappings {
        // Index of the foreign call structure 
        uint256 foreignCallIndex;
        // Mappings of individual arguments (Function Signature -> Foreign Call)
        IndividualArgumentMapping[] mappings;
    }

    /**
     * Structure to represent the mapping of an individual argument between a 
     * Rules Function Call Argument and a Foreign Call Argument.
     */
    struct IndividualArgumentMapping {
        // The Parameter Type of the Function Call Argument
        PT functionCallArgumentType;
        // The Argument information for the Function Call Argument
        Placeholder functionSignatureArg;
    }

    /**
     * Structure used to represent a foreign call that can be made during rule evaluation
     */
    struct ForeignCall {
        // Address of the contract to make the call to
        address foreignCallAddress;
        // Unique identifier for the foreign contract structure (used by the rule to reference it)
        uint256 foreignCallIndex;
        // The function signature of the foreign call
        bytes4 signature;
        // The parameter type of the foreign calls return
        PT returnType;
        // The parameter types of the arguments the foreign call takes
        PT[] parameterTypes;
    }

    struct functionSignatureToRuleMapping {
        bool set;
        mapping (bytes => ruleStorageStructure) ruleMap;
        mapping (bytes => functionSignatureStorage) functionSignatureMap;
    }

    struct functionSignatureStorage {
        bool set;
        PT[] parameterTypes;
    }

    struct ruleStorageStructure {
        bool set;
        Rule[] rules;
    }

    struct foreignCallStorage {
        bool set;
        ForeignCall[] foreignCalls;
    }

}