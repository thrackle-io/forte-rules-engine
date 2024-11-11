// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

interface RulesStorageStructure {

    /// Enumerated list of Logical operators used in Rule Engine Run 
    enum LC { NUM, ADD, SUB, MUL, DIV, LT, GT, EQ, AND, OR, NOT, PLH, FC }

    // Supported Parameter Types
    enum PT { ADDR, STR, UINT, BOOL, VOID, BYTES }


    /**
    * Structure used to represent the placeholders in the rule instruction set
    * provides the information needed to fill them in with values at run time.
    */
    struct Placeholder {
        // The type of parameter the placeholder represents
        PT pType;
        // The index in the specific array for the specified type;
        uint256 typeSpecificIndex;
        /// Determine if the index of value to replace the placeholder is a tracker value
        bool trackerValue; 

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

    /**
    * Structure used to store the foreign call sctructs 
    */
    struct foreignCallStorage {
        bool set;
        ForeignCall[] foreignCalls;
    }

    /**
    * Structure to store the rule mappings 
    * Function Signature => Rule Storage Struct 
    * Function Signature => function signature storage 
    */
    struct functionSignatureToRuleMapping {
        bool set;
        mapping (bytes => ruleStorageStructure) ruleMap;
        mapping (bytes => functionSignatureStorage) functionSignatureMap;
    }

    /**
    * Structure to store the parameter types of the function signature 
    */
    struct functionSignatureStorage {
        bool set;
        PT[] parameterTypes;
    }

    /**
    * Structure to store the Rules structs 
    */
    struct ruleStorageStructure {
        bool set;
        Rule[] rules;
    }

    /**
    * Structure to hold Tracker structs 
    */
    struct trackerValuesStorage {
        bool set; 
        trackers[] trackers; 
    }

    /**
    * Structure used to hold the tracker arguments.
    * TrackerValuePositions array is the key for the tracker value mapping positions 
    * Trackers must be initialized with a starting value and are updated outside of the run function. Therefore must have their own persistent storage for setting and getting of tracker values 
    */
    struct trackers {
        // Define what type of tracker
        PT pType; 
        // tracker types arrays 
        uint256 uintTracker; 
        address addressTracker; 
        string stringTracker; 
        bytes bytesTracker; 
        bool boolTracker;

    }

}

// Note this can be removed after documentation is complete 
/**
    Policy: Rules and envoking functions 
        Rules define logic, conditionals and arguments 
            Invoking function passes in arguments data 
                Conditionals are defined in rules 
                Trackers are defined when stored and updated by effects 
                    Rule Processing: 
                    replace all place holder values within run time algorithm 

                    retrieve and replace tracker data 
                    retrieve and replace foreign call data 

                            process rule as run time algorithm 
                                return bool for effects processing 
                        



Rule Conditionals  
            envoking contract addr => rule (will update to policy later)
    mapping(address => RulesStorageStructure.functionSignatureToRuleMapping) ruleStorage;
        struct functionSignatureToRuleMapping {
            bool set;
            mapping (bytes => ruleStorageStructure) ruleMap;
            mapping (bytes => functionSignatureStorage) functionSignatureMap;

                struct ruleStorageStructure {
                    bool set;
                    Rule[] rules;

                        struct Rule {
                            uint256[] instructionSet; <<<<each value coresponds to the LC enum to determine interpretation 
                            Placeholder[] placeHolders; <<< values to replace at run time 

                                struct Placeholder {
                                    PT pType; <<< define the data type of the place holder 
                                    uint256 typeSpecificIndex; <<<where in the array this value is (I believe in the instruction set)
                                }
                        }
                struct functionSignatureStorage {
                    bool set;
                    PT[] parameterTypes;
                }
            }
        }

Trackers 
            envoking contract addr => rule (will update to policy later)
    mapping(address => RulesStorageStructure.trackerValuesStorage) trackerStorage; 
        struct trackerValuesStorage {
            bool set; 
            trackers[] trackers;
                struct trackers {
                    // Define what type of tracker
                    PT pType;  
                    // tracker value mappings 
                    mapping (uint256 => uint256) uintTrackers; 
                    mapping (uint256 => address) addressTrackers; 
                    mapping (uint256 => string) stringTrackers; 
                    mapping (uint256 => bytes) bytesTrackers; 
                    mapping (uint256 => bool) boolTrackers;
                }
        }


Foreign Calls 
            envoking contract addr => foreign call storage (will update to policy later)
    mapping(address => RulesStorageStructure.foreignCallStorage) foreignCalls;
        struct foreignCallStorage {
            bool set;
            ForeignCall[] foreignCalls;
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
        }

Effects 
        

*/
