// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

struct InitializedS {
    bool initialized;
}


/// Enumerated list of Logical operators used in Rule Engine Run
/**
 * NUM - a static value will be in the next slot in the instruction set
 * ADD - add the values at the memory addresses denoted by the next two slots in the instruction set
 * SUB - subtract the values at the memory addresses denoted by the next two slots in the instruction set
 * MUL - multiply the values at the memory addresses denoted by the next two slots in the instruction set
 * DIV - divide the values at the memory addresses denoted by the next two slots in the instruction set
 * LT - perform a less than comparison with the values at the memory addresses denoted by the next two slots in the instruction set
 * GT - perform a greater than comparison with the values at the memory addresses denoted by the next two slots in the instruction set
 * EQ - perform a equals comparison with the values at the memory addresses denoted by the next two slots in the instruction set
 * AND - perform a logical AND with the values at the memory addresses denoted by the next two slots in the instruciton set
 * OR - perform a logical OR with the values at the memory addresses denoted by the next two slots in the instruction set
 * NOT - perform a logical NOT with the value at the memory address denoted by the next slot in the instruction set
 * PLH - insert a placeholder value into the next memory slot
 * TRU - perform a tracker update, the next two slots in the instruction set will denote the tracker index to update and the memory address of the value to use.
 */
enum LC {
    NUM,
    ADD,
    SUB,
    MUL,
    DIV,
    LT,
    GT,
    EQ,
    AND,
    OR,
    NOT,
    PLH,
    TRU
}

// Supported Parameter Types
enum PT {
    ADDR,
    STR,
    UINT,
    BOOL,
    VOID,
    BYTES
}
/// Effect Storage Structures
// Supported Effect Types
enum ET {
    REVERT,
    EVENT,
    EXPRESSION
}

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

// Effect Events
event RulesEngineEvent(string _message);

// Effect Structure
struct Effect {
    bool valid;
    ET effectType;
    string text; //used for any type of text(revert, event, etc.)
    // The instruction set that will be run at effect execution
    uint256[] instructionSet;
}

/// Foreign Call Structures
struct ForeignCallS {
    uint256 foreignCallIndex;
    mapping(uint256 policyId => ForeignCallSet) foreignCallSets;
}

struct ForeignCallSet {
    bool set;
    ForeignCall[] foreignCalls;
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
 * Structure used to represent the return value of a Foreign Call
 */
struct ForeignCallReturnValue {
    // Parameter type of the return value
    PT pType;
    // The actual value of the return value
    bytes value;
}

/**
 * Structure used to hold the decoded arguments.
 * Used to hold both the decoded arguments for a function signature in order,
 * and the arguments for a rules placeholders in order.
 */
struct Arguments {
    // Parameter types of arguments in order
    PT[] argumentTypes;
    // The actual values of the arguments in order
    bytes[] values;
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

/// Tracker Structures
struct TrackerS {
    uint256 TrackerIndex;
    mapping(uint256 policyId => TrackerValuesSet) trackerValueSets;
}

/**
 * Structure to hold Tracker structs
 */
struct TrackerValuesSet {
    bool set;
    Trackers[] trackers;
}

/**
 * Structure used to hold the tracker arguments.
 * TrackerValuePositions array is the key for the tracker value mapping positions
 * Trackers must be initialized with a starting value and are updated outside of the run function. Therefore must have their own persistent storage for setting and getting of tracker values
 */
struct Trackers {
    // Define what type of tracker
    PT pType;
    // tracker types arrays
    bytes trackerValue;
    // to be added: uint lastUpdatedTimestamp;
}

/// Function Signature Structures
struct FunctionSignatureS {
    uint256 functionId;
    mapping(uint256 functionId => FunctionSignatureStorageSet) functionSignatureStorageSets;
}

struct FunctionSignatureStorageSet {
    bool set;
    bytes4 signature;
    PT[] parameterTypes;
}

/// Rule Structures
struct RuleS {
    uint256 ruleId;
    mapping(uint256 ruleId => RuleStorageSet) ruleStorageSets;
}

/**
 * Structure to store the Rules structs
 */
struct RuleStorageSet {
    bool set;
    Rule rule;
}

/**
 * Structure used to represent an individual rule
 */
struct Rule {
    // The instruction set that will be run at rule evaluation
    uint256[] instructionSet;
    // The raw format string and addresses for values in the instruction set that have already been converted to uint256.
    RawData rawData;
    // List of all placeholders used in the rule in order
    // Needs to contain the type, and index (zero based) of the particular type in the function signature
    // For example if the argument in question is the 2nd address in the function signature the placeHolder would be:
    // pType = parameterType.ADDR index = 1
    Placeholder[] placeHolders;
    Placeholder[] effectPlaceHolders;
    // Mapping between the Foreigns Calls arguments and the arguments of the function signature and/or trackers this rule is associated with
    // (for foreign calls used in the rules condition evaluation)
    ForeignCallArgumentMappings[] fcArgumentMappingsConditions;
    // Mapping between the Foreigns Calls arguments and the arguments of the function signature and/or trackers this rule is associated with
    // (for foreign calls used in the rules effect execution)
    ForeignCallArgumentMappings[] fcArgumentMappingsEffects;
    // List of all positive effects
    Effect[] posEffects;
    // List of all positive effects
    Effect[] negEffects;
}

// This struct will hold the raw form of strings and addresses that were submitted to the SDK
struct RawData {
    // The index in the instruction set that contains the "converted" version of this data (converted to uint256)
    uint256[] instructionSetIndex;
    // The types for the data values in order (to aid with decoding them)
    PT[] argumentTypes;
    // The data (encoded using the viem equivalent of abi.encode, encoded types capture in argumentTypes in order)
    bytes[] dataValues;
}

// Contains the "converted" uint256 value and the stored original string value for comparison to make sure the conversion can be replicated.
struct StringVerificationStruct {
    // The "converted" value that exists in the instruction set.
    uint256 instructionSetValue;
    // The raw string value that has been stored with the rule.
    string rawData;
}

// Contains the "converted" uint256 value and the stored original address value for comparison to make sure the conversion can be replicated.
struct AddressVerificationStruct {
    // The "converted" value that exists in the instruction set.
    uint256 instructionSetValue;
    // The raw address value that has been stored with the rule.
    address rawData;
}

/// POLICY Storage Structures
struct PolicyS {
    uint256 policyId;
    mapping(uint256 policyId => PolicyStorageSet) policyStorageSets;
}

// Policy storage with set
struct PolicyStorageSet {
    bool set;
    Policy policy;
}

struct Policy {
    // function signatures to function signature Id
    mapping(bytes => uint256) functionSignatureIdMap;
    // function signatures to ruleIds
    mapping(bytes => uint256[]) signatureToRuleIds;
    // Array to hold the function sigs for iterating
    bytes[] signatures;
}

/// Policy Association Storage Structures
struct PolicyAssociationS {
    mapping(address contractAddress => uint256[]) contractPolicyIdMap;
}


