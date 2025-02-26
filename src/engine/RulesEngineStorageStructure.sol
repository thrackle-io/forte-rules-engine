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
    BYTES,
    STATIC_TYPE_ARRAY,
    DYNAMIC_TYPE_ARRAY
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
    uint128 typeSpecificIndex;
    /// Determine if the index of value to replace the placeholder is a tracker value
    bool trackerValue;
    // Used to determine whether this Placeholder represents the value returned from a foreign call
    bool foreignCall;
}

// Effect Events
event RulesEngineEvent(uint256 indexed _eventKey, bytes32 _eventString, string _message);
event RulesEngineEvent(uint256 indexed _eventKey, bytes32 _eventString, bytes32 _bytes);
event RulesEngineEvent(uint256 indexed _eventKey, bytes32 _eventString, uint256 indexed _num);
event RulesEngineEvent(uint256 indexed _eventKey, bytes32 _eventString, address indexed _address);
event RulesEngineEvent(uint256 indexed _eventKey, bytes32 _eventString, bool indexed _bool);

// Effect Structure
struct Effect {
    bool valid;
    bool dynamicParam; //bool to determine if event requires  
    ET effectType;
    // event data 
    PT pType;
    bytes param;
    bytes32 text; // This is used by events to "Name" the event. It is an unindexed bytes32 param in RulesEngineEvent: _eventString. Bytes32 is used to reduce gas costs
    string errorMessage;
    // The instruction set that will be run at effect execution
    uint256[] instructionSet;    
}

/// Foreign Call Structures
struct ForeignCallS {
    mapping(uint256 policyId => uint256) foreignCallIdxCounter;
    mapping(uint256 policyId => mapping(uint256 foreignCallIndex => ForeignCall)) foreignCalls;
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
 * Structure used to represent a foreign call that can be made during rule evaluation
 */
struct ForeignCall {
    bool set;
    // Address of the contract to make the call to
    address foreignCallAddress;
    // The function signature of the foreign call
    bytes4 signature;
    // The parameter type of the foreign calls return
    PT returnType;
    // Unique identifier for the foreign contract structure (used by the rule to reference it)
    uint256 foreignCallIndex;
    // The parameter types of the arguments the foreign call takes
    PT[] parameterTypes;
    // A list of type specific indices to use for the foreign call and where they sit in the calldata
    uint8[] typeSpecificIndices;
}

/// Tracker Structures
struct TrackerS {
    //uint256 TrackerIndex;
    mapping(uint256 policyId => uint256 trackerIndex) trackerIndexCounter;
    mapping(uint256 policyId => mapping(uint256 trackerIndex => Trackers)) trackers;
}

/**
 * Structure used to hold the tracker arguments.
 * TrackerValuePositions array is the key for the tracker value mapping positions
 * Trackers must be initialized with a starting value and are updated outside of the run function. Therefore must have their own persistent storage for setting and getting of tracker values
 */
struct Trackers {
    // Whether the tracker has been set
    bool set;
    // Define what type of tracker
    PT pType;
    // tracker types arrays
    bytes trackerValue;
    // to be added: uint lastUpdatedTimestamp;
}

/// Function Signature Structures
struct FunctionSignatureS {
    mapping(uint256 policyId => uint256 functionId) functionIdCounter;
    mapping(uint256 policyId => mapping(uint256 functionId => FunctionSignatureStorageSet)) functionSignatureStorageSets;
}

struct FunctionSignatureStorageSet {
    bool set;
    bytes4 signature;
    PT[] parameterTypes;
}

/// Rule Structures
struct RuleS {
    mapping(uint256 policyId => uint256 ruleId) ruleIdCounter;
    mapping(uint256 policyId => mapping(uint256 ruleId => RuleStorageSet)) ruleStorageSets;
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

// Policy Type enum to determine if policy is open or closed
enum PolicyType {
    CLOSED_POLICY,
    OPEN_POLICY
}

// Policy storage with set
struct PolicyStorageSet {
    bool set;
    Policy policy;
}

struct Policy {
    // function signatures to function signature Id
    mapping(bytes4 => uint256) functionSignatureIdMap;
    // function signatures to ruleIds
    mapping(bytes4 => uint256[]) signatureToRuleIds;
    // Array to hold the function sigs for iterating
    bytes4[] signatures;
    // Policy type to determine if policy is open or closed
    PolicyType policyType;

    mapping(address => bool) closedPolicySubscribers;
}

/// Policy Association Storage Structures
struct PolicyAssociationS {
    mapping(address contractAddress => uint256[]) contractPolicyIdMap;
}

