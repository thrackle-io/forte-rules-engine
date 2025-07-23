// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/**
 * @title Rules Engine Storage Structures
 * @dev This contract defines the storage structures used throughout the Rules Engine. These structures are used to
 *      manage policies, rules, trackers, calling functions, foreign calls, and other components of the Rules Engine.
 *      The storage structures are designed to support modular and efficient data management within the diamond proxy pattern.
 * @notice This contract is a critical component of the Rules Engine, enabling consistent and conflict-free storage management.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */

struct InitializedStorage {
    bool initialized;
}

/// Enumerated list of Logical operators used in Rule Engine Run
/**
 * NUM - a static value will be in the next slot in the instruction set
 * NOT - perform a logical NOT with the value at the memory address denoted by the next slot in the instruction set
 * PLH - insert a placeholder value into the next memory slot
 * PLHM - insert a mapped placeholder value into the next memory slot
 * ADD - add the values at the memory addresses denoted by the next two slots in the instruction set
 * SUB - subtract the values at the memory addresses denoted by the next two slots in the instruction set
 * MUL - multiply the values at the memory addresses denoted by the next two slots in the instruction set
 * DIV - divide the values at the memory addresses denoted by the next two slots in the instruction set
 * LT - perform a less than comparison with the values at the memory addresses denoted by the next two slots in the instruction set
 * GT - perform a greater than comparison with the values at the memory addresses denoted by the next two slots in the instruction set
 * EQ - perform a equals comparison with the values at the memory addresses denoted by the next two slots in the instruction set
 * AND - perform a logical AND with the values at the memory addresses denoted by the next two slots in the instruciton set
 * OR - perform a logical OR with the values at the memory addresses denoted by the next two slots in the instruction set
 * GTEQL - perform a greater than or equal to comparison with the values at the memory addresses denoted by the next two slots in the instruction set
 * LTEQL - perform a less than or equal to comparison with the values at the memory addresses denoted by the next two slots in the instruction set
 * NOTEQ - perform a not equal to comparison with the values at the memory addresses denoted by the next two slots in the instruction set
 * TRU - perform a tracker update, the next three slots in the instruction set will denote the tracker index and address to update and the memory address of the value to use.
 * TRUM - perform a mapped tracker update, the next four slots in the instruction set will denote the tracker key, index and address to update and the memory address of the value to use.
 */
enum LogicalOp {
    NUM,
    NOT,
    PLH,
    ASSIGN,
    PLHM,
    ADD,
    SUB,
    MUL,
    DIV,
    LT,
    GT,
    EQ,
    AND,
    OR,
    GTEQL,
    LTEQL,
    NOTEQ,
    TRU,
    TRUM
}

// Supported Parameter Types
enum ParamTypes {
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
enum EffectTypes {
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
    ParamTypes pType;
    // The index in the specific array for the specified type;
    uint128 typeSpecificIndex;
    // Packed flags/type:
    // - Bit 0: foreignCall flag
    // - Bit 1: trackerValue flag
    // - Bits 2-4: Global variable type (0-7)
    uint8 flags;
}

/**
 * Supported Tracker Instruction Set Retrieval Types. This is used to tell the engine where to pull the tracker data from.
 */
enum TrackerTypes {
    MEMORY,
    PLACE_HOLDER
}

// Effect Structure
struct Effect {
    bool valid;
    bool dynamicParam; //bool to determine if event requires
    EffectTypes effectType;
    // event data
    ParamTypes pType;
    bytes param;
    bytes32 text; // This is used by events to "Name" the event. It is an unindexed bytes32 param in RulesEngineEvent: _eventString. Bytes32 is used to reduce gas costs
    string errorMessage;
    // The instruction set that will be run at effect execution
    uint256[] instructionSet;
}

/// Foreign Call Structures
struct ForeignCallStorage {
    mapping(uint256 policyId => uint256) foreignCallIdxCounter;
    mapping(uint256 policyId => mapping(uint256 foreignCallIndex => ForeignCall)) foreignCalls;
    mapping(address foreignCallAddress => mapping(bytes4 signature => bool)) isPermissionedForeignCall; // Store all permissioned foreign calls within the rules engine
    mapping(address foreignCallContractAddress => mapping(bytes4 => mapping(address permissionedAdmin => bool))) permissionedForeignCallAdmins; // This is used to store the addresses of all permissioned foreign call admins for look ups
    mapping(address foreignCallContractAddress => mapping(bytes4 selector => address[])) permissionedForeignCallAdminsList; // This is used to store the addresses of all permissioned foreign call admins for look ups
}

struct PermissionedForeignCallStorage {
    address[] permissionedForeignCallAddresses; // This is used to store the addresses of all permissioned foreign call contracts for look ups
    bytes4[] permissionedForeignCallSignatures; // This is used to store the signatures of all permissioned foreign calls for look ups
}

struct ForeignCallMetadataStruct {
    mapping(uint256 policyId => mapping(uint256 foreignCallIndex => string)) foreignCallMetadata;
}

struct TrackerMetadataStruct {
    mapping(uint256 policyId => mapping(uint256 trackerIndex => string)) trackerMetadata;
}

struct CallingFunctionHashMapping {
    string callingFunction;
    bytes4 signature;
    string encodedValues;
}

struct CallingFunctionMetadataStruct {
    mapping(uint256 policyId => mapping(uint256 functionId => CallingFunctionHashMapping)) callingFunctionMetadata;
}

/**
 * Structure used to represent the return value of a Foreign Call
 */
struct ForeignCallReturnValue {
    // Parameter type of the return value
    ParamTypes pType;
    // The actual value of the return value
    bytes value;
}

/**
 * Structure used to hold the decoded arguments.
 * Used to hold both the decoded arguments for a calling function in order,
 * and the arguments for a rules placeholders in order.
 */
struct Arguments {
    // Parameter types of arguments in order
    ParamTypes[] argumentTypes;
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
    ParamTypes returnType;
    // Unique identifier for the foreign contract structure (used by the rule to reference it)
    uint256 foreignCallIndex;
    // The parameter types of the arguments the foreign call takes
    ParamTypes[] parameterTypes;
    // A list of type specific indices to use for the foreign call and where they sit in the calldata
    ForeignCallEncodedIndex[] encodedIndices;
    // Tracks the index of the arguments that are mapped to a tracker
    ForeignCallEncodedIndex[] mappedTrackerKeyIndices;
}

enum EncodedIndexType {
    ENCODED_VALUES,
    FOREIGN_CALL,
    TRACKER,
    GLOBAL_VAR,
    MAPPED_TRACKER_KEY
}

struct ForeignCallEncodedIndex {
    EncodedIndexType eType;
    uint256 index;
}

/// Tracker Structures
struct TrackerStorage {
    //uint256 TrackerIndex;
    mapping(uint256 policyId => uint256 trackerIndex) trackerIndexCounter;
    mapping(uint256 policyId => mapping(uint256 trackerIndex => Trackers)) trackers;
    mapping(uint256 policyId => mapping(uint256 trackerIndex => mapping(bytes key => bytes value))) mappedTrackerValues;
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
    ParamTypes pType; // determine the type of tracker value
    bool mapped; // if true, the tracker is using top level mapping: mappedTrackerValues
    ParamTypes trackerKeyType; // if mapped, this is the type of the key used in the mapping
    // tracker types arrays
    bytes trackerValue;
    // to be added: uint lastUpdatedTimestamp;
    uint256 trackerIndex;
}

/// Calling Function Structures
struct CallingFunctionStruct {
    mapping(uint256 policyId => uint256 functionId) functionIdCounter;
    mapping(uint256 policyId => mapping(uint256 functionId => CallingFunctionStorageSet)) callingFunctionStorageSets;
}

struct CallingFunctionStorageSet {
    bool set;
    bytes4 signature;
    ParamTypes[] parameterTypes;
}

/// Rule Structures
struct RuleStorage {
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
    // Needs to contain the type, and index (zero based) of the particular type in the calling function
    // For example if the argument in question is the 2nd address in the calling function the placeHolder would be:
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
    ParamTypes[] argumentTypes;
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
struct PolicyStorage {
    uint256 policyId;
    mapping(uint256 policyId => PolicyStorageSet) policyStorageSets;
}

// Policy Type enum to determine if policy is open or closed
enum PolicyType {
    CLOSED_POLICY,
    OPEN_POLICY,
    DISABLED_POLICY
}

// Policy storage with set
struct PolicyStorageSet {
    bool set;
    Policy policy;
}

struct Policy {
    // calling functions to calling function Id
    mapping(bytes4 => uint256) callingFunctionIdMap;
    // calling function signature to ruleIds
    mapping(bytes4 => uint256[]) callingFunctionsToRuleIds;
    // Array to hold the calling functions signatures for iterating
    bytes4[] callingFunctions;
    // Policy type to determine if policy is open or closed
    PolicyType policyType;
    // Cemented status
    bool cemented;
    mapping(address => bool) closedPolicySubscribers;
}

/// Policy Association Storage Structures
struct PolicyAssociationStorage {
    mapping(address contractAddress => uint256[]) contractPolicyIdMap;
    mapping(uint256 policyId => address[]) policyIdContractMap;
}
