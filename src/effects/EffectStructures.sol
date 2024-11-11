 // SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "src/RulesEngineStructures.sol";

abstract contract EffectStructures {

    // Supported Effect Types
    enum ET { REVERT, EVENT}

    /// Events 
    event RulesEngineEvent(string _message);
    
    /// Effect structures
    mapping(uint256=>Effect) effectStorage;

    uint256 effectTotal;
    
    struct Effect {
        uint256 effectId;
        ET effectType;
        string text;//used for any type of text(revert, event, etc.)
        // Mapping between the Foreigns Calls arguments and the arguments of the function signature this rule is associated with
        // RulesStorageStructure.ForeignCallArgumentMappings fcArgumentMapping;
    }

    // struct EffectForeignCallStorage {
    //     bool set;
    //     EffectForeignCall[] foreignCalls;
    // }

    /**
     * Structure used to represent a foreign call that can be made during rule evaluation
     */
    // struct EffectForeignCall {
    //     // Address of the contract to make the call to
    //     address foreignCallAddress;
    //     // Unique identifier for the foreign contract structure (used by the rule to reference it)
    //     uint256 foreignCallIndex;
    //     // The function signature of the foreign call
    //     bytes4 signature;
    //     // The parameter types of the arguments the foreign call takes
    //     RulesEngineStructures.PT[] parameterTypes;
    // }
}