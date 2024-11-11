 // SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "src/RulesEngineStructures.sol";

abstract contract EffectStructures {

    // Supported Effect Types
    enum ET { REVERT, EVENT, TRACKER, CALL }

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
        RulesStorageStructure.ForeignCallArgumentMappings[] fcArgumentMappings;
    }
}