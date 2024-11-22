 // SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "src/RulesStorageStructure.sol";

abstract contract EffectStructures {

    // Supported Effect Types
    enum ET { REVERT, EVENT, EXPRESSION}

    /// Events 
    event RulesEngineEvent(string _message);
    
    /// Effect structures
    mapping(uint256=>Effect) effectStorage;

    uint256 effectTotal;
    
    struct Effect {
        uint256 effectId;
        ET effectType;
        string text;//used for any type of text(revert, event, etc.)
        // The instruction set that will be run at effect execution
        uint256[] instructionSet;
    }

}