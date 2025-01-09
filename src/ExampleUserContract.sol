// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "src/IRulesEngine.sol";
import "src/engine/RulesEngineStorageStructure.sol";

/**
 * @title Example contract for testing the Rules Engine
 * @dev This contract provides the ability to test the rules engine with an external contract
 * @author @mpetersoCode55 
 */
contract ExampleUserContract {
    address public rulesEngineAddress;

    function transfer(address _to, uint256 _amount) public returns (bool) {
        IRulesEngine rulesEngine = IRulesEngine(rulesEngineAddress);
        uint256 retVal = rulesEngine.checkPolicies(address(this), msg.data);
        // This is where the overridden transfer would be called

        return retVal == 1;
    }

    /**
     * Set the Rules Engine address
     * @param rulesEngine rules engine address
     */
    function setRulesEngineAddress(address rulesEngine) public {
        rulesEngineAddress = rulesEngine;
    }
}
