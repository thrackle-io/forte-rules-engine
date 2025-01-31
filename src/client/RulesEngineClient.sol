// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./IRulesEngine.sol";

/**
 * @title Rules Engine Client
 * @author @ShaneDuncan602
 * @dev The abstract contract containing function to connect to the Rules Engine.
 */
abstract contract RulesEngineClient {

    address public rulesEngineAddress;

    /**
     * Set the Rules Engine address
     * @dev Function should be overridden within inheriting contracts to add Role Based Controls appropriate for your needs.
     * @param rulesEngine rules engine address
     */
    function setRulesEngineAddress(address rulesEngine) public virtual {
        rulesEngineAddress = rulesEngine;
    }

    /**
     * @dev This function makes the call to the Rules Engine
     * @param encoded encoded data to be passed to the rules engine
     * @return retval return value from the rules engine
     */
    function _invokeRulesEngine(bytes memory encoded) internal returns (uint256 retval) {
        if (rulesEngineAddress != address(0)) return IRulesEngine(rulesEngineAddress).checkPolicies(address(this), encoded);
    }
}
