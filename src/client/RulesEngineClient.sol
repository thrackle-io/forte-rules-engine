// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./IRulesEngine.sol";
import "lib/openzeppelin-contracts/contracts/access/AccessControl.sol";

/**
 * @title Rules Engine Client
 * @author @ShaneDuncan602
 * @dev The abstract contract containing function to connect to the Rules Engine.
 */
abstract contract RulesEngineClient is AccessControl {

    address public rulesEngineAddress;
    bytes32 constant TOKEN_ADMIN_ROLE = keccak256("TOKEN_ADMIN_ROLE");

    constructor() {
        _grantRole(TOKEN_ADMIN_ROLE, msg.sender);
        _setRoleAdmin(TOKEN_ADMIN_ROLE, TOKEN_ADMIN_ROLE);
    }

    /**
     * Set the Rules Engine address
     * @param rulesEngine rules engine address
     */
    function setRulesEngineAddress(address rulesEngine) onlyRole(TOKEN_ADMIN_ROLE) public {
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
