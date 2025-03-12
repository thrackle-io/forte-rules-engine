// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "src/client/RulesEngineClient.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/access/IAccessControl.sol";


/**
 * @title Example contract for testing the Rules Engine
 * @dev This contract provides the ability to test the rules engine with an external contract
 * @author @mpetersoCode55
 */
contract ExampleUserAccessControl is RulesEngineClient, AccessControl {
    bytes32 constant CALLING_CONTRACT_ADMIN = "Calling_Contract_Admin";

    constructor(address callingContractAdmin) {
        _grantRole(CALLING_CONTRACT_ADMIN, callingContractAdmin);
    }
    
    /**
     @dev This is a generic function that showcases custom arguments being sent to the Rules Engine
     */
    function transfer(address to, uint256 value) public returns (bool) {
        uint256 retval = _invokeRulesEngine(msg.data);
        to;
        value;
        if (retval > 0) return true;
        else return false; 
    }

}
