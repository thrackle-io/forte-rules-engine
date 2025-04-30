/// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/client/RulesEngineClient.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/access/IAccessControl.sol";

/**
 * @title Example User Access Control Contract
 * @dev This contract demonstrates how to integrate the Rules Engine with an external contract. It provides an example 
 *      of using the Rules Engine to enforce policies on a generic `transfer` function. The contract also includes 
 *      role-based access control using OpenZeppelin's AccessControl.
 * @notice This contract is intended for testing and demonstration purposes to showcase the Rules Engine's capabilities.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract ExampleUserAccessControl is RulesEngineClient, AccessControl {
    bytes32 constant CALLING_CONTRACT_ADMIN = "Calling_Contract_Admin";

    /**
     * @notice Constructor for the Example User Access Control contract.
     * @dev Grants the Calling Contract Admin role to the specified address.
     * @param callingContractAdmin The address to be assigned the Calling Contract Admin role.
     */
    constructor(address callingContractAdmin) {
        _grantRole(CALLING_CONTRACT_ADMIN, callingContractAdmin);
    }
    
    /**
     * @notice Demonstrates a generic `transfer` function integrated with the Rules Engine.
     * @dev This function sends custom arguments to the Rules Engine for policy enforcement. The Rules Engine determines 
     *      whether the transfer is allowed based on the provided arguments.
     * @param to The recipient address.
     * @param value The amount to transfer.
     * @return bool True if the transfer is allowed by the Rules Engine, false otherwise.
     */
    function transfer(address to, uint256 value) public returns (bool) {
        uint256 retval = _invokeRulesEngine(msg.data);
        to;
        value;
        if (retval > 0) return true;
        else return false; 
    }

}
