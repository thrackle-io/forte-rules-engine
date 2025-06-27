/// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/client/RulesEngineClient.sol";
import "@openzeppelin/access/Ownable.sol";

/**
 * @title Example User Ownable Contract for Testing the Rules Engine
 * @dev This contract demonstrates how to integrate the Rules Engine with an external contract that uses OpenZeppelin's 
 *      Ownable for access control. It provides a generic `transfer` function that interacts with the Rules Engine to 
 *      enforce policies. This contract is intended for testing and demonstration purposes.
 * @notice This contract showcases the Rules Engine's ability to enforce policies on external contract functions while 
 *         leveraging ownership-based access control.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract ExampleUserOwnableContract is RulesEngineClient, Ownable {
    /**
     * @notice Constructor for the Example User Ownable Contract.
     * @dev Initializes the contract with an initial owner.
     * @param initialOwner The address to be set as the initial owner of the contract.
     */
    constructor(address initialOwner)  Ownable(initialOwner) {}
    
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

