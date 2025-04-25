// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "src/client/RulesEngineClient.sol";

/**
 * @title Example User Contract for Testing the Rules Engine
 * @dev This contract demonstrates how to integrate the Rules Engine with an external contract. It provides a generic 
 *      `transfer` function that interacts with the Rules Engine to enforce policies. This contract is intended for 
 *      testing and demonstration purposes.
 * @notice This contract showcases the Rules Engine's ability to enforce policies on external contract functions.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract ExampleUserContract is RulesEngineClient {
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

/**
 * @title Example User Contract with Extra Parameters for Testing the Rules Engine
 * @dev This contract extends the functionality of the ExampleUserContract by including additional parameters, such as 
 *      the sender's address, in the data sent to the Rules Engine. It demonstrates how to pass extra context to the 
 *      Rules Engine for policy enforcement.
 * @notice This contract showcases advanced integration with the Rules Engine by including additional parameters in the 
 *         policy evaluation process.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract ExampleUserContractExtraParams is RulesEngineClient {
    /**
     * @notice Demonstrates a generic `transfer` function with extra parameters integrated with the Rules Engine.
     * @dev This function sends custom arguments, including the sender's address, to the Rules Engine for policy 
     *      enforcement. The Rules Engine determines whether the transfer is allowed based on the provided arguments.
     * @param to The recipient address.
     * @param value The amount to transfer.
     * @return bool True if the transfer is allowed by the Rules Engine, false otherwise.
     */
    function transfer(address to, uint256 value) public returns (bool) {
        uint256 retval = _invokeRulesEngine(abi.encode(msg.data, msg.sender));
        to;
        value;
        if (retval > 0) return true;
        else return false; 
    }

}
