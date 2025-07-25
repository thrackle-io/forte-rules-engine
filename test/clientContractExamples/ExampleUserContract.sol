/// SPDX-License-Identifier: BUSL-1.1
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
    bytes public msgData;
    address public userAddress;
    uint256 public number;
    /**
     * @notice Demonstrates a generic `transfer` function integrated with the Rules Engine.
     * @dev This function sends custom arguments to the Rules Engine for policy enforcement. The Rules Engine determines
     *      whether the transfer is allowed based on the provided arguments.
     * @param to The recipient address.
     * @param value The amount to transfer.
     * @return bool True if the transfer is allowed by the Rules Engine, false otherwise.
     */
    function transfer(address to, uint256 value) public returns (bool) {
        _invokeRulesEngine(msg.data);
        to;
        value;
        return true;
    }

    function transferFrom(address to, uint256 value, bytes memory _bytes) public returns (bool) {
        _invokeRulesEngine(msg.data);
        to; // added to silence compiler warnings
        value; // added to silence compiler warnings
        _bytes; // added to silence compiler warnings
        return true;
    }

    function transferFromString(address to, uint256 value, string memory _string) public returns (bool) {
        _invokeRulesEngine(msg.data);
        to; // added to silence compiler warnings
        value; // added to silence compiler warnings
        _string; // added to silence compiler warnings
        return true;
    }

    function transferSigTest(address to, uint256 value, string memory _str, string memory _str2) public returns (bool) {
        _invokeRulesEngine(abi.encodeWithSelector(this.transferFrom.selector, to, value, _str, _str2, 22));
        to; // added to silence compiler warnings
        value; // added to silence compiler warnings
        _str; // added to silence compiler warnings
        _str2; // added to silence compiler warnings
        return true;
    }

    function setMsgData(bytes memory data) public returns (bool) {
        msgData = data;
        return true;
    }

    function setUserAddress(address user) public returns (bool) {
        userAddress = user;
        return true;
    }

    function setNumber(uint256 num) public returns (bool) {
        number = num;
        return true;
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
        _invokeRulesEngine(abi.encode(msg.data, msg.sender));
        to;
        value;
        return true;
    }
}
