// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;


/**
 * @title Example contract for testing the Rules Engine
 * @dev This contract provides the ability to test a hard coded min transfer rule
 * @author @ShaneDuncan602 
 */
contract ExampleUserContractWithMinTransfer {
    event RulesEngineEvent(string _message);
    uint256 predefinedMinTransfer;

    constructor () {
        predefinedMinTransfer = 4;
    }

    function transfer(address _to, uint256 _amount) public returns (bool _return) {
        _to;
        if (_amount > predefinedMinTransfer) {
            emit RulesEngineEvent("Min Transfer triggered");
            return true;
        } else {
            return false;
        }
    }

}
