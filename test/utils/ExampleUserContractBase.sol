/// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;


/**
 * @title Example contract for testing the Rules Engine
 * @dev This contract provides the ability to get a base test 
 * @author @ShaneDuncan602 
 */
contract ExampleUserContractBase {
    event RulesEngineEvent(string _message);

    function transfer(address _to, uint256 _amount) public pure returns (bool _return) {
        _to;
        _amount;
        return false;
    }

}
