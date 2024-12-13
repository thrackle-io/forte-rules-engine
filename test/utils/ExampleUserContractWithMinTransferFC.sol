// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "test/utils/ForeignCallTestCommon.sol";


/**
 * @title Example contract for testing the Rules Engine
 * @dev This contract provides the ability to test a hardcoded min transfer with a foreign call
 * @author @ShaneDuncan602 
 */
contract ExampleUserContractWithMinTransferFC {
    event RulesEngineEvent(string _message);
    ForeignCallTestContract fc;

    constructor () {
        fc = new ForeignCallTestContract();
    }

    function transfer(address _to, uint256 _amount) public returns (bool _return) {
        _to;
        uint256 internalAmount = fc.simpleCheck(_amount);
        if (internalAmount > 4) {
            emit RulesEngineEvent("Min Transfer triggered");
            return true;
        } else {
            return false;
        }
    }

}
