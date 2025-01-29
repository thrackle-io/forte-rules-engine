// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "test/utils/ForeignCallTestCommon.sol";


/**
 * @title Example contract for testing the Rules Engine
 * @dev This contract provides the ability to test a hardcoded min transfer with a foreign call
 * @author @ShaneDuncan602 
 */
contract ExampleUserContractWithDenyList {
    event RulesEngineEvent(string _message);
    ForeignCallTestContractOFAC fc;
    uint256 predefinedMinTransfer;

    constructor () {
        fc = new ForeignCallTestContractOFAC();
        predefinedMinTransfer = 4;
    }

    function transfer(address _to, uint256 _amount) public view returns (bool _return) {
        _amount;
        bool isOnDenyList = fc.onTheNaughtyList(_to);
        if (isOnDenyList) {
            revert();
        } else {
            return true;
        }
    }

    function addToDenyList(address _to) public {
        fc.addToNaughtyList(_to);
    }

}
