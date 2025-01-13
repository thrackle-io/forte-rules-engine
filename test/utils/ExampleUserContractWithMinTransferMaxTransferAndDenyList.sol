// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "test/utils/ForeignCallTestCommon.sol";


/**
 * @title Example contract for testing the Rules Engine
 * @dev This contract provides the ability to test a hardcoded min transfer with a foreign call
 * @author @ShaneDuncan602 
 */
contract ExampleUserContractWithMinTransferMaxTransferAndDenyList {
    event RulesEngineEvent(string _message);
    ForeignCallTestContractOFAC fc;
    uint256 predefinedMinTransfer;
    uint256 predefinedMaxTransfer;
    constructor () {
        fc = new ForeignCallTestContractOFAC();
        predefinedMinTransfer = 4;
        predefinedMaxTransfer = 5;
    }

    function transfer(address _to, uint256 _amount) public returns (bool _return) {
        _to;
        bool isOnDenyList = fc.onTheNaughtyList(_to);
        bool minCheck = _amount < predefinedMinTransfer;
        bool maxCheck = _amount > predefinedMaxTransfer;
        if (isOnDenyList || minCheck || maxCheck) {
            revert();
        } else {
            return true;
        }
    }

    function addToDenyList(address _to) public {
        fc.addToNaughtyList(_to);
    }

}