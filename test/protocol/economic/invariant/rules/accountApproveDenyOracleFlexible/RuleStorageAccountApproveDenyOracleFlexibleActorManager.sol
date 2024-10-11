// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "./RuleStorageAccountApproveDenyOracleFlexibleActor.sol";
import "../util/RuleStorageInvariantActorManagerCommon.sol";

/**
 * @title RuleStorageAccountApproveDenyOracleFlexibleActorManager
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett, @mpetersoCode55
 * @dev This is the actor manager for the AccountApproveDenyOracle rule. It will manage a variable number of invariant actors
 */
contract RuleStorageAccountApproveDenyOracleFlexibleActorManager is RuleStorageInvariantActorManagerCommon {
    RuleStorageAccountApproveDenyOracleFlexibleActor[] actors;

    constructor(RuleStorageAccountApproveDenyOracleFlexibleActor[] memory _actors) {
        actors = _actors;
    }

    /**
     * @dev uses the fuzzed handler index to "randomly" choose a handler to add the rule
     */
    function addAccountApproveDenyOracleFlexible(uint8 _handlerIndex, address _oracleAddress, uint8 _type, uint8 _addressToggle) public endWithStopPrank {
        _type = uint8(bound(uint256(_type), 0, 1));
        _addressToggle = uint8(bound(uint256(_type), 0, 3));
        if (_oracleAddress == address(0)) _oracleAddress = address(0xaddafee);
        _handlerIndex = uint8(bound(uint256(_handlerIndex), 0, actors.length - 1));
        actors[_handlerIndex].addAccountApproveDenyOracleFlexible(_oracleAddress, _type, _addressToggle);
    }
}
