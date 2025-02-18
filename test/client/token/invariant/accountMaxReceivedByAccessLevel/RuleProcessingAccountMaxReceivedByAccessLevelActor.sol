// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {RuleProcessingInvariantActorCommon} from "test/client/token/invariant/util/RuleProcessingInvariantActorCommon.sol";
import "test/client/token/invariant/util/DummySingleTokenAMM.sol";
import "test/util/TestCommonFoundry.sol";
import {InvariantUtils} from "test/client/token/invariant/util/InvariantUtils.sol";

/**
 * @title RuleProcessingAccountMaxReceivedByAccessLevelActor
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett, @mpetersoCode55
 * @dev This is the rule processing actor for the AccountMaxReceivedByAccessLevel rule.
 */
contract RuleProcessingAccountMaxReceivedByAccessLevelActor is TestCommonFoundry, RuleProcessingInvariantActorCommon, InvariantUtils {
    uint256 public totalReceived;

    constructor(RuleProcessorDiamond _processor) {
        processor = _processor;
        testStartsAtTime = block.timestamp;
    }

    /**
     * @dev test the rule
     */
    function checkAccountMaxReceivedByAccessLevel(uint256 _amount, address _token) public {
        address eoa = _convertActorAddressToEOA(address(this));
        vm.startPrank(eoa, eoa);
        UtilApplicationERC20(_token).mint(eoa, _amount);
        totalReceived += _amount;
    }
}
