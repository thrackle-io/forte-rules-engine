// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {RuleProcessingInvariantActorCommon} from "test/client/token/invariant/util/RuleProcessingInvariantActorCommon.sol";
import "test/client/token/invariant/util/DummySingleTokenAMM.sol";
import "test/util/TestCommonFoundry.sol";

/**
 * @title RuleProcessingTokenMaxBuySellVolumeActor
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett, @mpetersoCode55
 * @dev This is the rule processing actor for the TokenMaxSellVolume rule.
 */
contract RuleProcessingTokenMaxBuySellVolumeActor is TestCommonFoundry, RuleProcessingInvariantActorCommon {
    constructor(RuleProcessorDiamond _processor) {
        processor = _processor;
        testStartsAtTime = block.timestamp;
    }

    /**
     * @dev test the rule
     */
    function checkTokenMaxBuySellVolumeSell(uint256 _amount, address amm, address _token) public {
        DummySingleTokenAMM(amm).sell(_amount, _token);
    }

    /**
     * @dev test the rule
     */
    function checkTokenMaxBuySellVolumeBuy(uint256 _amount, address amm, address _token) public {
        DummySingleTokenAMM(amm).buy(_amount, _token);
    }
}