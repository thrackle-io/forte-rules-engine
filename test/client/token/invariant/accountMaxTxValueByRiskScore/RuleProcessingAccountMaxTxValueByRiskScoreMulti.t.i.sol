// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "test/client/token/invariant/util/RuleProcessingInvariantCommon.sol";
import {RuleProcessingAccountMaxTxValueByRiskScoreActor} from "./RuleProcessingAccountMaxTxValueByRiskScoreActor.sol";
import "./RuleProcessingAccountMaxTxValueByRiskScoreActorManager.sol";
import {InvariantUtils} from "test/client/token/invariant/util/InvariantUtils.sol";

/**
 * @title RuleProcessingAccountMaxTxValueByRiskScoreMultiTest
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett, @mpetersoCode55
 * @dev This is the multi actor rule storage invariant test for multiple managers with multiple actors. Each manager has its
 * own application and set of tokens which will be tested through their own set of actors. The same single rule is shared by all
 * the applications and tokens in this invariant test.
 */
contract RuleProcessingAccountMaxTxValueByRiskScoreMultiTest is RuleProcessingInvariantCommon, InvariantUtils {
    RuleProcessingAccountMaxTxValueByRiskScoreActorManager[] actorManagers;
    RuleProcessingAccountMaxTxValueByRiskScoreActor[][] actors;
    HandlerDiamond[] appHandlers;
    uint8 constant AMOUNT_ACTORS = 8;
    uint8 constant AMOUNT_MANAGERS = 1; //must only be one manager with no more than 8 addresses.

    function setUp() public {
        prepRuleProcessingInvariant();
        switchToRuleAdmin();
        uint32 index = AppRuleDataFacet(address(ruleProcessor)).addAccountMaxTxValueByRiskScore(
            address(applicationAppManager),
            accountMaxTxValueByRiskScoreA.maxValue,
            accountMaxTxValueByRiskScoreA.riskScore,
            accountMaxTxValueByRiskScoreA.period,
            uint64(block.timestamp)
        );
        for (uint j; j < AMOUNT_MANAGERS; j++) {
            switchToAppAdministrator();
            (UtilApplicationERC20 testCoin, HandlerDiamond testCoinHandler) = deployAndSetupERC20(string.concat("coin", vm.toString(j)), string.concat("C", vm.toString(j)));
            switchToAppAdministrator();
            erc20Pricer.setSingleTokenPrice(address(testCoin), 1 * ATTO); //setting at $1
            RuleProcessingAccountMaxTxValueByRiskScoreActor[] memory tempActors = new RuleProcessingAccountMaxTxValueByRiskScoreActor[](AMOUNT_ACTORS);
            // Load actors
            for (uint i; i < AMOUNT_ACTORS; i++) {
                RuleProcessingAccountMaxTxValueByRiskScoreActor actor = new RuleProcessingAccountMaxTxValueByRiskScoreActor(ruleProcessor, ADDRESSES[i]);
                tempActors[i] = actor;
                switchToAppAdministrator();
                address eoa = _convertActorAddressToEOA(address(actor));
                testCoin.mint(eoa, 2_000 * ATTO);
                switchToRiskAdmin();
                applicationAppManager.addRiskScore(ADDRESSES[i], uint8(i * 10));
            }
            actors.push(tempActors);
            RuleProcessingAccountMaxTxValueByRiskScoreActorManager actorManager = new RuleProcessingAccountMaxTxValueByRiskScoreActorManager(tempActors, address(testCoin));
            targetContract(address(actorManager));
            actorManagers.push(actorManager);
            testCoinHandler;
        }
        switchToRuleAdmin();
        applicationHandler.setAccountMaxTxValueByRiskScoreId(createActionTypeArray(ActionTypes.BUY, ActionTypes.SELL, ActionTypes.P2P_TRANSFER), index);
    }

    /**
     * the cumulative USD value transacted in all application assets within a defined period of time can never exceed
     * the maximum of the AccountMaxTxValueByRiskScore applied for the application and the risk score of the account
     */
    function invariant_amountTransactedCanNeverExceedTheRiskProfileMaximum() public view {
        for (uint j; j < actors.length; j++) {
            for (uint i; i < actors[j].length; i++) {
                uint256 totalTransactedInPeriodWeis = actors[j][i].totalTransactedInPeriod();
                if (i < 1) {
                    console.log("no limit", totalTransactedInPeriodWeis / (ATTO));
                } else if (i < 6) {
                    console.log("1st limit", totalTransactedInPeriodWeis / (ATTO));
                    assertLe(totalTransactedInPeriodWeis / (ATTO), accountMaxTxValueByRiskScoreA.maxValue[0]);
                } else if (i < 8) {
                    console.log("2nd limit", totalTransactedInPeriodWeis / (ATTO));
                    assertLe(totalTransactedInPeriodWeis / (ATTO), accountMaxTxValueByRiskScoreA.maxValue[1]);
                } else {
                    console.log("3rd limit", totalTransactedInPeriodWeis / (ATTO));
                    assertLe(totalTransactedInPeriodWeis / (ATTO), accountMaxTxValueByRiskScoreA.maxValue[2]);
                }
            }
        }
    }
}
