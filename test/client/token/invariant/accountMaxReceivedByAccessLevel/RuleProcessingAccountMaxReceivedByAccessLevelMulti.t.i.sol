// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "test/client/token/invariant/util/RuleProcessingInvariantCommon.sol";
import {RuleProcessingAccountMaxReceivedByAccessLevelActor} from "./RuleProcessingAccountMaxReceivedByAccessLevelActor.sol";
import "./RuleProcessingAccountMaxReceivedByAccessLevelActorManager.sol";
import {InvariantUtils} from "test/client/token/invariant/util/InvariantUtils.sol";

/**
 * @title RuleProcessingAccountMaxReceivedByAccessLevelMultiTest
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett, @mpetersoCode55
 * @dev This is the multi actor rule storage invariant test for multiple managers with multiple actors. Each manager has its
 * own application and set of tokens which will be tested through their own set of actors. The same single rule is shared by all
 * the applications and tokens in this invariant test.
 */
contract RuleProcessingAccountMaxReceivedByAccessLevelMultiTest is RuleProcessingInvariantCommon, InvariantUtils {
    RuleProcessingAccountMaxReceivedByAccessLevelActorManager[] actorManagers;
    RuleProcessingAccountMaxReceivedByAccessLevelActor[][] actors;
    HandlerDiamond[] appHandlers;
    uint8 constant AMOUNT_ACTORS = 10;
    uint8 constant AMOUNT_MANAGERS = 4;

    function setUp() public {
        prepRuleProcessingInvariant();
        switchToRuleAdmin();
        uint32 index = AppRuleDataFacet(address(ruleProcessor)).addAccountMaxReceivedByAccessLevel(address(applicationAppManager), accountMaxReceivedByAccessLevel, address(0));
        for (uint j; j < AMOUNT_MANAGERS; j++) {
            switchToAppAdministrator();
            (UtilApplicationERC20 testCoin, HandlerDiamond testCoinHandler) = deployAndSetupERC20(string.concat("coin", vm.toString(j)), string.concat("C", vm.toString(j)));
            switchToAppAdministrator();
            erc20Pricer.setSingleTokenPrice(address(testCoin), 1 * ATTO); //setting at $1
            RuleProcessingAccountMaxReceivedByAccessLevelActor[] memory tempActors = new RuleProcessingAccountMaxReceivedByAccessLevelActor[](AMOUNT_ACTORS);
            // Load actors
            for (uint i; i < AMOUNT_ACTORS; i++) {
                RuleProcessingAccountMaxReceivedByAccessLevelActor actor = new RuleProcessingAccountMaxReceivedByAccessLevelActor(ruleProcessor);
                tempActors[i] = actor;
                switchToAppAdministrator();
                address eoa = _convertActorAddressToEOA(address(actor));
                switchToAccessLevelAdmin();
                applicationAppManager.addAccessLevel(eoa, uint8(i / 2));
            }
            actors.push(tempActors);
            RuleProcessingAccountMaxReceivedByAccessLevelActorManager actorManager = new RuleProcessingAccountMaxReceivedByAccessLevelActorManager(tempActors, address(testCoin));
            targetContract(address(actorManager));
            actorManagers.push(actorManager);
            (testCoinHandler);
        }
        switchToRuleAdmin();
        applicationHandler.setAccountMaxReceivedByAccessLevelId(createActionTypeArray(ActionTypes.MINT), index);
    }

    /**
     * the cumulative USD value in all application assets received from the application economy can never exceed the maximum of the AccountMaxReceivedByAccessLevel
     * applied for the application and the access level of the account.
     */
    function invariant_amountReceivedCanNeverExceedMaximumOfAccessLevel() public view {
        for (uint j; j < actors.length; j++) {
            for (uint i; i < actors[j].length; i++) {
                uint256 totalReceivedWeis = actors[j][i].totalReceived();
                if (i / 2 < 1) assertLe(totalReceivedWeis / (ATTO), accountMaxReceivedByAccessLevel[0]);
                else if (i / 2 < 2) assertLe(totalReceivedWeis / (ATTO), accountMaxReceivedByAccessLevel[1]);
                else if (i / 2 < 3) assertLe(totalReceivedWeis / (ATTO), accountMaxReceivedByAccessLevel[2]);
                else if (i / 2 < 4) assertLe(totalReceivedWeis / (ATTO), accountMaxReceivedByAccessLevel[3]);
                else assertLe(totalReceivedWeis / (ATTO), accountMaxReceivedByAccessLevel[4]);
            }
        }
    }
}
