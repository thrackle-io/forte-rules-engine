// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "test/protocol/economic/invariant/rules/util/RuleStorageInvariantCommon.sol";
import {RuleStorageTokenMaxSupplyVolatilityActor} from "./RuleStorageTokenMaxSupplyVolatilityActor.sol";
import "./RuleStorageTokenMaxSupplyVolatilityActorManager.sol";

/**
 * @title RuleStorageTokenMaxSupplyVolatilityMultiTest
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett, @mpetersoCode55
 * @dev This is the multi actor rule storage invariant test for multiple actors.
 */
contract RuleStorageTokenMaxSupplyVolatilityMultiTest is
    RuleStorageInvariantCommon
{
    RuleStorageTokenMaxSupplyVolatilityActorManager actorManager;
    RuleStorageTokenMaxSupplyVolatilityActor[] actors;
    NonTaggedRules.TokenMaxSupplyVolatility ruleBefore;

    function setUp() public {
        prepRuleStorageInvariant();
        // Load 10 actors
        for (uint i; i < 10; i++) {
            ApplicationAppManager actorAppManager = _createAppManager();
            switchToSuperAdmin();
            actorAppManager.addAppAdministrator(appAdministrator);
            actors.push(
                new RuleStorageTokenMaxSupplyVolatilityActor(
                    ruleProcessor,
                    actorAppManager
                )
            );
            if (i % 2 == 0) {
                vm.startPrank(appAdministrator);
                actorAppManager.addRuleAdministrator(
                    address(actors[actors.length - 1])
                );
            }
        }
        actorManager = new RuleStorageTokenMaxSupplyVolatilityActorManager(
            actors
        );
        switchToRuleAdmin();
        index = RuleDataFacet(address(ruleProcessor))
            .addTokenMaxSupplyVolatility(
                address(applicationAppManager),
                666,
                24,
                uint64(block.timestamp),
                0
            );
        ruleBefore = ERC20RuleProcessorFacet(address(ruleProcessor))
            .getTokenMaxSupplyVolatility(index);
        targetContract(address(actorManager));
    }

    // The total amount of rules will never decrease.
    function invariant_rulesTotalTokenMaxSupplyVolatilityNeverDecreases()
        public
        view
    {
        uint256 total;
        for (uint i; i < actors.length; i++) {
            total += actors[i].totalRules();
        }
        // index must be incremented by one to account for 0 based array
        assertLe(
            index + 1,
            ERC20RuleProcessorFacet(address(ruleProcessor))
                .getTotalTokenMaxSupplyVolatility()
        );
    }

    // The biggest ruleId in a rule type will always be the same as the total amount of rules registered in the protocol for that rule type - 1.
    function invariant_rulesTotalTokenMaxSupplyVolatilityEqualsAppBalances()
        public
        view
    {
        uint256 total;
        for (uint i; i < actors.length; i++) {
            total += actors[i].totalRules();
        }
        console.log(total);
        console.log(
            ERC20RuleProcessorFacet(address(ruleProcessor))
                .getTotalTokenMaxSupplyVolatility()
        );
        // adding 1 to total for the initial rule created in the setup function
        assertEq(
            total + 1,
            ERC20RuleProcessorFacet(address(ruleProcessor))
                .getTotalTokenMaxSupplyVolatility()
        );
    }

    // There can be only a total of 2**32 of each rule type.
    function invariant_rulesTotalTokenMaxSupplyVolatilityLessThanMax()
        public
        view
    {
        assertLe(
            ERC20RuleProcessorFacet(address(ruleProcessor))
                .getTotalTokenMaxSupplyVolatility(),
            maxRuleCount
        );
    }

    /// The next ruleId created in a specific rule type will always be the same as the previous ruleId + 1.
    function invariant_rulesTotalTokenMaxSupplyVolatilityIncrementsByOne()
        public
    {
        uint256 previousTotal = ERC20RuleProcessorFacet(address(ruleProcessor))
            .getTotalTokenMaxSupplyVolatility();
        // not incrementing previousTotal by one due to zero based ruleId
        assertEq(
            previousTotal,
            RuleDataFacet(address(ruleProcessor)).addTokenMaxSupplyVolatility(
                address(applicationAppManager),
                666,
                24,
                uint64(block.timestamp),
                0
            )
        );
    }

    // Rules can never be modified.
    function invariant_TokenMaxSupplyVolatilityImmutable() public view {
        NonTaggedRules.TokenMaxSupplyVolatility
            memory ruleAfter = ERC20RuleProcessorFacet(address(ruleProcessor))
                .getTokenMaxSupplyVolatility(index);
        assertEq(ruleBefore.max, ruleAfter.max);
        assertEq(ruleBefore.period, ruleAfter.period);
        assertEq(ruleBefore.startTime, ruleAfter.startTime);
        assertEq(ruleBefore.totalSupply, ruleAfter.totalSupply);
    }
}