// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "test/protocol/economic/invariant/rules/util/RuleStorageInvariantCommon.sol";
import {RuleStorageAccountApproveDenyOracleFlexibleActor} from "./RuleStorageAccountApproveDenyOracleFlexibleActor.sol";
import "./RuleStorageAccountApproveDenyOracleFlexibleActorManager.sol";

/**
 * @title RuleStorageAccountApproveDenyOracleFlexibleMultiTest
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett, @mpetersoCode55
 * @dev This is the multi actor rule storage invariant test for multiple actors.
 */
contract RuleStorageAccountApproveDenyOracleFlexibleMultiTest is RuleStorageInvariantCommon {
    RuleStorageAccountApproveDenyOracleFlexibleActorManager actorManager;
    RuleStorageAccountApproveDenyOracleFlexibleActor[] actors;
    NonTaggedRules.AccountApproveDenyOracleFlexible ruleBefore;

    function setUp() public {
        prepRuleStorageInvariant();
        // Load 10 actors
        for (uint i; i < 10; i++) {
            ApplicationAppManager actorAppManager = _createAppManager();
            switchToSuperAdmin();
            actorAppManager.addAppAdministrator(appAdministrator);
            actors.push(new RuleStorageAccountApproveDenyOracleFlexibleActor(ruleProcessor, actorAppManager));
            if (i % 2 == 0) {
                vm.startPrank(appAdministrator);
                actorAppManager.addRuleAdministrator(address(actors[actors.length - 1]));
            }
        }
        actorManager = new RuleStorageAccountApproveDenyOracleFlexibleActorManager(actors);
        switchToRuleAdmin();
        index = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracleFlexible(address(applicationAppManager), 0, 0, address(0xabc));
        ruleBefore = ERC20RuleProcessorFacet(address(ruleProcessor)).getAccountApproveDenyOracleFlexible(index);
        targetContract(address(actorManager));
    }

    // The total amount of rules will never decrease.
    function invariant_rulesTotalAccountApproveDenyOracleFlexibleNeverDecreases() public view {
        uint256 total;
        for (uint i; i < actors.length; i++) {
            total += actors[i].totalRules();
        }
        // index must be incremented by one to account for 0 based array
        assertLe(index + 1, ERC20RuleProcessorFacet(address(ruleProcessor)).getTotalAccountApproveDenyOracleFlexible());
    }

    // The biggest ruleId in a rule type will always be the same as the total amount of rules registered in the protocol for that rule type - 1.
    function invariant_rulesTotalAccountApproveDenyOracleFlexibleEqualsAppBalances() public view {
        uint256 total;
        for (uint i; i < actors.length; i++) {
            total += actors[i].totalRules();
        }
        // adding 1 to total for the initial rule created in the setup function
        assertEq(total + 1, ERC20RuleProcessorFacet(address(ruleProcessor)).getTotalAccountApproveDenyOracleFlexible());
    }

    // There can be only a total of 2**32 of each rule type.
    function invariant_rulesTotalAccountApproveDenyOracleFlexibleLessThanMax() public view {
        assertLe(ERC20RuleProcessorFacet(address(ruleProcessor)).getTotalAccountApproveDenyOracleFlexible(), maxRuleCount);
    }

    /// The next ruleId created in a specific rule type will always be the same as the previous ruleId + 1.
    function invariant_rulesTotalAccountApproveDenyOracleFlexibleIncrementsByOne() public {
        uint256 previousTotal = ERC20RuleProcessorFacet(address(ruleProcessor)).getTotalAccountApproveDenyOracleFlexible();
        // not incrementing previousTotal by one due to zero based ruleId
        switchToRuleAdmin();
        assertEq(previousTotal, RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracleFlexible(address(applicationAppManager), 0, 0, address(0xabc)));
    }

    // Rules can never be modified.
    function invariant_AccountApproveDenyOracleFlexibleImmutable() public view {
        NonTaggedRules.AccountApproveDenyOracleFlexible memory ruleAfter = ERC20RuleProcessorFacet(address(ruleProcessor)).getAccountApproveDenyOracleFlexible(index);
        assertEq(ruleBefore.oracleType, ruleAfter.oracleType);
        assertEq(ruleBefore.oracleAddress, ruleAfter.oracleAddress);
    }
}
