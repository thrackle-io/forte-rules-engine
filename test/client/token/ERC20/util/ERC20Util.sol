// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "test/client/token/TokenUtils.sol";
import "test/client/token/TestTokenCommon.sol";

/**
 * @title Rule Creation Functions
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev This contract is an abstract template to be reused by all the tests.
 * This contract holds the functions for adding a protocol rule for tests.
 */

abstract contract ERC20Util is TokenUtils, DummyAMM {
    function setAccountApproveDenyOracleRule(address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT, ActionTypes.BURN);
        ERC20NonTaggedRuleFacet(address(assetHandler)).setAccountApproveDenyOracleId(actionTypes, ruleId);
    }

    function setAccountApproveDenyOracleRuleSingleAction(ActionTypes _action, address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(_action);
        ERC20NonTaggedRuleFacet(address(assetHandler)).setAccountApproveDenyOracleId(actionTypes, ruleId);
    }

    function setAccountApproveDenyOracleRuleFull(address assetHandler, ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        ERC20NonTaggedRuleFacet(address(assetHandler)).setAccountApproveDenyOracleIdFull(actions, ruleIds);
    }

    function setAccountApproveDenyOracleFlexibleRuleSingleAction(ActionTypes _action, address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(_action);
        ERC20NonTaggedRuleFacet(address(assetHandler)).setAccountApproveDenyOracleFlexibleId(actionTypes, ruleId);
    }

    function setAccountApproveDenyOracleFlexibleRule(address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT, ActionTypes.BURN);
        ERC20NonTaggedRuleFacet(address(assetHandler)).setAccountApproveDenyOracleFlexibleId(actionTypes, ruleId);
    }

    function setAccountApproveDenyOracleFlexibleRuleFull(address assetHandler, ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        ERC20NonTaggedRuleFacet(address(assetHandler)).setAccountApproveDenyOracleFlexibleIdFull(actions, ruleIds);
    }

    function setAccountMinMaxTokenBalanceRule(address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.MINT, ActionTypes.BUY, ActionTypes.BURN);
        ERC20TaggedRuleFacet(address(assetHandler)).setAccountMinMaxTokenBalanceId(actionTypes, ruleId);
    }

    function setAccountMinMaxTokenBalanceRuleSingleAction(ActionTypes _action, address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(_action);
        ERC20TaggedRuleFacet(address(assetHandler)).setAccountMinMaxTokenBalanceId(actionTypes, ruleId);
    }

    function setAccountMinMaxTokenBalanceRuleFull(address assetHandler, ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        ERC20TaggedRuleFacet(address(assetHandler)).setAccountMinMaxTokenBalanceIdFull(actions, ruleIds);
    }

    function setTokenMaxSupplyVolatilityRule(address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.MINT, ActionTypes.BURN);
        ERC20NonTaggedRuleFacet(address(assetHandler)).setTokenMaxSupplyVolatilityId(actionTypes, ruleId);
    }

    function setTokenMaxSupplyVolatilityRuleSingleAction(ActionTypes _action, address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(_action);
        ERC20NonTaggedRuleFacet(address(assetHandler)).setTokenMaxSupplyVolatilityId(actionTypes, ruleId);
    }

    function setTokenMaxTradingVolumeRule(address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT);
        ERC20NonTaggedRuleFacet(address(assetHandler)).setTokenMaxTradingVolumeId(actionTypes, ruleId);
    }

    function setAccountMaxTradeSizeIdFull(address assetHandler, ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        TradingRuleFacet(address(assetHandler)).setAccountMaxTradeSizeIdFull(actions, ruleIds);
    }

    function setTokenMaxBuySellVolumeIdFull(address assetHandler, ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        TradingRuleFacet(address(assetHandler)).setTokenMaxBuySellVolumeIdFull(actions, ruleIds);
    }

    function setTokenMaxTradingVolumeRuleSingleAction(ActionTypes _action, address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(_action);
        ERC20NonTaggedRuleFacet(address(assetHandler)).setTokenMaxTradingVolumeId(actionTypes, ruleId);
    }

    function setTokenMaxSupplyVolatilityRuleFull(address assetHandler, ActionTypes[] memory actions, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ERC20NonTaggedRuleFacet(address(assetHandler)).setTokenMaxSupplyVolatilityIdFull(actions, ruleId);
    }
   
    function setTokenMaxTradingVolumeRuleFull(address assetHandler, ActionTypes[] memory actions, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ERC20NonTaggedRuleFacet(address(assetHandler)).setTokenMaxTradingVolumeIdFull(actions, ruleId);
    }

    function setTokenMinimumTransactionRule(address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.BURN, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT);
        ERC20NonTaggedRuleFacet(address(assetHandler)).setTokenMinTxSizeId(actionTypes, ruleId);
    }

    function setTokenMinimumTransactionRuleSingleAction(ActionTypes action, address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(action);
        ERC20NonTaggedRuleFacet(address(assetHandler)).setTokenMinTxSizeId(actionTypes, ruleId);
    }

    function setTokenMinimumTransactionRuleFull(address assetHandler, ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        ERC20NonTaggedRuleFacet(address(assetHandler)).setTokenMinTxSizeIdFull(actions, ruleIds);
    }

    function initializeERC20AMM(address token1, address token2) public endWithStopPrank returns (DummyAMM amm) {
        amm = new DummyAMM();
        switchToAppAdministrator();
        ApplicationERC20(token1).mint(appAdministrator, 1_000_000_000_000 * ATTO);
        ApplicationERC20(token2).mint(appAdministrator, 1_000_000_000_000 * ATTO);
        /// Transfer the tokens into the AMM
        ApplicationERC20(token1).transfer(address(amm), 1_000_000 * ATTO);
        ApplicationERC20(token2).transfer(address(amm), 1_000_000 * ATTO);
        /// Make sure the tokens made it
        assertEq(ApplicationERC20(token1).balanceOf(address(amm)), 1_000_000 * ATTO);
        assertEq(ApplicationERC20(token2).balanceOf(address(amm)), 1_000_000 * ATTO);        
    }

    function initializeERC20Stake(address token1) public endWithStopPrank returns (DummyStaking staking) {
        staking = new DummyStaking();
        switchToAppAdministrator();
        ApplicationERC20(token1).mint(appAdministrator, 1_000_000_000_000 * ATTO);
        /// Transfer the tokens into the AMM
        ApplicationERC20(token1).transfer(address(staking), 1_000_000 * ATTO);
        /// Make sure the tokens made it
        assertEq(ApplicationERC20(token1).balanceOf(address(staking)), 1_000_000 * ATTO);
    }
}
