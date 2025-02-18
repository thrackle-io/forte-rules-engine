// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "test/util/RuleCreation.sol";
import {IApplicationHandlerEvents} from "src/common/IEvents.sol";

/**
 * @title Rule Creation Functions
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev This contract is an abstract template to be reused by all the tests.
 * This contract holds the functions for adding a protocol rule for tests.
 */

abstract contract TokenUtils is IApplicationHandlerEvents, RuleCreation {
    /** APPLICATION LEVEL RULES */
    function setAccountMaxTxValueByRiskRule(uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT, ActionTypes.BURN);
        // check the event emission when setting
        for(uint256 i = 0; i < actionTypes.length; ++i){
            vm.expectEmit(true, true, true, true);
            emit AD1467_ApplicationRuleApplied(ACC_MAX_TX_VALUE_BY_RISK_SCORE, actionTypes[i], ruleId);
        }
        applicationHandler.setAccountMaxTxValueByRiskScoreId(actionTypes, ruleId);
    }

    function setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes action, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        // check the event emission when setting
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationRuleApplied(ACC_MAX_TX_VALUE_BY_RISK_SCORE, action, ruleId);
        applicationHandler.setAccountMaxTxValueByRiskScoreId(createActionTypeArray(action), ruleId);
    }

    function setAccountMaxTxValueByRiskRuleFull(ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        // check the event emission when setting
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationRuleAppliedFull(ACC_MAX_TX_VALUE_BY_RISK_SCORE, actions, ruleIds);
        applicationHandler.setAccountMaxTxValueByRiskScoreIdFull(actions, ruleIds);
    }

    function setAccountMaxValueByAccessLevelRule(uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.MINT);
        // check the event emission when setting
        for(uint256 i = 0; i < actionTypes.length; ++i){
            vm.expectEmit(true, true, true, true);
            emit AD1467_ApplicationRuleApplied(ACC_MAX_VALUE_BY_ACCESS_LEVEL, actionTypes[i], ruleId);
        }
        applicationHandler.setAccountMaxValueByAccessLevelId(actionTypes, ruleId);
    }

    function setAccountMaxValueByAccessLevelRuleSingleAction(ActionTypes action, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        // check the event emission when setting
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationRuleApplied(ACC_MAX_VALUE_BY_ACCESS_LEVEL, action, ruleId);
        applicationHandler.setAccountMaxValueByAccessLevelId(createActionTypeArray(action), ruleId);
    }

    function setAccountMaxValueByAccessLevelRuleFull(ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        // check the event emission when setting
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationRuleAppliedFull(ACC_MAX_VALUE_BY_ACCESS_LEVEL, actions, ruleIds);
        applicationHandler.setAccountMaxValueByAccessLevelIdFull(actions, ruleIds);
    }

    function setAccountMaxReceivedByAccessLevelIdFull(ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        // check the event emission when setting
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationRuleAppliedFull(ACC_MAX_RECEIVED_BY_ACCESS_LEVEL, actions, ruleIds);
        applicationHandler.setAccountMaxReceivedByAccessLevelIdFull(actions, ruleIds);
    }

    function setAccountMaxReceivedByAccessLevelSingleAction(ActionTypes action, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        // check the event emission when setting
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationRuleApplied(ACC_MAX_RECEIVED_BY_ACCESS_LEVEL, action, ruleId);
        applicationHandler.setAccountMaxReceivedByAccessLevelId(createActionTypeArray(action), ruleId);
    }

    function setAccountMaxValueByRiskRule(uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.MINT);
        // check the event emission when setting
        for(uint256 i = 0; i < actionTypes.length; ++i){
            vm.expectEmit(true, true, true, true);
            emit AD1467_ApplicationRuleApplied(ACC_MAX_VALUE_BY_RISK_SCORE, actionTypes[i], ruleId);
        }
        applicationHandler.setAccountMaxValueByRiskScoreId(actionTypes, ruleId);
    }

    function setAccountMaxValueByRiskRuleSingleAction(ActionTypes action, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        // check the event emission when setting
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationRuleApplied(ACC_MAX_VALUE_BY_RISK_SCORE, action, ruleId);
        applicationHandler.setAccountMaxValueByRiskScoreId(createActionTypeArray(action), ruleId);
    }

    function setAccountMaxValueByRiskRuleFull(ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        // check the event emission when setting
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationRuleAppliedFull(ACC_MAX_VALUE_BY_RISK_SCORE, actions, ruleIds);
        applicationHandler.setAccountMaxValueByRiskScoreIdFull(actions, ruleIds);
    }

    function setAccountMaxValueOutByAccessLevelRule(uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL);
        // check the event emission when setting
        for(uint256 i = 0; i < actionTypes.length; ++i){
            vm.expectEmit(true, true, true, true);
            emit AD1467_ApplicationRuleApplied(ACC_MAX_VALUE_OUT_ACCESS_LEVEL, actionTypes[i], ruleId);
        }
        applicationHandler.setAccountMaxValueOutByAccessLevelId(actionTypes, ruleId);
    }

    function setAccountMaxValueOutByAccessLevelSingleAction(ActionTypes action, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        // check the event emission when setting
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationRuleApplied(ACC_MAX_VALUE_OUT_ACCESS_LEVEL, action, ruleId);
        applicationHandler.setAccountMaxValueOutByAccessLevelId(createActionTypeArray(action), ruleId);
    }

    function setAccountMaxValueOutByAccessLevelRuleFull(ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        // check the event emission when setting
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationRuleAppliedFull(ACC_MAX_VALUE_OUT_ACCESS_LEVEL, actions, ruleIds);
        applicationHandler.setAccountMaxValueOutByAccessLevelIdFull(actions, ruleIds);
    }

    function setAccountDenyForNoAccessLevelRuleFull(ActionTypes[] memory actions) public endWithStopPrank {
        switchToRuleAdmin();
        // check the event emission when setting
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationRuleAppliedFull(ACCOUNT_DENY_FOR_NO_ACCESS_LEVEL, actions, new uint32[](actions.length));
        applicationHandler.setAccountDenyForNoAccessLevelIdFull(actions);
    }

    function setTokenMaxBuySellVolumeRule(address assetHandler, ActionTypes[] memory actions, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        // check the event emission when setting
        for(uint256 i = 0; i < actions.length; ++i){
            vm.expectEmit(true, true, true, true);
            emit AD1467_ApplicationHandlerActionApplied(TOKEN_MAX_BUY_SELL_VOLUME, actions[i], ruleId);
        }
        TradingRuleFacet(address(assetHandler)).setTokenMaxBuySellVolumeId(actions, ruleId);
    }

    function setAccountMaxTradeSizeRule(address assetHandler, ActionTypes[] memory actions, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        // check the event emission when setting
        for(uint256 i = 0; i < actions.length; ++i){
            vm.expectEmit(true, true, true, true);
            emit AD1467_ApplicationHandlerActionApplied(ACCOUNT_MAX_TRADE_SIZE, actions[i], ruleId);
        }
        TradingRuleFacet(address(assetHandler)).setAccountMaxTradeSizeId(actions, ruleId);
    }
}
