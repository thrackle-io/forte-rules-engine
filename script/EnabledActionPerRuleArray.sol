// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "src/common/ActionEnum.sol";
import "src/client/common/ActionTypesArray.sol";
import "src/protocol/economic/ruleProcessor/RuleCodeData.sol";

/**
 * @title Official List Of Enabled Actions Per Rule
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett, @mpetersoCode55
 * @dev This file contains the official list of enabled actions per rule
 */

/**
 * @dev Data structure to hold the list of enabled actions per rule for easy iteration
 */
struct EnabledActionPerRule {
    bytes32 ruleName;
    ActionTypes[] enabledActions;
}

/**
 * @title Enabled Action Per Rule Array
 * @dev This contract's only purpose is to hold the official list of enabled actions per rule
 */
contract EnabledActionPerRuleArray is ActionTypesArray {
    /**
     * @dev this array should be iterated to setup the protocol
     */
    EnabledActionPerRule[] enabledActionPerRuleArray;

    constructor() {
        enabledActionPerRuleArray.push(
            EnabledActionPerRule(ACCOUNT_APPROVE_DENY_ORACLE, createActionTypesArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT, ActionTypes.BURN))
        );
        enabledActionPerRuleArray.push(
            EnabledActionPerRule(ACCOUNT_APPROVE_DENY_ORACLE_FLEXIBLE, createActionTypesArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT, ActionTypes.BURN))
        );
        enabledActionPerRuleArray.push(EnabledActionPerRule(ACCOUNT_DENY_FOR_NO_ACCESS_LEVEL, createActionTypesArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT)));
        enabledActionPerRuleArray.push(EnabledActionPerRule(ACCOUNT_MAX_TRADE_SIZE, createActionTypesArray(ActionTypes.BUY, ActionTypes.SELL)));
        enabledActionPerRuleArray.push(
            EnabledActionPerRule(ACC_MAX_TX_VALUE_BY_RISK_SCORE, createActionTypesArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT, ActionTypes.BURN))
        );
        enabledActionPerRuleArray.push(EnabledActionPerRule(ACC_MAX_VALUE_BY_ACCESS_LEVEL, createActionTypesArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.MINT)));
        enabledActionPerRuleArray.push(EnabledActionPerRule(ACC_MAX_RECEIVED_BY_ACCESS_LEVEL, createActionTypesArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT)));
        enabledActionPerRuleArray.push(EnabledActionPerRule(ACC_MAX_VALUE_BY_RISK_SCORE, createActionTypesArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.MINT)));
        enabledActionPerRuleArray.push(EnabledActionPerRule(ACC_MAX_VALUE_OUT_ACCESS_LEVEL, createActionTypesArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BURN)));
        enabledActionPerRuleArray.push(
            EnabledActionPerRule(TOKEN_MIN_TX_SIZE, createActionTypesArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT, ActionTypes.BURN))
        );
        enabledActionPerRuleArray.push(
            EnabledActionPerRule(ACCOUNT_MIN_MAX_TOKEN_BALANCE, createActionTypesArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT, ActionTypes.BURN))
        );
        enabledActionPerRuleArray.push(EnabledActionPerRule(TOKEN_MAX_BUY_SELL_VOLUME, createActionTypesArray(ActionTypes.BUY, ActionTypes.SELL)));
        enabledActionPerRuleArray.push(EnabledActionPerRule(TOKEN_MAX_DAILY_TRADES, createActionTypesArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT, ActionTypes.BURN)));
        enabledActionPerRuleArray.push(EnabledActionPerRule(TOKEN_MAX_SUPPLY_VOLATILITY, createActionTypesArray(ActionTypes.MINT, ActionTypes.BURN)));
        enabledActionPerRuleArray.push(EnabledActionPerRule(TOKEN_MAX_TRADING_VOLUME, createActionTypesArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT, ActionTypes.BURN)));
        enabledActionPerRuleArray.push(EnabledActionPerRule(TOKEN_MIN_HOLD_TIME, createActionTypesArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BURN)));
    }
}
