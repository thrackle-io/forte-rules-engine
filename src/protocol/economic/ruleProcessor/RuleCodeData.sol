// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

// Rule Code Constants
bytes32 constant AMM_FEE = "AMM_FEE";
bytes32 constant ACCOUNT_MAX_TRADE_SIZE = "ACCOUNT_MAX_TRADE_SIZE";
bytes32 constant TOKEN_MAX_BUY_SELL_VOLUME = "TOKEN_MAX_BUY_SELL_VOLUME";
bytes32 constant ACCOUNT_MIN_MAX_TOKEN_BALANCE = "ACCOUNT_MIN_MAX_TOKEN_BALANCE";
bytes32 constant ACC_MAX_VALUE_BY_ACCESS_LEVEL = "ACC_MAX_VALUE_BY_ACCESS_LEVEL";
bytes32 constant ACC_MAX_TX_VALUE_BY_RISK_SCORE = "ACC_MAX_TX_VALUE_BY_RISK_SCORE";
bytes32 constant TX_SIZE_BY_RISK = "TX_SIZE_BY_RISK";
bytes32 constant ACC_MAX_VALUE_BY_RISK_SCORE = "ACC_MAX_VALUE_BY_RISK_SCORE";
bytes32 constant BUY_PERCENT = "BUY_PERCENT";
bytes32 constant SELL_PERCENT = "SELL_PERCENT";
bytes32 constant BUY_FEE_BY_VOLUME = "BUY_FEE_BY_VOLUME";
bytes32 constant TOKEN_VOLATILITY = "TOKEN_VOLATILITY";
bytes32 constant TOKEN_MAX_TRADING_VOLUME = "TOKEN_MAX_TRADING_VOLUME";
bytes32 constant TOKEN_MIN_TX_SIZE = "TOKEN_MIN_TX_SIZE";
bytes32 constant TOKEN_MAX_SUPPLY_VOLATILITY = "TOKEN_MAX_SUPPLY_VOLATILITY";
bytes32 constant ACCOUNT_APPROVE_DENY_ORACLE = "ACCOUNT_APPROVE_DENY_ORACLE";
bytes32 constant TOKEN_MAX_DAILY_TRADES = "TOKEN_MAX_DAILY_TRADES";
bytes32 constant ACC_MAX_VALUE_OUT_ACCESS_LEVEL = "ACC_MAX_VALUE_OUT_ACCESS_LEVEL";
bytes32 constant TOKEN_MIN_HOLD_TIME = "TOKEN_MIN_HOLD_TIME";
bytes32 constant ACCOUNT_DENY_FOR_NO_ACCESS_LEVEL = "ACCOUNT_DENY_FOR_NO_ACCESS_LEVEL";
bytes32 constant PAUSE_RULE = "PAUSE_RULE";
bytes32 constant TRADE_RULE_ORACLE_LIST = "TRADE_RULE_ORACLE_LIST";

enum ORACLE_TYPE {
    DENIED_LIST,
    APPROVED_LIST
}
