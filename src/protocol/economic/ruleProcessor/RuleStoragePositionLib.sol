// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/protocol/economic/ruleProcessor/IRuleStorage.sol";

/**
 * @title Rules Storage Library
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev This contract serves as the storage library for the rules Diamond. It basically serves up the storage position for all rules
 * @notice Library for Rules
 */
library RuleStoragePositionLib {
    bytes32 constant DIAMOND_CUT_STORAGE_POSITION = bytes32(uint256(keccak256("diamond-cut.storage")) - 1);
    /// every rule has its own storage
    bytes32 constant ACCOUNT_MAX_TRADE_SIZE = bytes32(uint256(keccak256("account-max-trade-volume")) - 1);
    bytes32 constant ACCOUNT_MAX_BUY_SELL_VOLUME_POSITION = bytes32(uint256(keccak256("account-max-buy-sell-volume")) - 1);
    bytes32 constant BUY_FEE_BY_TOKEN_MAX_TRADING_VOLUME_POSITION = bytes32(uint256(keccak256("amm.fee-by-volume")) - 1);
    bytes32 constant TOKEN_MAX_PRICE_VOLATILITY_POSITION = bytes32(uint256(keccak256("token-max-price-volatility")) - 1);
    bytes32 constant TOKEN_MAX_TRADING_VOLUME_POSITION = bytes32(uint256(keccak256("token-max-trading-volume")) - 1);
    bytes32 constant TOKEN_MIN_TX_SIZE_POSITION = bytes32(uint256(keccak256("token-min-tx-size")) - 1);
    bytes32 constant TOKEN_MIN_HOLD_TIME_POSITION = bytes32(uint256(keccak256("token-min-hold-time")) - 1);
    bytes32 constant ACCOUNT_MIN_MAX_TOKEN_BALANCE_POSITION = bytes32(uint256(keccak256("account-min-max-token-balance")) - 1);
    bytes32 constant TOKEN_MAX_SUPPLY_VOLATILITY_POSITION = bytes32(uint256(keccak256("token-max-supply-volatility")) - 1);
    bytes32 constant ACC_APPROVE_DENY_ORACLE_POSITION = bytes32(uint256(keccak256("account-approve-deny-oracle")) - 1);
    bytes32 constant ACC_APPROVE_DENY_ORACLE_FLEXIBLE_POSITION = bytes32(uint256(keccak256("account-approve-deny-oracle-flexible")) - 1);
    bytes32 constant ACC_MAX_VALUE_BY_ACCESS_LEVEL_POSITION = bytes32(uint256(keccak256("account-max-value-by-access-level")) - 1);
    bytes32 constant ACC_MAX_TX_VALUE_BY_RISK_SCORE_POSITION = bytes32(uint256(keccak256("account-max-transaction-value-by-access-level")) - 1);
    bytes32 constant ACCOUNT_MAX_VALUE_BY_RISK_SCORE_POSITION = bytes32(uint256(keccak256("account-max-value-by-risk-score")) - 1);
    bytes32 constant TOKEN_MAX_DAILY_TRADES_POSITION = bytes32(uint256(keccak256("token-max-daily-trades")) - 1);
    bytes32 constant AMM_FEE_RULE_POSITION = bytes32(uint256(keccak256("AMM.fee-rule")) - 1);
    bytes32 constant ACC_MAX_VALUE_OUT_ACCESS_LEVEL_POSITION = bytes32(uint256(keccak256("account-max-value-out-by-access-level")) - 1);
    bytes32 constant ENABLED_ACTIONS = bytes32(uint256(keccak256("enabled-actions")) - 1);

    /**
     * @dev Function to store Trade rules
     * @return ds Data Storage of Trade Rule
     */
    function accountMaxTradeSizeStorage() internal pure returns (IRuleStorage.AccountMaxTradeSizeS storage ds) {
        bytes32 position = ACCOUNT_MAX_TRADE_SIZE;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Account Max Buy Volume rules
     * @return ds Data Storage of Account Max Buy Volume Rule
     */
    function accountMaxBuySellVolumeStorage() internal pure returns (IRuleStorage.TokenMaxBuySellVolumeS storage ds) {
        bytes32 position = ACCOUNT_MAX_BUY_SELL_VOLUME_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Purchase Fee by Volume rules
     * @return ds Data Storage of Purchase Fee by Volume Rule
     */
    function purchaseFeeByVolumeStorage() internal pure returns (IRuleStorage.PurchaseFeeByVolRuleS storage ds) {
        bytes32 position = BUY_FEE_BY_TOKEN_MAX_TRADING_VOLUME_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Price Volitility rules
     * @return ds Data Storage of Price Volitility Rule
     */
    function tokenMaxPriceVolatilityStorage() internal pure returns (IRuleStorage.TokenMaxPriceVolatilityS storage ds) {
        bytes32 position = TOKEN_MAX_PRICE_VOLATILITY_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Max Trading Volume rules
     * @return ds Data Storage of Max Trading Volume Rule
     */
    function tokenMaxTradingVolumeStorage() internal pure returns (IRuleStorage.TokenMaxTradingVolumeS storage ds) {
        bytes32 position = TOKEN_MAX_TRADING_VOLUME_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Token Min Transaction Size rules
     * @return ds Data Storage of Token Min Transaction Size Rule
     */
    function tokenMinTxSizePosition() internal pure returns (IRuleStorage.TokenMinTxSizeS storage ds) {
        bytes32 position = TOKEN_MIN_TX_SIZE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Account Min Max Token Balance rules
     * @return ds Data Storage of Account Min Max Token Balance Rule
     */
    function accountMinMaxTokenBalanceStorage() internal pure returns (IRuleStorage.AccountMinMaxTokenBalanceS storage ds) {
        bytes32 position = ACCOUNT_MIN_MAX_TOKEN_BALANCE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Max Supply Volitility rules
     * @return ds Data Storage of Max Supply Volitility Rule
     */
    function tokenMaxSupplyVolatilityStorage() internal pure returns (IRuleStorage.TokenMaxSupplyVolatilityS storage ds) {
        bytes32 position = TOKEN_MAX_SUPPLY_VOLATILITY_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Oracle rules
     * @return ds Data Storage of Oracle Rule
     */
    function accountApproveDenyOracleStorage() internal pure returns (IRuleStorage.AccountApproveDenyOracleS storage ds) {
        bytes32 position = ACC_APPROVE_DENY_ORACLE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Flexible Oracle rules
     * @return ds Data Storage of Flexible Oracle Rule
     */
    function accountApproveDenyOracleFlexibleStorage() internal pure returns (IRuleStorage.AccountApproveDenyOracleFlexibleS storage ds) {
        bytes32 position = ACC_APPROVE_DENY_ORACLE_FLEXIBLE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Account Max Value Access Level rules
     * @return ds Data Storage of Account Max Value Access Level Rule
     */
    function accountMaxValueByAccessLevelStorage() internal pure returns (IRuleStorage.AccountMaxValueByAccessLevelS storage ds) {
        bytes32 position = ACC_MAX_VALUE_BY_ACCESS_LEVEL_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Account Max Tx Value by Risk rules
     * @return ds Data Storage of Account Max Tx Value by Risk Rule
     */
    function accountMaxTxValueByRiskScoreStorage() internal pure returns (IRuleStorage.AccountMaxTxValueByRiskScoreS storage ds) {
        bytes32 position = ACC_MAX_TX_VALUE_BY_RISK_SCORE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Token Min Hold Time rules
     * @return ds Data Storage of Token Min Hold Time Rule
     */
    function tokenMinHoldTimeStorage() internal pure returns (IRuleStorage.TokenMinHoldTimeS storage ds) {
        bytes32 position = TOKEN_MIN_HOLD_TIME_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Account Max Value By Risk Score rules
     * @return ds Data Storage of Account Max Value By Risk Score Rule
     */
    function accountMaxValueByRiskScoreStorage() internal pure returns (IRuleStorage.AccountMaxValueByRiskScoreS storage ds) {
        bytes32 position = ACCOUNT_MAX_VALUE_BY_RISK_SCORE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Token Max Daily Trades rules
     * @return ds Data Storage of Token Max Daily Trades rule
     */
    function TokenMaxDailyTradesStorage() internal pure returns (IRuleStorage.TokenMaxDailyTradesS storage ds) {
        bytes32 position = TOKEN_MAX_DAILY_TRADES_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store AMM Fee rules
     * @return ds Data Storage of AMM Fee rule
     */
    function ammFeeRuleStorage() internal pure returns (IRuleStorage.AMMFeeRuleS storage ds) {
        bytes32 position = AMM_FEE_RULE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Account Max Value Out By Access Level rules
     * @return ds Data Storage of Account Max Value Out By Access Level rule
     */
    function accountMaxValueOutByAccessLevelStorage() internal pure returns (IRuleStorage.AccountMaxValueOutByAccessLevelS storage ds) {
        bytes32 position = ACC_MAX_VALUE_OUT_ACCESS_LEVEL_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to access storage for EnabledActions
     * @return ds Data Storage for RuleApplicationValidationFacet - EnabledActions
     */
    function enabledActions() internal pure returns (IRuleStorage.EnabledActions storage ds) {
        bytes32 position = ENABLED_ACTIONS;
        assembly {
            ds.slot := position
        }
    }
}
