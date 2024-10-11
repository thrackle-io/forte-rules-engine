// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;
// import "./IRuleStorage.sol";
import "src/client/token/handler/diamond/RuleStorage.sol";

/**
 * @title Rules Storage Library
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev This contract serves as the storage library for the rules Diamond. It basically serves up the storage position for all rules
 * @notice Library for Rules
 */
library StorageLib {
    bytes32 constant DIAMOND_CUT_STORAGE_HANDLER_POS = bytes32(uint256(keccak256("diamond-cut.storage-handler")) - 1);
    bytes32 constant ACCOUNT_APPROVE_DENY_ORACLE_HANDLER_POSITION = bytes32(uint256(keccak256("account-approve-deny-oracle-position")) - 1);
    bytes32 constant ACCOUNT_APPROVE_DENY_ORACLE_FLEXIBLE_HANDLER_POSITION = bytes32(uint256(keccak256("account-approve-deny-oracle-flexible-position")) - 1);
    bytes32 constant ACCOUNT_MIN_MAX_TOKEN_BALANCE_HANDLER_POSITION = bytes32(uint256(keccak256("account-min-max-token-balance-position")) - 1);
    bytes32 constant HANDLER_BASE_POSITION = bytes32(uint256(keccak256("handler-base-position")) - 1);    
    bytes32 constant FEES_HANDLER_POSITION = bytes32(uint256(keccak256("fees-position")) - 1);
    bytes32 constant TOKEN_MAX_SUPPLY_VOLATILITY_HANDLER_POSITION = bytes32(uint256(keccak256("token-max-supply-volatility-position")) - 1);
    bytes32 constant TOKEN_MAX_TRADING_VOLUME_HANDLER_POSITION = bytes32(uint256(keccak256("token-max-trading-volume-position")) - 1);
    bytes32 constant TOKEN_MIN_TX_SIZE_HANDLER_POSITION = bytes32(uint256(keccak256("token-min-tx-size-position")) - 1);
    bytes32 constant TOKEN_MIN_HOLD_TIME_HANDLER_POSITION = bytes32(uint256(keccak256("token-min-hold-time-position")) - 1);
    bytes32 constant TOKEN_MAX_DAILY_TRADES_HANDLER_POSITION = bytes32(uint256(keccak256("nft-max-daily-trades-position")) - 1);
    bytes32 constant NFT_VALUATION_LIMIT_POSITION = bytes32(uint256(keccak256("nft-valuation-position")) - 1);
    bytes32 constant INITIALIZED_POSITION = bytes32(uint256(keccak256("initialized-position")) - 1);
    bytes32 constant TOKEN_MAX_BUY_SELL_VOLUME_HANDLER_POSITION = bytes32(uint256(keccak256("token-max-buy-sell-position")) - 1);
    bytes32 constant ACCOUNT_MAX_TRADE_SIZE_HANDLER_POSITION = bytes32(uint256(keccak256("account-max-trading-size-handler-postion")) - 1);
    bytes32 constant HANDLER_VERSION_POSITION = bytes32(uint256(keccak256("handler-version-position")) - 1);


    /**
     * @dev Function to store the Initialized flag
     * @return ds Data Storage of the Initialized flag
     */
    function handlerVersionStorage() internal pure returns (HandlerVersionS storage ds) {
        bytes32 position = HANDLER_VERSION_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store the Initialized flag
     * @return ds Data Storage of the Initialized flag
     */
    function initializedStorage() internal pure returns (InitializedS storage ds) {
        bytes32 position = INITIALIZED_POSITION;
        assembly {
            ds.slot := position
        }
    }
    
    /**
     * @dev Function to store Handler Base
     * @return ds Data Storage of Handler Base
     */
    function handlerBaseStorage() internal pure returns (HandlerBaseS storage ds) {
        bytes32 position = HANDLER_BASE_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store the fees
     * @return ds Data Storage of Fees
     */
    function feeStorage() internal pure returns (FeeS storage ds) {
        bytes32 position = FEES_HANDLER_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Max Trade Size rules
     * @return ds Data Storage of Max Trade Size Rule
     */
    function accountMaxTradeSizeStorage() internal pure returns (AccountMaxTradeSizeS storage ds) {
        bytes32 position = ACCOUNT_MAX_TRADE_SIZE_HANDLER_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Token Max Buy Sell Volume rules
     * @return ds Data Storage of Token Max Buy Sell Volume Rule
     */
    function tokenMaxBuySellVolumeStorage() internal pure returns (TokenMaxBuySellVolumeS storage ds) {
        bytes32 position = TOKEN_MAX_BUY_SELL_VOLUME_HANDLER_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Max Trading Volume rules
     * @return ds Data Storage of Max Trading Volume Rule
     */
    function tokenMaxTradingVolumeStorage() internal pure returns (TokenMaxTradingVolumeS storage ds) {
        bytes32 position = TOKEN_MAX_TRADING_VOLUME_HANDLER_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Max Daily Trade rules
     * @return ds Data Storage of Max Daily Trade Rule
     */
    function tokenMaxDailyTradesStorage() internal pure returns (TokenMaxDailyTradesS storage ds) {
        bytes32 position = TOKEN_MAX_DAILY_TRADES_HANDLER_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Token Min Transaction Size rules
     * @return ds Data Storage of Token Min Transaction Size Rule
     */
    function tokenMinTxSizeStorage() internal pure returns (TokenMinTxSizeS storage ds) {
        bytes32 position = TOKEN_MIN_TX_SIZE_HANDLER_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Account Min Max Token Balance rules
     * @return ds Data Storage of Account Min Max Token Balance Rule
     */
    function accountMinMaxTokenBalanceStorage() internal pure returns (AccountMinMaxTokenBalanceHandlerS storage ds) {
        bytes32 position = ACCOUNT_MIN_MAX_TOKEN_BALANCE_HANDLER_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Max Supply Volitility rules
     * @return ds Data Storage of Max Supply Volitility Rule
     */
    function tokenMaxSupplyVolatilityStorage() internal pure returns (TokenMaxSupplyVolatilityS storage ds) {
        bytes32 position = TOKEN_MAX_SUPPLY_VOLATILITY_HANDLER_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Oracle rules
     * @return ds Data Storage of Oracle Rule
     */
    function accountApproveDenyOracleStorage() internal pure returns (AccountApproveDenyOracleS storage ds) {
        bytes32 position = ACCOUNT_APPROVE_DENY_ORACLE_HANDLER_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Oracle Flexible rules
     * @return ds Data Storage of Oracle Flexible Rule
     */
    function accountApproveDenyOracleFlexibleStorage() internal pure returns (AccountApproveDenyOracleFlexibleS storage ds) {
        bytes32 position = ACCOUNT_APPROVE_DENY_ORACLE_FLEXIBLE_HANDLER_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store Token Min Hold Time
     * @return ds Data Storage of Token Min Hold Time
     */
    function tokenMinHoldTimeStorage() internal pure returns (TokenMinHoldTimeS storage ds) {
        bytes32 position = TOKEN_MIN_HOLD_TIME_HANDLER_POSITION;
        assembly {
            ds.slot := position
        }
    }

    /**
     * @dev Function to store NFT Valuation Limit storage
     * @return ds Data Storage of NFT Valuation Limit
     */
    function nftValuationLimitStorage() internal pure returns (NFTValuationLimitS storage ds) {
        bytes32 position = NFT_VALUATION_LIMIT_POSITION;
        assembly {
            ds.slot := position
        }
    }

}
