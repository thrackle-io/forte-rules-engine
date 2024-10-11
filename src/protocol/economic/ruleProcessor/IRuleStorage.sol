// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {INonTaggedRules, ITaggedRules, IFeeRules, IApplicationRules} from "src/protocol/economic/ruleProcessor/RuleDataInterfaces.sol";
import "src/common/ActionEnum.sol";

/**
 * @title IRuleStorage
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev The data structure of each rule storage inside the diamond.
 * @notice This interface outlines the storage structures for each rule stored in diamond
 */
interface IRuleStorage {
    /**
     * Note The following are market-related oppertation rules. Checks depend on the
     * accuracy of the method to determine when a transfer is part of a trade and what
     * direction it is taking (buy or sell).
     */
    /// ******** Account Max Trade Sizes ********
    struct AccountMaxTradeSizeS {
        /// ruleIndex => userType => rules
        mapping(uint32 => mapping(bytes32 => ITaggedRules.AccountMaxTradeSize)) accountMaxTradeSizeRules;
        mapping(uint32 => uint64) startTimes; ///Time the rule is applied
        uint32 accountMaxTradeSizeIndex;
    }

    /// ******** Token Max Buy Sell Volume ********
    struct TokenMaxBuySellVolumeS {
        mapping(uint32 => INonTaggedRules.TokenMaxBuySellVolume) tokenMaxBuySellVolumeRules;
        uint32 tokenMaxBuySellVolumeIndex;
    }

    /// ******** Token Purchase Fee By Volume Rules ********
    struct PurchaseFeeByVolRuleS {
        mapping(uint32 => INonTaggedRules.TokenPurchaseFeeByVolume) purchaseFeeByVolumeRules;
        uint32 purchaseFeeByVolumeRuleIndex;
    }

    /// ******** Token Max Price Volatility ********
    struct TokenMaxPriceVolatilityS {
        mapping(uint32 => INonTaggedRules.TokenMaxPriceVolatility) tokenMaxPriceVolatilityRules;
        uint32 tokenMaxPriceVolatilityIndex;
    }

    /// ******** Token Max Trading Volume ********
    struct TokenMaxTradingVolumeS {
        mapping(uint32 => INonTaggedRules.TokenMaxTradingVolume) tokenMaxTradingVolumeRules;
        uint32 tokenMaxTradingVolumeIndex;
    }

    /// ******** Token Min Tx Size ********
    struct TokenMinTxSizeS {
        mapping(uint32 => INonTaggedRules.TokenMinTxSize) tokenMinTxSizeRules;
        uint32 tokenMinTxSizeIndex;
    }

    /// ******** Account Minimum/Maximum Token Balance ********
    struct AccountMinMaxTokenBalanceS {
        mapping(uint32 => mapping(bytes32 => ITaggedRules.AccountMinMaxTokenBalance)) accountMinMaxTokenBalanceRules;
        mapping(uint32 => uint64) startTimes; ///Time the rule is applied
        uint32 accountMinMaxTokenBalanceIndex;
    }

    /// ******** Token Max Supply Volatility ********
    struct TokenMaxSupplyVolatilityS {
        mapping(uint32 => INonTaggedRules.TokenMaxSupplyVolatility) tokenMaxSupplyVolatilityRules;
        uint32 tokenMaxSupplyVolatilityIndex;
    }

    /// ******** Account Approve/Deny Oracle ********
    struct AccountApproveDenyOracleS {
        mapping(uint32 => INonTaggedRules.AccountApproveDenyOracle) accountApproveDenyOracleRules;
        uint32 accountApproveDenyOracleIndex;
    }

    /// ******** Account Approve/Deny Oracle ********
    struct AccountApproveDenyOracleFlexibleS {
        mapping(uint32 => INonTaggedRules.AccountApproveDenyOracleFlexible) accountApproveDenyOracleFlexibleRules;
        uint32 accountApproveDenyOracleFlexibleIndex;
    }

    /// ******** Token Min Hold Time ********
    struct TokenMinHoldTimeS {
        mapping(uint32 => INonTaggedRules.TokenMinHoldTime) tokenMinHoldTimeRules;
        uint32 tokenMinHoldTimeIndex;
    }

    /*****************************************
    ************* AccessLevel Rules ***********
    /*****************************************/

    /// ******** Account Max Value by Access Level ********
    struct AccountMaxValueByAccessLevelS {
        mapping(uint32 => mapping(uint8 => uint48)) accountMaxValueByAccessLevelRules;
        uint32 accountMaxValueByAccessLevelIndex;
    }

    /// ******** Account Max Value Out by Access Level ********
    struct AccountMaxValueOutByAccessLevelS {
        mapping(uint32 => mapping(uint8 => uint48)) accountMaxValueOutByAccessLevelRules;
        uint32 accountMaxValueOutByAccessLevelIndex;
    }

    /*****************************************
    *************** NFT Rules ****************
    /*****************************************/

    /// ******** Token Max Daily Trades ********
    struct TokenMaxDailyTradesS {
        /// ruleIndex => taggedNFT => tradesAllowed
        mapping(uint32 => mapping(bytes32 => ITaggedRules.TokenMaxDailyTrades)) tokenMaxDailyTradesRules;
        uint32 tokenMaxDailyTradesIndex;
    }

    /*****************************************
    *************** Risk Rules ****************
    /*****************************************/

    /// ******** Account Max Value By Risk Score Rules ********
    struct AccountMaxValueByRiskScoreS {
        mapping(uint32 => IApplicationRules.AccountMaxValueByRiskScore) accountMaxValueByRiskScoreRules;
        uint32 accountMaxValueByRiskScoreIndex;
    }

    /// ******** Account Max Transaction Value By Period Rules ********
    struct AccountMaxTxValueByRiskScoreS {
        mapping(uint32 => IApplicationRules.AccountMaxTxValueByRiskScore) accountMaxTxValueByRiskScoreRules;
        uint32 accountMaxTxValueByRiskScoreIndex;
    }

    /*****************************************
    *************** Fee Rules ****************
    /*****************************************/

    /// ******** AMM Fee Rule ********
    struct AMMFeeRuleS {
        mapping(uint32 => IFeeRules.AMMFeeRule) ammFeeRules;
        uint32 ammFeeRuleIndex;
    }

    /// ******** Storage of RuleApplicationValidationFacet ********
    struct EnabledActions {
        mapping(bytes32 => mapping(ActionTypes => bool)) isActionEnabled;
    }
}
