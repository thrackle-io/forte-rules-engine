// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/**
 * @title Rule Interfaces
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev data structures of each rule in the protocol, grouped by rule subset
 * (NonTagged Rules, Tagged rules, AccessLevel rules, Risk rules, and Fee rules)
 */

interface INonTaggedRules {
    /// ******** Token Min Tx Size Rules ********
    struct TokenMinTxSize {
        uint256 minSize;
    }

    /// ******** Token Max Buy Sell Volume Rules ********
    struct TokenMaxBuySellVolume {
        uint16 tokenPercentage; /// from 0000 to 10000 => 0.00% to 100.00%.
        uint16 period;
        uint256 totalSupply; /// set 0 to use erc20 totalSupply
        uint64 startTime; ///start of time period for the rule
    }

    /// ******** Token Purchase Fee By Volume Rules ********
    struct TokenPurchaseFeeByVolume {
        uint256 volume;
        uint16 rateIncreased; /// from 0000 to 10000 => 0.00% to 100.00%.
    }

    /// ******** Token Max Price Volatility ********
    struct TokenMaxPriceVolatility {
        uint16 max; /// from 0000 to 10000 => 0.00% to 100.00%.
        uint16 period; /// hours
        uint16 hoursFrozen; /// hours in the freeze period
        uint256 totalSupply; /// If specified, this is the circulating supply value to use. If not specified, it defaults to ERC20 totalSupply.
    }

    /// ******** Token Max Trading Volume ********
    struct TokenMaxTradingVolume {
        uint24 max; /// this is a percentage with 2 decimals of precision(2500 = 25%)
        uint16 period; /// hours
        uint64 startTime; /// UNIX date MUST be at a time with 0 minutes, 0 seconds. i.e: 20:00 on Jan 01 2024(basically 0-23)
        uint256 totalSupply; /// If specified, this is the circulating supply value to use. If not specified, it defaults to ERC20 totalSupply.
    }

    /// ******** Supply Volatility ********
    struct TokenMaxSupplyVolatility {
        uint16 max; /// from 0000 to 10000 => 0.00% to 100.00%.
        uint16 period; /// hours
        uint64 startTime; /// UNIX date MUST be at a time with 0 minutes, 0 seconds. i.e: 20:00 on Jan 01 2024(basically 0-23)
        uint256 totalSupply; /// If specified, this is the circulating supply value to use. If not specified, it defaults to ERC20 totalSupply.
    }

    /// ******** Account Approve/Deny Oracle ********
    struct AccountApproveDenyOracle {
        uint8 oracleType; /// enum value --> 0 = restricted; 1 = allowed
        address oracleAddress;
    }

    /// ******** Account Approve/Deny Oracle ********
    struct AccountApproveDenyOracleFlexible {
        uint8 oracleType; /// enum value --> 0 = restricted; 1 = allowed
        uint8 addressToggle;
        address oracleAddress;
    }

    /// ******** Token Min Hold Time ********
    struct TokenMinHoldTime {
        uint32 minHoldTime; /// from 0000 to 43830
    }
}

interface ITaggedRules {
    /// ******** Account Max Trade Size ********
    struct AccountMaxTradeSize {
        uint240 maxSize; /// token units
        uint16 period; /// hours
    }

    /// ******** Account Min Max Token Balance ********
    struct AccountMinMaxTokenBalance {
        uint256 min;
        uint256 max;
        uint16 period; /// hours
    }

    /// ******** TokenMaxDailyTrades ********
    struct TokenMaxDailyTrades {
        uint8 tradesAllowedPerDay;
        uint64 startTime; /// starting timestamp for the rule
    }
}

interface IFeeRules {
    struct AMMFeeRule {
        uint256 feePercentage; /// intended to be 3 digits(true percentage = feePercentage/100)
    }
}

interface IApplicationRules {
    /// ******** Account Max Transaction Value ByRisk Score Rules ********
    /**
     * @dev maxValue size must be equal to _riskScore
     * The positioning of the arrays is ascendant in terms of risk scores,
     * and descendant in the size of transactions. (i.e. if highest risk score is 99, the last balanceLimit
     * will apply to all risk scores of 100.)
     */
    struct AccountMaxTxValueByRiskScore {
        uint48[] maxValue; /// whole USD (no cents) -> 1 = 1 USD (Max allowed: 281 trillion USD)
        uint8[] riskScore;
        uint16 period; // hours
        uint64 startTime; // UNIX date MUST be at a time with 0 minutes, 0 seconds. i.e: 20:00 on Jan 01 2024
    }

    /// ******** Account Max Value By Risk Score Rules ********
    struct AccountMaxValueByRiskScore {
        uint8[] riskScore; //
        uint48[] maxValue; /// whole USD (no cents) -> 1 = 1 USD (Max allowed: 281 trillion USD)
    }
}
