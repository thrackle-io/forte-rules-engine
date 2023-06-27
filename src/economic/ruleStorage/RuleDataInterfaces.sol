// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

/**
 * @title Rule Interfaces
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev data structures of each rule in the protocol, grouped by rule subset
 * (NonTagged Rules, Tagged rules, AccessLevel rules, Risk rules, and Fee rules)
 */

interface INonTaggedRules {
    /// ******** Token Minimum Transfer Rules ********
    struct TokenMinimumTransferRule {
        uint256 minTransferAmount;
    }

    /// ******** Token Purchase Percentage Rules ********
    struct TokenPercentagePurchaseRule {
        uint16 tokenPercentage; /// from 0000 to 10000 => 0.00% to 100.00%.
        uint32 purchasePeriod;
        uint256 totalSupply; /// set 0 to use erc20 totalSupply
        uint64 startTime; /// start of time period for the rule
    }

    /// ******** Token Percentage Sell Rules ********
    struct TokenPercentageSellRule {
        uint16 tokenPercentage; /// from 0000 to 10000 => 0.00% to 100.00%.
        uint32 sellPeriod;
        uint256 totalSupply; /// set 0 to use erc20 totalSupply
        uint64 startTime; ///start of time period for the rule
    }

    /// ******** Token Purchase Fee By Volume Rules ********
    struct TokenPurchaseFeeByVolume {
        uint256 volume;
        uint16 rateIncreased; /// from 0000 to 10000 => 0.00% to 100.00%.
    }

    /// ******** Token Volatility ********
    struct TokenVolatilityRule {
        uint16 maxVolatility; /// from 0000 to 10000 => 0.00% to 100.00%.
        uint8 blocksPerPeriod;
        uint8 hoursFrozen;
    }

    /// ******** Token Trading Volume ********
    struct TokenTradingVolumeRule {
        uint256 maxVolume;
        uint8 hoursPerPeriod;
        uint8 hoursFrozen;
    }
    /// ******** Token Transfer Volume ********
    struct TokenTransferVolumeRule {
        uint16 maxVolume; // this is a percentage with 2 decimals of precision(2500 = 25%)
        uint8 period; // hours
        uint64 startingTime; // UNIX date MUST be at a time with 0 minutes, 0 seconds. i.e: 20:00 on Jan 01 2024(basically 0-23)
        uint256 totalSupply; // If specified, this is the circulating supply value to use. If not specified, it defaults to ERC20 totalSupply.
    }
    /// ******** Supply Volatility ********
    struct SupplyVolatilityRule {
        uint16 maxChange; /// from 0000 to 10000 => 0.00% to 100.00%.
        uint8 hoursPerPeriod;
        uint8 hoursFrozen;
    }
    /// ******** Oracle ********
    struct OracleRule {
        uint8 oracleType; /// enum value
        address oracleAddress;
    }
    /// ******** NFT ********
    struct NFTTradeCounterRule {
        uint8 tradesAllowedPerDay;
        bool active; // this is here for an easy check to determine that the rule exists and is on. It's to account for tradesAllowedPerDay = 0
    }
}

interface ITaggedRules {
    /// ******** Account Purchase Rules ********
    struct PurchaseRule {
        uint256 purchaseAmount; /// token units
        uint32 purchasePeriod; /// hours
        uint64 startTime; ///Time the rule is created
    }

    /// ******** Account Sell Rules ********
    struct SellRule {
        uint256 sellAmount; /// token units
        uint32 sellPeriod; /// hours
        uint64 startTime; /// Time the rule is created
    }
    /// ******** Account Withdrawal Rules ********
    struct WithdrawalRule {
        uint256 amount;
        uint256 releaseDate; /// timestamp
    }

    /// ******** Minimum/Maximum Account Balances ********
    struct BalanceLimitRule {
        uint256 minimum;
        uint256 maximum;
    }

    /// ******** Admin Withdrawal Rules ********
    struct AdminWithdrawalRule {
        uint256 amount;
        uint256 releaseDate; /// timestamp
    }
    /// ******** Transaction Size Rules ********
    struct TransactionSizeToRiskRule {
        uint8[] riskLevel;
        uint48[] maxSize; /// whole USD (no cents) -> 1 = 1 USD (Max allowed: 281 trillion USD)
    }
    /// ******** Minimum Balance By Date Rules ********
    struct MinBalByDateRule {
        uint256 holdAmount; /// token units
        uint256 holdPeriod; /// hours
        uint256 startTimeStamp; /// start
    }
}

interface IFeeRules {
    struct AMMFeeRule {
        uint256 feePercentage; // intended to be 3 digits(true percentage = feePercentage/100)
    }
}

interface IApplicationRules {
    /// ******** Transaction Size Per Period Rules ********
    /**
     * @dev maxSize size must be equal to riskLevel size + 1.
     * This is because the maxSize should also specified the max tx
     * size allowed for anything between the highest risk level and 100
     * which is specified in the last position of the maxSize.
     * The positionning of the elements within the arrays has meaning.
     * The first element in the maxSize array corresponds to the risk
     * range between 0 and the risk score specified in the first position
     * of the riskLevel array (exclusive). The last maxSize value
     * will represent the max tx size allowed for any risk score above
     * the risk level set in the last element of the riskLevel array.
     * Therefore, the order of the values inside the riskLevel
     * array must be ascendant.
     */
    struct TxSizePerPeriodToRiskRule {
        uint48[] maxSize; /// whole USD (no cents) -> 1 = 1 USD (Max allowed: 281 trillion USD)
        uint8[] riskLevel;
        uint8 period; // hours
        uint64 startingTime; // UNIX date MUST be at a time with 0 minutes, 0 seconds. i.e: 20:00 on Jan 01 2024
    }

    /// ******** Account Balance Rules By Risk Score ********
    struct AccountBalanceToRiskRule {
        uint8[] riskLevel; //
        uint48[] maxBalance; /// whole USD (no cents) -> 1 = 1 USD (Max allowed: 281 trillion USD)
    }
}
