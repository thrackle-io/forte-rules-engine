# IRuleStorage
[Git Source](https://github.com/thrackle-io/tron/blob/ee06788a23623ed28309de5232eaff934d34a0fe/src/protocol/economic/ruleProcessor/IRuleStorage.sol)

**Author:**
@ShaneDuncan602 @oscarsernarosero @TJ-Everett

This interface outlines the storage structures for each rule stored in diamond

*The data structure of each rule storage inside the diamond.*


## Structs
### PurchaseRuleS
Note The following are market-related rules. Checks must be
made in AMMs rather than at token level.


```solidity
struct PurchaseRuleS {
    mapping(uint32 => mapping(bytes32 => ITaggedRules.PurchaseRule)) purchaseRulesPerUser;
    mapping(uint32 => uint64) startTimes;
    uint32 purchaseRulesIndex;
}
```

### SellRuleS
******** Account Sell Rules ********


```solidity
struct SellRuleS {
    mapping(uint32 => mapping(bytes32 => ITaggedRules.SellRule)) sellRulesPerUser;
    mapping(uint32 => uint64) startTimes;
    uint32 sellRulesIndex;
}
```

### PctPurchaseRuleS
******** Token Purchase Percentage Rules ********


```solidity
struct PctPurchaseRuleS {
    mapping(uint32 => INonTaggedRules.TokenPercentagePurchaseRule) percentagePurchaseRules;
    uint32 percentagePurchaseRuleIndex;
}
```

### PctSellRuleS
******** Token Percentage Sell Rules ********


```solidity
struct PctSellRuleS {
    mapping(uint32 => INonTaggedRules.TokenPercentageSellRule) percentageSellRules;
    uint32 percentageSellRuleIndex;
}
```

### PurchaseFeeByVolRuleS
******** Token Purchase Fee By Volume Rules ********


```solidity
struct PurchaseFeeByVolRuleS {
    mapping(uint32 => INonTaggedRules.TokenPurchaseFeeByVolume) purchaseFeeByVolumeRules;
    uint32 purchaseFeeByVolumeRuleIndex;
}
```

### VolatilityRuleS
******** Token Volatility ********


```solidity
struct VolatilityRuleS {
    mapping(uint32 => INonTaggedRules.TokenVolatilityRule) volatilityRules;
    uint32 volatilityRuleIndex;
}
```

### TransferVolRuleS
******** Token Transfer Volume ********


```solidity
struct TransferVolRuleS {
    mapping(uint32 => INonTaggedRules.TokenTransferVolumeRule) transferVolumeRules;
    uint32 transferVolRuleIndex;
}
```

### WithdrawalRuleS
******** Withdrawal Rules ********


```solidity
struct WithdrawalRuleS {
    mapping(uint32 => mapping(bytes32 => ITaggedRules.WithdrawalRule)) withdrawalRulesPerToken;
    uint32 withdrawalRulesIndex;
}
```

### AdminWithdrawalRuleS
******** Admin Withdrawal Rules ********


```solidity
struct AdminWithdrawalRuleS {
    mapping(uint32 => ITaggedRules.AdminWithdrawalRule) adminWithdrawalRulesPerToken;
    uint32 adminWithdrawalRulesIndex;
}
```

### MinTransferRuleS
******** Minimum Transaction ********


```solidity
struct MinTransferRuleS {
    mapping(uint32 => INonTaggedRules.TokenMinimumTransferRule) minimumTransferRules;
    uint32 minimumTransferRuleIndex;
}
```

### MinMaxBalanceRuleS
******** Minimum/Maximum Account Balances ********


```solidity
struct MinMaxBalanceRuleS {
    mapping(uint32 => mapping(bytes32 => ITaggedRules.MinMaxBalanceRule)) minMaxBalanceRulesPerUser;
    uint32 minMaxBalanceRuleIndex;
}
```

### MinBalByDateRuleS
******** Minimum Balance By Date ********


```solidity
struct MinBalByDateRuleS {
    mapping(uint32 => mapping(bytes32 => ITaggedRules.MinBalByDateRule)) minBalByDateRulesPerUser;
    mapping(uint32 => uint64) startTimes;
    uint32 minBalByDateRulesIndex;
}
```

### SupplyVolatilityRuleS
******** Supply Volatility ********


```solidity
struct SupplyVolatilityRuleS {
    mapping(uint32 => INonTaggedRules.SupplyVolatilityRule) supplyVolatilityRules;
    uint32 supplyVolatilityRuleIndex;
}
```

### OracleRuleS
******** Oracle ********


```solidity
struct OracleRuleS {
    mapping(uint32 => INonTaggedRules.OracleRule) oracleRules;
    uint32 oracleRuleIndex;
}
```

### AccessLevelRuleS
AccessLevel Rules ***********
/****************************************
Balance Limit by Access Level


```solidity
struct AccessLevelRuleS {
    mapping(uint32 => mapping(uint8 => uint48)) accessRulesPerToken;
    uint32 accessRuleIndex;
}
```

### AccessLevelWithrawalRuleS
Withdrawal Limit by Access Level


```solidity
struct AccessLevelWithrawalRuleS {
    mapping(uint32 => mapping(uint8 => uint48)) accessLevelWithdrawal;
    uint32 accessLevelWithdrawalRuleIndex;
}
```

### NFTTransferCounterRuleS
NFT Rules ****************
/****************************************


```solidity
struct NFTTransferCounterRuleS {
    mapping(uint32 => mapping(bytes32 => ITaggedRules.NFTTradeCounterRule)) NFTTransferCounterRule;
    uint32 NFTTransferCounterRuleIndex;
}
```

### TxSizeToRiskRuleS
Risk Rules ****************
/****************************************
******** Transaction Size Rules ********


```solidity
struct TxSizeToRiskRuleS {
    mapping(uint32 => ITaggedRules.TransactionSizeToRiskRule) txSizeToRiskRule;
    uint32 txSizeToRiskRuleIndex;
}
```

### AccountBalanceToRiskRuleS
******** Account Balance Rules ********


```solidity
struct AccountBalanceToRiskRuleS {
    mapping(uint32 => IApplicationRules.AccountBalanceToRiskRule) balanceToRiskRule;
    uint32 balanceToRiskRuleIndex;
}
```

### TxSizePerPeriodToRiskRuleS
******** Transaction Size Per Period Rules ********


```solidity
struct TxSizePerPeriodToRiskRuleS {
    mapping(uint32 => IApplicationRules.TxSizePerPeriodToRiskRule) txSizePerPeriodToRiskRule;
    uint32 txSizePerPeriodToRiskRuleIndex;
}
```

### AMMFeeRuleS
Fee Rules ****************
/****************************************
******** AMM Fee Rule ********


```solidity
struct AMMFeeRuleS {
    mapping(uint32 => IFeeRules.AMMFeeRule) ammFeeRules;
    uint32 ammFeeRuleIndex;
}
```
