# RuleStoragePositionLib
[Git Source](https://github.com/thrackle-io/tron/blob/ee06788a23623ed28309de5232eaff934d34a0fe/src/protocol/economic/ruleProcessor/RuleStoragePositionLib.sol)

**Author:**
@ShaneDuncan602 @oscarsernarosero @TJ-Everett

Library for Rules

*This contract serves as the storage library for the rules Diamond. It basically serves up the storage position for all rules*


## State Variables
### DIAMOND_CUT_STORAGE_POSITION

```solidity
bytes32 constant DIAMOND_CUT_STORAGE_POSITION = bytes32(uint256(keccak256("diamond-cut.storage")) - 1);
```


### PURCHASE_RULE_POSITION
every rule has its own storage


```solidity
bytes32 constant PURCHASE_RULE_POSITION = bytes32(uint256(keccak256("amm.purchase")) - 1);
```


### SELL_RULE_POSITION

```solidity
bytes32 constant SELL_RULE_POSITION = bytes32(uint256(keccak256("amm.sell")) - 1);
```


### PCT_PURCHASE_RULE_POSITION

```solidity
bytes32 constant PCT_PURCHASE_RULE_POSITION = bytes32(uint256(keccak256("amm.pct-purchase")) - 1);
```


### PCT_SELL_RULE_POSITION

```solidity
bytes32 constant PCT_SELL_RULE_POSITION = bytes32(uint256(keccak256("amm.pct.sell")) - 1);
```


### PURCHASE_FEE_BY_VOLUME_RULE_POSITION

```solidity
bytes32 constant PURCHASE_FEE_BY_VOLUME_RULE_POSITION = bytes32(uint256(keccak256("amm.fee-by-volume")) - 1);
```


### PRICE_VOLATILITY_RULE_POSITION

```solidity
bytes32 constant PRICE_VOLATILITY_RULE_POSITION = bytes32(uint256(keccak256("amm.price.volatility")) - 1);
```


### VOLUME_RULE_POSITION

```solidity
bytes32 constant VOLUME_RULE_POSITION = bytes32(uint256(keccak256("amm.volume")) - 1);
```


### WITHDRAWAL_RULE_POSITION

```solidity
bytes32 constant WITHDRAWAL_RULE_POSITION = bytes32(uint256(keccak256("vault.withdrawal")) - 1);
```


### ADMIN_WITHDRAWAL_RULE_POSITION

```solidity
bytes32 constant ADMIN_WITHDRAWAL_RULE_POSITION = bytes32(uint256(keccak256("vault.admin-withdrawal")) - 1);
```


### MIN_TRANSFER_RULE_POSITION

```solidity
bytes32 constant MIN_TRANSFER_RULE_POSITION = bytes32(uint256(keccak256("token.min-transfer")) - 1);
```


### MIN_MAX_BALANCE_RULE_POSITION

```solidity
bytes32 constant MIN_MAX_BALANCE_RULE_POSITION = bytes32(uint256(keccak256("token.min-max-balance-limit")) - 1);
```


### SUPPLY_VOLATILITY_RULE_POSITION

```solidity
bytes32 constant SUPPLY_VOLATILITY_RULE_POSITION = bytes32(uint256(keccak256("token.supply-volatility")) - 1);
```


### ORACLE_RULE_POSITION

```solidity
bytes32 constant ORACLE_RULE_POSITION = bytes32(uint256(keccak256("all.oracle")) - 1);
```


### ACCESS_LEVEL_RULE_POSITION

```solidity
bytes32 constant ACCESS_LEVEL_RULE_POSITION = bytes32(uint256(keccak256("token.access")) - 1);
```


### TX_SIZE_TO_RISK_RULE_POSITION

```solidity
bytes32 constant TX_SIZE_TO_RISK_RULE_POSITION = bytes32(uint256(keccak256("token.tx-size-to-risk")) - 1);
```


### TX_SIZE_PER_PERIOD_TO_RISK_RULE_POSITION

```solidity
bytes32 constant TX_SIZE_PER_PERIOD_TO_RISK_RULE_POSITION =
    bytes32(uint256(keccak256("token.tx-size-per-period-to-risk")) - 1);
```


### BALANCE_LIMIT_TO_RISK_RULE_POSITION

```solidity
bytes32 constant BALANCE_LIMIT_TO_RISK_RULE_POSITION = bytes32(uint256(keccak256("token.balance-limit-to-risk")) - 1);
```


### NFT_TRANSFER_RULE_POSITION

```solidity
bytes32 constant NFT_TRANSFER_RULE_POSITION = bytes32(uint256(keccak256("NFT.transfer-rule")) - 1);
```


### MIN_BAL_BY_DATE_RULE_POSITION

```solidity
bytes32 constant MIN_BAL_BY_DATE_RULE_POSITION = bytes32(uint256(keccak256("token.min-bal-by-date-rule")) - 1);
```


### AMM_FEE_RULE_POSITION

```solidity
bytes32 constant AMM_FEE_RULE_POSITION = bytes32(uint256(keccak256("AMM.fee-rule")) - 1);
```


### ACCESS_LEVEL_WITHDRAWAL_RULE_POSITION

```solidity
bytes32 constant ACCESS_LEVEL_WITHDRAWAL_RULE_POSITION =
    bytes32(uint256(keccak256("token.access-level-withdrawal-rule")) - 1);
```


## Functions
### purchaseStorage

*Function to store Purchase rules*


```solidity
function purchaseStorage() internal pure returns (IRuleStorage.PurchaseRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.PurchaseRuleS`|Data Storage of Purchase Rule|


### sellStorage

*Function to store Sell rules*


```solidity
function sellStorage() internal pure returns (IRuleStorage.SellRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.SellRuleS`|Data Storage of Sell Rule|


### pctPurchaseStorage

*Function to store Percent Purchase rules*


```solidity
function pctPurchaseStorage() internal pure returns (IRuleStorage.PctPurchaseRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.PctPurchaseRuleS`|Data Storage of Percent Purchase Rule|


### pctSellStorage

*Function to store Percent Sell rules*


```solidity
function pctSellStorage() internal pure returns (IRuleStorage.PctSellRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.PctSellRuleS`|Data Storage of Percent Sell Rule|


### purchaseFeeByVolumeStorage

*Function to store Purchase Fee by Volume rules*


```solidity
function purchaseFeeByVolumeStorage() internal pure returns (IRuleStorage.PurchaseFeeByVolRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.PurchaseFeeByVolRuleS`|Data Storage of Purchase Fee by Volume Rule|


### priceVolatilityStorage

*Function to store Price Volitility rules*


```solidity
function priceVolatilityStorage() internal pure returns (IRuleStorage.VolatilityRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.VolatilityRuleS`|Data Storage of Price Volitility Rule|


### volumeStorage

*Function to store Volume rules*


```solidity
function volumeStorage() internal pure returns (IRuleStorage.TransferVolRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.TransferVolRuleS`|Data Storage of Volume Rule|


### withdrawalStorage

*Function to store Withdrawal rules*


```solidity
function withdrawalStorage() internal pure returns (IRuleStorage.WithdrawalRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.WithdrawalRuleS`|Data Storage of Withdrawal Rule|


### adminWithdrawalStorage

*Function to store AppAdministrator Withdrawal rules*


```solidity
function adminWithdrawalStorage() internal pure returns (IRuleStorage.AdminWithdrawalRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.AdminWithdrawalRuleS`|Data Storage of AppAdministrator Withdrawal Rule|


### minTransferStorage

*Function to store Minimum Transfer rules*


```solidity
function minTransferStorage() internal pure returns (IRuleStorage.MinTransferRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.MinTransferRuleS`|Data Storage of Minimum Transfer Rule|


### minMaxBalanceStorage

*Function to store Balance Limit rules*


```solidity
function minMaxBalanceStorage() internal pure returns (IRuleStorage.MinMaxBalanceRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.MinMaxBalanceRuleS`|Data Storage of Balance Limit Rule|


### supplyVolatilityStorage

*Function to store Supply Volitility rules*


```solidity
function supplyVolatilityStorage() internal pure returns (IRuleStorage.SupplyVolatilityRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.SupplyVolatilityRuleS`|Data Storage of Supply Volitility Rule|


### oracleStorage

*Function to store Oracle rules*


```solidity
function oracleStorage() internal pure returns (IRuleStorage.OracleRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.OracleRuleS`|Data Storage of Oracle Rule|


### accessStorage

*Function to store AccessLevel rules*


```solidity
function accessStorage() internal pure returns (IRuleStorage.AccessLevelRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.AccessLevelRuleS`|Data Storage of AccessLevel Rule|


### txSizeToRiskStorage

*Function to store Transaction Size by Risk rules*


```solidity
function txSizeToRiskStorage() internal pure returns (IRuleStorage.TxSizeToRiskRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.TxSizeToRiskRuleS`|Data Storage of Transaction Size by Risk Rule|


### txSizePerPeriodToRiskStorage

*Function to store Transaction Size by Risk per Period rules*


```solidity
function txSizePerPeriodToRiskStorage() internal pure returns (IRuleStorage.TxSizePerPeriodToRiskRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.TxSizePerPeriodToRiskRuleS`|Data Storage of Transaction Size by Risk per Period Rule|


### accountBalanceToRiskStorage

*Function to store Account Balance rules*


```solidity
function accountBalanceToRiskStorage() internal pure returns (IRuleStorage.AccountBalanceToRiskRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.AccountBalanceToRiskRuleS`|Data Storage of Account Balance Rule|


### nftTransferStorage

*Function to store NFT Transfer rules*


```solidity
function nftTransferStorage() internal pure returns (IRuleStorage.NFTTransferCounterRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.NFTTransferCounterRuleS`|Data Storage of NFT Transfer rule|


### ammFeeRuleStorage

*Function to store AMM Fee rules*


```solidity
function ammFeeRuleStorage() internal pure returns (IRuleStorage.AMMFeeRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.AMMFeeRuleS`|Data Storage of AMM Fee rule|


### minBalByDateRuleStorage

*Function to store Minimum Balance By Date rules*


```solidity
function minBalByDateRuleStorage() internal pure returns (IRuleStorage.MinBalByDateRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.MinBalByDateRuleS`|Data Storage of Minimum Balance by Date rule|


### accessLevelWithdrawalRuleStorage

*Function to store Access Level Withdrawal rules*


```solidity
function accessLevelWithdrawalRuleStorage() internal pure returns (IRuleStorage.AccessLevelWithrawalRuleS storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`IRuleStorage.AccessLevelWithrawalRuleS`|Data Storage of Access Level Withdrawal rule|

