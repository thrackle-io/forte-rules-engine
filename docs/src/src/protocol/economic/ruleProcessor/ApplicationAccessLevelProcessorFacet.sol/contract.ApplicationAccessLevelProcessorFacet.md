# ApplicationAccessLevelProcessorFacet
[Git Source](https://github.com/thrackle-io/tron/blob/ee06788a23623ed28309de5232eaff934d34a0fe/src/protocol/economic/ruleProcessor/ApplicationAccessLevelProcessorFacet.sol)

**Inherits:**
[IInputErrors](/src/common/IErrors.sol/interface.IInputErrors.md), [IRuleProcessorErrors](/src/common/IErrors.sol/interface.IRuleProcessorErrors.md), [IAccessLevelErrors](/src/common/IErrors.sol/interface.IAccessLevelErrors.md)

**Author:**
@ShaneDuncan602 @oscarsernarosero @TJ-Everett

Implements AccessLevel Rule Checks. AccessLevel rules are measured in
in terms of USD with 18 decimals of precision.

*This contract implements rules to be checked by Handler.*


## Functions
### checkAccBalanceByAccessLevel

*Check if transaction passes Balance by AccessLevel rule.*


```solidity
function checkAccBalanceByAccessLevel(uint32 _ruleId, uint8 _accessLevel, uint128 _balance, uint128 _amountToTransfer)
    external
    view;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_ruleId`|`uint32`|Rule Identifier for rule arguments|
|`_accessLevel`|`uint8`|the Access Level of the account|
|`_balance`|`uint128`|account's beginning balance in USD with 18 decimals of precision|
|`_amountToTransfer`|`uint128`|total USD amount to be transferred with 18 decimals of precision|


### getAccessLevelBalanceRule

Get the account's AccessLevel
max has to be multiplied by 10 ** 18 to take decimals in token pricing into account

*Function to get the AccessLevel Balance rule in the rule set that belongs to the Access Level*


```solidity
function getAccessLevelBalanceRule(uint32 _index, uint8 _accessLevel) public view returns (uint48);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_index`|`uint32`|position of rule in array|
|`_accessLevel`|`uint8`|AccessLevel Level to check|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint48`|balanceAmount balance allowed for access levellevel|


### getTotalAccessLevelBalanceRules

*Function to get total AccessLevel Balance rules*


```solidity
function getTotalAccessLevelBalanceRules() public view returns (uint32);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint32`|Total length of array|


### checkwithdrawalLimitsByAccessLevel

*Check if transaction passes Withdrawal by AccessLevel rule.*


```solidity
function checkwithdrawalLimitsByAccessLevel(
    uint32 _ruleId,
    uint8 _accessLevel,
    uint128 _usdWithdrawalTotal,
    uint128 _usdAmountTransferring
) external view returns (uint128);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_ruleId`|`uint32`|Rule Identifier for rule arguments|
|`_accessLevel`|`uint8`|the Access Level of the account|
|`_usdWithdrawalTotal`|`uint128`|account's total amount withdrawn in USD with 18 decimals of precision|
|`_usdAmountTransferring`|`uint128`|total USD amount to be transferred with 18 decimals of precision|


### getAccessLevelWithdrawalRules

max has to be multiplied by 10 ** 18 to take decimals in token pricing into account

*Function to get the Access Level Withdrawal rule in the rule set that belongs to the Access Level*


```solidity
function getAccessLevelWithdrawalRules(uint32 _index, uint8 _accessLevel) public view returns (uint48);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_index`|`uint32`|position of rule in array|
|`_accessLevel`|`uint8`|AccessLevel Level to check|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint48`|balanceAmount balance allowed for access levellevel|


### getTotalAccessLevelWithdrawalRule

*Function to get total AccessLevel withdrawal rules*


```solidity
function getTotalAccessLevelWithdrawalRule() external view returns (uint32);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint32`|Total number of access level withdrawal rules|


### checkAccessLevel0Passes

*Check if transaction passes AccessLevel 0 rule.This has no stored rule as there are no additional variables needed.*


```solidity
function checkAccessLevel0Passes(uint8 _accessLevel) external pure;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_accessLevel`|`uint8`|the Access Level of the account|

