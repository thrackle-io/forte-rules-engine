# HandlerAccountMaxSellSize
[Git Source](https://github.com/thrackle-io/tron/blob/a1ed7a1196c8d6c5b62fc72c2a02c192f6b90700/src/client/token/handler/ruleContracts/HandlerAccountMaxSellSize.sol)

**Inherits:**
[RuleAdministratorOnly](/src/protocol/economic/RuleAdministratorOnly.sol/contract.RuleAdministratorOnly.md), [ITokenHandlerEvents](/src/common/IEvents.sol/interface.ITokenHandlerEvents.md)

**Author:**
@ShaneDuncan602 @oscarsernarosero @TJ-Everett

*Setters and getters for the rule in the handler. Meant to be inherited by a handler
facet to easily support the rule.*


## Functions
### setAccountMaxSellSizeId

Rule Setters and Getters

that setting a rule will automatically activate it.

*Set the AccountMaxSellSizeRuleId. Restricted to rule administrators only.*


```solidity
function setAccountMaxSellSizeId(uint32 _ruleId) external ruleAdministratorOnly(lib.handlerBaseStorage().appManager);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_ruleId`|`uint32`|Rule Id to set|


### activateAccountMaxSellSize

*enable/disable rule. Disabling a rule will save gas on transfer transactions.*


```solidity
function activateAccountMaxSellSize(bool _on) external ruleAdministratorOnly(lib.handlerBaseStorage().appManager);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_on`|`bool`|boolean representing if a rule must be checked or not.|


### getAccountMaxSellSizeId

*Retrieve the Account Max Sell Size Rule Id*


```solidity
function getAccountMaxSellSizeId() external view returns (uint32);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint32`|accountMaxSellSizeId|


### isAccountMaxSellSizeActive

*Tells you if the Account Max Sell Size Rule is active or not.*


```solidity
function isAccountMaxSellSizeActive() external view returns (bool);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|boolean representing if the rule is active|

