# FeesFacet
[Git Source](https://github.com/thrackle-io/tron/blob/a1ed7a1196c8d6c5b62fc72c2a02c192f6b90700/src/client/token/handler/diamond/FeesFacet.sol)

**Inherits:**
[RuleAdministratorOnly](/src/protocol/economic/RuleAdministratorOnly.sol/contract.RuleAdministratorOnly.md), [Fees](/src/client/token/handler/ruleContracts/Fees.sol/contract.Fees.md)


## Functions
### setFeeActivation

*Turn fees on/off*


```solidity
function setFeeActivation(bool on_off) external ruleAdministratorOnly(lib.handlerBaseStorage().appManager);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`on_off`|`bool`|value for fee status|


### isFeeActive

*returns the full mapping of fees*


```solidity
function isFeeActive() external view returns (bool);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|feeActive fee activation status|

