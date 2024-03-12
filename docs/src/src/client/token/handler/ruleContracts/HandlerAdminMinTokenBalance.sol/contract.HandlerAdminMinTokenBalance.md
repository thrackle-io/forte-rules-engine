# HandlerAdminMinTokenBalance
[Git Source](https://github.com/thrackle-io/tron/blob/a1ed7a1196c8d6c5b62fc72c2a02c192f6b90700/src/client/token/handler/ruleContracts/HandlerAdminMinTokenBalance.sol)

**Inherits:**
[HandlerRuleContractsCommonImports](/src/client/token/handler/ruleContracts/HandlerRuleContractsCommonImports.sol/abstract.HandlerRuleContractsCommonImports.md), [IAppManagerErrors](/src/common/IErrors.sol/interface.IAppManagerErrors.md), [ITokenHandlerEvents](/src/common/IEvents.sol/interface.ITokenHandlerEvents.md), [RuleAdministratorOnly](/src/protocol/economic/RuleAdministratorOnly.sol/contract.RuleAdministratorOnly.md), [IAdminMinTokenBalanceCapable](/src/client/token/IAdminMinTokenBalanceCapable.sol/abstract.IAdminMinTokenBalanceCapable.md)

**Author:**
@ShaneDuncan602 @oscarsernarosero @TJ-Everett

*Setters and getters for the rule in the handler. Meant to be inherited by a handler
facet to easily support the rule.*


## State Variables
### LAST_POSSIBLE_ACTION
This is used to set the max action for an efficient check of all actions in the enum


```solidity
uint8 constant LAST_POSSIBLE_ACTION = uint8(ActionTypes.BURN);
```


## Functions
### setAdminMinTokenBalanceId

Rule Setters and Getters

that setting a rule will automatically activate it.

*Set the AdminMinTokenBalance. Restricted to rule administrators only.*


```solidity
function setAdminMinTokenBalanceId(ActionTypes[] calldata _actions, uint32 _ruleId)
    external
    ruleAdministratorOnly(lib.handlerBaseStorage().appManager);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_actions`|`ActionTypes[]`|the action type|
|`_ruleId`|`uint32`|Rule Id to set|


### isAdminMinTokenBalanceActiveAndApplicable

if the rule is currently active, we check that time for current ruleId is expired. Revert if not expired.
after time expired on current rule we set new ruleId and maintain true for adminRuleActive bool.

*This function is used by the app manager to determine if the AdminMinTokenBalance rule is active for any actions*


```solidity
function isAdminMinTokenBalanceActiveAndApplicable() public view override returns (bool);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|Success equals true if all checks pass|


### isAdminMinTokenBalanceActiveForAnyAction

if the rule is active for any actions, set it as active and applicable.

*This function is used internally to check if the admin min token balance is active for any actions*


```solidity
function isAdminMinTokenBalanceActiveForAnyAction() internal view returns (bool);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|Success equals true if all checks pass|


### activateAdminMinTokenBalance

if the rule is active for any actions, set it as active and applicable.

*enable/disable rule. Disabling a rule will save gas on transfer transactions.*


```solidity
function activateAdminMinTokenBalance(ActionTypes[] calldata _actions, bool _on)
    external
    ruleAdministratorOnly(lib.handlerBaseStorage().appManager);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_actions`|`ActionTypes[]`|the action type|
|`_on`|`bool`|boolean representing if a rule must be checked or not.|


### isAdminMinTokenBalanceActive

if the rule is currently active, we check that time for current ruleId is expired

*Tells you if the admin min token balance rule is active or not.*


```solidity
function isAdminMinTokenBalanceActive(ActionTypes _action) external view returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_action`|`ActionTypes`|the action type|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|boolean representing if the rule is active|


### getAdminMinTokenBalanceId

*Retrieve the admin min token balance rule id*


```solidity
function getAdminMinTokenBalanceId(ActionTypes _action) external view returns (uint32);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_action`|`ActionTypes`|the action type|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint32`|adminMinTokenBalanceRuleId rule id|

