# AppRuleDataFacet
[Git Source](https://github.com/thrackle-io/tron/blob/ee06788a23623ed28309de5232eaff934d34a0fe/src/protocol/economic/ruleProcessor/AppRuleDataFacet.sol)

**Inherits:**
Context, [RuleAdministratorOnly](/src/protocol/economic/RuleAdministratorOnly.sol/contract.RuleAdministratorOnly.md), [IEconomicEvents](/src/common/IEvents.sol/interface.IEconomicEvents.md), [IInputErrors](/src/common/IErrors.sol/interface.IInputErrors.md), [IAppRuleInputErrors](/src/common/IErrors.sol/interface.IAppRuleInputErrors.md), [IRiskInputErrors](/src/common/IErrors.sol/interface.IRiskInputErrors.md)

**Author:**
@ShaneDuncan602 @oscarsernarosero @TJ-Everett

This contract sets and gets the App Rules for the protocol

*Setters and getters for Application level Rules*


## State Variables
### MAX_ACCESSLEVELS

```solidity
uint8 constant MAX_ACCESSLEVELS = 5;
```


### MAX_RISKSCORE

```solidity
uint8 constant MAX_RISKSCORE = 99;
```


## Functions
### addAccessLevelBalanceRule

that position within the array matters. Posotion 0 represents access levellevel 0,
and position 4 represents level 4.

*Function add a AccessLevel Balance rule*

*Function has RuleAdministratorOnly Modifier and takes AppManager Address Param*


```solidity
function addAccessLevelBalanceRule(address _appManagerAddr, uint48[] calldata _balanceAmounts)
    external
    ruleAdministratorOnly(_appManagerAddr)
    returns (uint32);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_appManagerAddr`|`address`|Address of App Manager|
|`_balanceAmounts`|`uint48[]`|Balance restrictions for each 5 levels from level 0 to 4 in whole USD.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint32`|position of new rule in array|


### addAccessLevelWithdrawalRule

that position within the array matters. Posotion 0 represents access levellevel 0,
and position 4 represents level 4.

*Function add a Accessc Level Withdrawal rule*

*Function has ruleAdministratorOnly Modifier and takes AppManager Address Param*


```solidity
function addAccessLevelWithdrawalRule(address _appManagerAddr, uint48[] calldata _withdrawalAmounts)
    external
    ruleAdministratorOnly(_appManagerAddr)
    returns (uint32);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_appManagerAddr`|`address`|Address of App Manager|
|`_withdrawalAmounts`|`uint48[]`|withdrawal amaount restrictions for each 5 levels from level 0 to 4 in whole USD.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint32`|position of new rule in array|


### addMaxTxSizePerPeriodByRiskRule

validation block

_maxSize size must be equal to _riskLevel.
This means that the positioning of the arrays is ascendant in terms of risk levels,
and descendant in the size of transactions. (i.e. if highest risk level is 99, the last balanceLimit
will apply to all risk scores of 100.)
eg.
risk scores      balances         resultant logic
-----------      --------         ---------------
0-24  =   NO LIMIT
25              500            25-49 =   500
50              250            50-74 =   250
75              100            75-99 =   100

*Function add a Max Tx Size Per Period By Risk rule*

*Function has ruleAdministratorOnly Modifier and takes AppManager Address Param*


```solidity
function addMaxTxSizePerPeriodByRiskRule(
    address _appManagerAddr,
    uint48[] calldata _maxSize,
    uint8[] calldata _riskLevel,
    uint16 _period,
    uint64 _startTimestamp
) external ruleAdministratorOnly(_appManagerAddr) returns (uint32);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_appManagerAddr`|`address`|Address of App Manager|
|`_maxSize`|`uint48[]`|array of max-tx-size allowed within period (whole USD max values --no cents) Each value in the array represents max USD value transacted within _period, and its positions indicate what range of risk levels it applies to. A value of 1000 here means $1000.00 USD.|
|`_riskLevel`|`uint8[]`|array of risk-level ceilings that define each range. Risk levels are inclusive.|
|`_period`|`uint16`|amount of hours that each period lasts for.|
|`_startTimestamp`|`uint64`|start timestamp for the rule|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint32`|position of new rule in array|


### addAccountBalanceByRiskScore

Validation block
We create the rule now

_balanceLimits size must be equal to _riskLevel.
The positioning of the arrays is ascendant in terms of risk levels,
and descendant in the size of transactions. (i.e. if highest risk level is 99, the last balanceLimit
will apply to all risk scores of 100.)
eg.
risk scores      balances         resultant logic
-----------      --------         ---------------
0-24  =   NO LIMIT
25              500            25-49 =   500
50              250            50-74 =   250
75              100            75-99 =   100

*Function to add new AccountBalanceByRiskScore Rules*

*Function has ruleAdministratorOnly Modifier and takes AppManager Address Param*


```solidity
function addAccountBalanceByRiskScore(
    address _appManagerAddr,
    uint8[] calldata _riskScores,
    uint48[] calldata _balanceLimits
) external ruleAdministratorOnly(_appManagerAddr) returns (uint32);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_appManagerAddr`|`address`|Address of App Manager|
|`_riskScores`|`uint8[]`|User Risk Level Array|
|`_balanceLimits`|`uint48[]`|Account Balance Limit in whole USD for each score range. It corresponds to the _riskScores array and is +1 longer than _riskScores. A value of 1000 in this arrays will be interpreted as $1000.00 USD.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint32`|position of new rule in array|


### _addAccountBalanceByRiskScore

*internal Function to avoid stack too deep error*


```solidity
function _addAccountBalanceByRiskScore(uint8[] calldata _riskScores, uint48[] calldata _balanceLimits)
    internal
    returns (uint32);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_riskScores`|`uint8[]`|Account Risk Level|
|`_balanceLimits`|`uint48[]`|Account Balance Limit for each Score in USD (no cents). It corresponds to the _riskScores array. A value of 1000 in this arrays will be interpreted as $1000.00 USD.|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint32`|position of new rule in array|

