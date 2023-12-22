# ProtocolApplicationHandler
[Git Source](https://github.com/thrackle-io/tron/blob/ee06788a23623ed28309de5232eaff934d34a0fe/src/client/application/ProtocolApplicationHandler.sol)

**Inherits:**
Ownable, [RuleAdministratorOnly](/src/protocol/economic/RuleAdministratorOnly.sol/contract.RuleAdministratorOnly.md), [IApplicationHandlerEvents](/src/common/IEvents.sol/interface.IApplicationHandlerEvents.md), [ICommonApplicationHandlerEvents](/src/common/IEvents.sol/interface.ICommonApplicationHandlerEvents.md), [IInputErrors](/src/common/IErrors.sol/interface.IInputErrors.md), [IZeroAddressError](/src/common/IErrors.sol/interface.IZeroAddressError.md)

**Author:**
@ShaneDuncan602, @oscarsernarosero, @TJ-Everett

This contract is the rules handler for all application level rules. It is implemented via the AppManager

*This contract is injected into the appManagers.*


## State Variables
### VERSION

```solidity
string private constant VERSION = "1.1.0";
```


### appManager

```solidity
AppManager appManager;
```


### appManagerAddress

```solidity
address public appManagerAddress;
```


### ruleProcessor

```solidity
IRuleProcessor immutable ruleProcessor;
```


### accountBalanceByRiskRuleId
Application level Rule Ids


```solidity
uint32 private accountBalanceByRiskRuleId;
```


### maxTxSizePerPeriodByRiskRuleId

```solidity
uint32 private maxTxSizePerPeriodByRiskRuleId;
```


### accountBalanceByRiskRuleActive
Application level Rule on-off switches


```solidity
bool private accountBalanceByRiskRuleActive;
```


### maxTxSizePerPeriodByRiskActive

```solidity
bool private maxTxSizePerPeriodByRiskActive;
```


### accountBalanceByAccessLevelRuleId
AccessLevel Rule Ids


```solidity
uint32 private accountBalanceByAccessLevelRuleId;
```


### withdrawalLimitByAccessLevelRuleId

```solidity
uint32 private withdrawalLimitByAccessLevelRuleId;
```


### accountBalanceByAccessLevelRuleActive
AccessLevel Rule on-off switches


```solidity
bool private accountBalanceByAccessLevelRuleActive;
```


### AccessLevel0RuleActive

```solidity
bool private AccessLevel0RuleActive;
```


### withdrawalLimitByAccessLevelRuleActive

```solidity
bool private withdrawalLimitByAccessLevelRuleActive;
```


### pauseRuleActive
Pause Rule on-off switch


```solidity
bool private pauseRuleActive;
```


### usdValueTransactedInRiskPeriod
MaxTxSizePerPeriodByRisk data


```solidity
mapping(address => uint128) usdValueTransactedInRiskPeriod;
```


### lastTxDateRiskRule

```solidity
mapping(address => uint64) lastTxDateRiskRule;
```


### usdValueTotalWithrawals
AccessLevelWithdrawalRule data


```solidity
mapping(address => uint128) usdValueTotalWithrawals;
```


## Functions
### constructor

*Initializes the contract setting the AppManager address as the one provided and setting the ruleProcessor for protocol access*


```solidity
constructor(address _ruleProcessorProxyAddress, address _appManagerAddress);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_ruleProcessorProxyAddress`|`address`|of the protocol's Rule Processor contract.|
|`_appManagerAddress`|`address`|address of the application AppManager.|


### requireValuations

*checks if any of the balance prerequisite rules are active*


```solidity
function requireValuations() public view returns (bool);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|true if one or more rules are active|


### checkApplicationRules

*Check Application Rules for valid transaction.*


```solidity
function checkApplicationRules(
    ActionTypes _action,
    address _from,
    address _to,
    uint128 _usdBalanceTo,
    uint128 _usdAmountTransferring
) external onlyOwner returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_action`|`ActionTypes`|Action to be checked. This param is intentially added for future enhancements.|
|`_from`|`address`|address of the from account|
|`_to`|`address`|address of the to account|
|`_usdBalanceTo`|`uint128`|recepient address current total application valuation in USD with 18 decimals of precision|
|`_usdAmountTransferring`|`uint128`|valuation of the token being transferred in USD with 18 decimals of precision|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|success Returns true if allowed, false if not allowed|


### _checkRiskRules

*This function consolidates all the Risk rules that utilize application level Risk rules.*


```solidity
function _checkRiskRules(address _from, address _to, uint128 _usdBalanceTo, uint128 _usdAmountTransferring) internal;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_from`|`address`|address of the from account|
|`_to`|`address`|address of the to account|
|`_usdBalanceTo`|`uint128`|recepient address current total application valuation in USD with 18 decimals of precision|
|`_usdAmountTransferring`|`uint128`|valuation of the token being transferred in USD with 18 decimals of precision|


### _checkAccessLevelRules

if rule is active check if the recipient is address(0) for burning tokens
check if sender violates the rule
check if recipient violates the rule

*This function consolidates all the application level AccessLevel rules.*


```solidity
function _checkAccessLevelRules(
    address _from,
    address _to,
    uint128 _usdBalanceValuation,
    uint128 _usdAmountTransferring
) internal;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_from`|`address`||
|`_to`|`address`|address of the to account|
|`_usdBalanceValuation`|`uint128`|address current balance in USD|
|`_usdAmountTransferring`|`uint128`|number of tokens transferred|


### setAccountBalanceByRiskRuleId

Perform the access level = 0 rule checks if necessary
If sender is not AMM and then check sender access level
If receiver is not AMM or AMM treasury and then check receiver access level. Exempting address(0) allows for burning.
Check that the recipient is not address(0). If it is we do not check this rule as it is a burn.

that setting a rule will automatically activate it.

*Set the accountBalanceByRiskRule. Restricted to app administrators only.*


```solidity
function setAccountBalanceByRiskRuleId(uint32 _ruleId) external ruleAdministratorOnly(appManagerAddress);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_ruleId`|`uint32`|Rule Id to set|


### activateAccountBalanceByRiskRule

*enable/disable rule. Disabling a rule will save gas on transfer transactions.*


```solidity
function activateAccountBalanceByRiskRule(bool _on) external ruleAdministratorOnly(appManagerAddress);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_on`|`bool`|boolean representing if a rule must be checked or not.|


### isAccountBalanceByRiskActive

*Tells you if the accountBalanceByRiskRule is active or not.*


```solidity
function isAccountBalanceByRiskActive() external view returns (bool);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|boolean representing if the rule is active|


### getAccountBalanceByRiskRule

*Retrieve the accountBalanceByRisk rule id*


```solidity
function getAccountBalanceByRiskRule() external view returns (uint32);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint32`|accountBalanceByRiskRuleId rule id|


### setAccountBalanceByAccessLevelRuleId

that setting a rule will automatically activate it.

*Set the accountBalanceByAccessLevelRule. Restricted to app administrators only.*


```solidity
function setAccountBalanceByAccessLevelRuleId(uint32 _ruleId) external ruleAdministratorOnly(appManagerAddress);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_ruleId`|`uint32`|Rule Id to set|


### activateAccountBalanceByAccessLevelRule

*enable/disable rule. Disabling a rule will save gas on transfer transactions.*


```solidity
function activateAccountBalanceByAccessLevelRule(bool _on) external ruleAdministratorOnly(appManagerAddress);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_on`|`bool`|boolean representing if a rule must be checked or not.|


### isAccountBalanceByAccessLevelActive

*Tells you if the accountBalanceByAccessLevelRule is active or not.*


```solidity
function isAccountBalanceByAccessLevelActive() external view returns (bool);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|boolean representing if the rule is active|


### getAccountBalanceByAccessLevelRule

*Retrieve the accountBalanceByAccessLevel rule id*


```solidity
function getAccountBalanceByAccessLevelRule() external view returns (uint32);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint32`|accountBalanceByAccessLevelRuleId rule id|


### activateAccessLevel0Rule

*enable/disable rule. Disabling a rule will save gas on transfer transactions.*


```solidity
function activateAccessLevel0Rule(bool _on) external ruleAdministratorOnly(appManagerAddress);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_on`|`bool`|boolean representing if a rule must be checked or not.|


### isAccessLevel0Active

*Tells you if the AccessLevel0 Rule is active or not.*


```solidity
function isAccessLevel0Active() external view returns (bool);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|boolean representing if the rule is active|


### setWithdrawalLimitByAccessLevelRuleId

that setting a rule will automatically activate it.

*Set the withdrawalLimitByAccessLevelRule. Restricted to app administrators only.*


```solidity
function setWithdrawalLimitByAccessLevelRuleId(uint32 _ruleId) external ruleAdministratorOnly(appManagerAddress);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_ruleId`|`uint32`|Rule Id to set|


### activateWithdrawalLimitByAccessLevelRule

*enable/disable rule. Disabling a rule will save gas on transfer transactions.*


```solidity
function activateWithdrawalLimitByAccessLevelRule(bool _on) external ruleAdministratorOnly(appManagerAddress);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_on`|`bool`|boolean representing if a rule must be checked or not.|


### isWithdrawalLimitByAccessLevelActive

*Tells you if the withdrawalLimitByAccessLevelRule is active or not.*


```solidity
function isWithdrawalLimitByAccessLevelActive() external view returns (bool);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|boolean representing if the rule is active|


### getWithdrawalLimitByAccessLevelRule

*Retrieve the withdrawalLimitByAccessLevel rule id*


```solidity
function getWithdrawalLimitByAccessLevelRule() external view returns (uint32);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint32`|withdrawalLimitByAccessLevelRuleId rule id|


### getMaxTxSizePerPeriodByRiskRuleId

*Retrieve the MaxTxSizePerPeriodByRisk rule id*


```solidity
function getMaxTxSizePerPeriodByRiskRuleId() external view returns (uint32);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint32`|MaxTxSizePerPeriodByRisk rule id for specified token|


### setMaxTxSizePerPeriodByRiskRuleId

that setting a rule will automatically activate it.

*Set the MaxTxSizePerPeriodByRisk. Restricted to app administrators only.*


```solidity
function setMaxTxSizePerPeriodByRiskRuleId(uint32 _ruleId) external ruleAdministratorOnly(appManagerAddress);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_ruleId`|`uint32`|Rule Id to set|


### activateMaxTxSizePerPeriodByRiskRule

*enable/disable rule. Disabling a rule will save gas on transfer transactions.*


```solidity
function activateMaxTxSizePerPeriodByRiskRule(bool _on) external ruleAdministratorOnly(appManagerAddress);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_on`|`bool`|boolean representing if a rule must be checked or not.|


### isMaxTxSizePerPeriodByRiskActive

*Tells you if the MaxTxSizePerPeriodByRisk is active or not.*


```solidity
function isMaxTxSizePerPeriodByRiskActive() external view returns (bool);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|boolean representing if the rule is active for specified token|


### activatePauseRule

This function uses the onlyOwner modifier since the appManager contract is calling this function when adding a pause rule or removing the final pause rule of the array.

*enable/disable rule. Disabling a rule will save gas on transfer transactions.
This function does not use ruleAdministratorOnly modifier, the onlyOwner modifier checks that the caller is the appManager contract.*


```solidity
function activatePauseRule(bool _on) external onlyOwner;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_on`|`bool`|boolean representing if a rule must be checked or not.|


### isPauseRuleActive

*Tells you if the pause rule check is active or not.*


```solidity
function isPauseRuleActive() external view returns (bool);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|boolean representing if the rule is active for specified token|


### version

*gets the version of the contract*


```solidity
function version() external pure returns (string memory);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`string`|VERSION|

