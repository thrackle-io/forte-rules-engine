# Token Max Supply Volatility

## Purpose

The purpose of this rule is to prevent a sudden increase or decrease in the supply of a token. This can help to prevent a sudden crash or spike in the price of a token due to sharp changes in the supply side, which could lead to severe damages to the health of the economy in the long run. 

## Applies To:

- [x] ERC20
- [x] ERC721

## Applies To Actions:

- [x] MINT
- [x] BURN
- [ ] BUY
- [ ] SELL
- [ ] TRANSFER(Peer to Peer)
  
## Scope 

This rule works at a token level. It must be activated and configured for each desired token in the corresponding token handler.

## Data Structure

A token-max-supply-volatility rule is composed of 4 variables:

- **Max Change** (uint16): the maximum percentage change allowed in the supply during a *period* of time (expressed in basis points).
- **Period** (uint16): the amount of hours that defines a period.
- **Starting timestamp** (uint64): the timestamp of the date when the rule starts the first *period*.
- **Total Supply** (uint256): if not zero, this value will always be used as the token's total supply for rule evaluation. This can be used when the amount of circulating supply is much smaller than the amount of the token totalSupply due to some tokens being locked in a dev account or a vesting contract, etc. Only use this value in such cases.

```c
/// ******** Token Max Supply Volatility ********
    struct TokenMaxSupplyVolatility {
        uint16 max; /// from 0000 to 10000 => 0.00% to 100.00%.
        uint16 period; // hours
        uint64 startTime; // UNIX date MUST be at a time with 0 minutes, 0 seconds. i.e: 20:00 on Jan 01 2024(basically 0-23)
        uint256 totalSupply; // If specified, this is the circulating supply value to use. If not specified, it defaults to token's totalSupply.
    }
```
###### *see [RuleDataInterfaces](../../../src/protocol/economic/ruleProcessor/RuleDataInterfaces.sol)*

These rules are stored in a mapping indexed by ruleId(uint32) in order of creation:

```c
/// ******** Token Max Supply Volatility ********
    struct TokenMaxSupplyVolatilityS {
        mapping(uint32 => INonTaggedRules.TokenMaxSupplyVolatility) tokenMaxSupplyVolatilityRules;
        uint32 tokenMaxSupplyVolatilityIndex;
    }
```
###### *see [IRuleStorage](../../../src/protocol/economic/ruleProcessor/IRuleStorage.sol)*

## Configuration and Enabling/Disabling
- This rule can only be configured in the protocol by a **rule administrator**.
- This rule can only be set in the asset handler by a **rule administrator**.
- This rule can only be activated/deactivated in the asset handler by a **rule administrator**.
- This rule can only be updated in the asset handler by a **rule administrator**.


## Rule Evaluation

The rule will be evaluated with the following logic:

1. The handler determines if the rule is active from the supplied action. If not, processing does not continue past this step.
2. The asset handler keeps track of the total supply per period, the net supply increase/decrease per period, and the date of the last mint/burn transaction.
3. The asset handler first checks if the transaction is a *minting* or *burning* operation. If it is, then it sends the aforementioned data to the rule processor with the rule Id, and the amount of tokens being minted/burned in the transaction.
4. The rule processor evaluates if the current transaction is in a new period or part of the same period as the last burning/minting transactions. 
    - **If it is a new period**, the absolute net supply change for the period is equal to the amount of tokens minted/burned in current transaction. Also, the totalSupply for the current period is set to current value. 
    - **If it is not a new period**, then the absolute net supply change for the period accumulates the amount of tokens minted/burned in current transaction. The totalSupply for the current period remains fixed to the value set in the first transaction of the period. 
5. After current period's net supply change and totalSupply have been defined, the rule processor calculates the change in supply. If the change is greater than the rule's maximum, it reverts.

**The list of available actions rules can be applied to can be found at [ACTION_TYPES.md](./ACTION-TYPES.md)**

###### *see [ERC20TaggedRuleProcessorFacet](../../../src/protocol/economic/ruleProcessor/ERC20TaggedRuleProcessorFacet.sol) -> checkTokenMaxSupplyVolatility*

## Evaluation Exceptions 
- This rule doesn't apply when a **treasuryAccount** address is in either the *from* or the *to* side of the transaction. This doesn't necessarily mean that if an treasury account is the one executing the transaction it will bypass the rule, unless the aforementioned condition is true.

### Revert Message

The rule processor will revert with the following error if the rule check fails: 

```
error OverMaxSupplyVolatility();
```

The selector for this error is `0xc406d470`.

## Create Function

Adding a token-max-supply-volatility rule is done through the function: 

```c
function addTokenMaxSupplyVolatility(
        address _appManagerAddr,
        uint16 _maxPercentage,
        uint16 _period,
        uint64 _startTime,
        uint256 _totalSupply
    ) external ruleAdministratorOnly(_appManagerAddr) returns (uint32);
```
###### *see [RuleDataFacet](../../../src/protocol/economic/ruleProcessor/RuleDataFacet.sol)*

The add function will return the protocol ID of the rule.

### Parameters:

- **_appManagerAddr** (address): the address of the application manager to verify that the caller has rule administrator privileges.
- **_maxPercentage** (uint16): Maximum percentage change of supply allowed expressed in basis points (1 -> 0.01%; 100 -> 1.0%). 
- **_period** (uint16): amount of hours that defines a period.
- **_startTime** (uint64): Unix timestamp for the *_period*s to start counting.
- **_totalSupply** (uint256): (optional) if not 0, then this is the value used for totalSupply instead of the live token's totalSupply value at rule processing time.


### Parameter Optionality:

The parameters where developers have options are:

- **_totalSupply**: For volatility calculations, when this is zero, the token's totalSupply is used. Otherwise, this value is used as the total supply.

### Parameter Validation:

The following validation will be carried out by the add function in order to ensure that these parameters are valid and make sense:

- `_appManagerAddr` is not the zero address.
- `_maxPercentage` is not zero.
- `_period` is not zero.
- `_startTime` is not zero and is not more than 52 weeks in the future.


###### *see [TaggedRuleDataFacet](../../../src/protocol/economic/ruleProcessor/TaggedRuleDataFacet.sol)*

## Other Functions:

- In Protocol [Rule Processor](../../../src/protocol/economic/ruleProcessor/ERC20RuleProcessorFacet.sol):
    -  Function to get a rule by its ID:
        ```c
        function getTokenMaxSupplyVolatility(uint32 _index) external view returns (NonTaggedRules.TokenMaxSupplyVolatility memory);
        ```
    - Function to get current amount of rules in the protocol:
        ```c
        function getTotalTokenMaxSupplyVolatility() public view returns (uint32);
        ```
- In Protocol [Rule Processor](../../../src/protocol/economic/ruleProcessor/ERC20RuleProcessorFacet.sol):
    - Function that evaluates the rule:
        ```c
        function checkTokenMaxSupplyVolatility(
                uint32 _ruleId,
                int256 _volumeTotalForPeriod,
                uint256 _tokenTotalSupply,
                uint256 _supply,
                int256 _amount,
                uint64 _lastSupplyUpdateTime
            ) external view returns (int256, uint256);
        ```
- in Asset Handler:
    - Function to set and activate at the same time the rule for the supplied actions in an asset handler:
        ```c
        function setTokenMaxSupplyVolatilityId(ActionTypes[] calldata _actions, uint32 _ruleId) external ruleAdministratorOnly(appManagerAddress);
        ```
    - Function to activate/deactivate the rule for the supplied actions in an asset handler:
        ```c
        function activateTokenMaxSupplyVolatility(ActionTypes[] calldata _actions, bool _on) external ruleAdministratorOnly(appManagerAddress);
        ```
    - Function to know the activation state of the rule for the supplied action in an asset handler:
        ```c
        function isTokenMaxSupplyVolatilityActive(ActionTypes _action) external view returns (bool);
        ```
    - Function to get the rule Id for the supplied action from an asset handler:
        ```c
        function getTokenMaxSupplyVolatilityId(ActionTypes _action) external view returns (uint32);
        ```
## Return Data

This rule returns 2 values:
1. **Volume Total For Period** (int256): the updated value for the total volume during the period. 
2. **Total Supply For Period** (uint256): the updated value of the total supply for the period in the case of the first transaction in a period, or the fixed initial total supply for the period in the rest of the transactions.

```c
int256 private volumeTotalForPeriod;
uint256 private totalSupplyForPeriod;
```

*see [ERC721Handler](../architecture/client/assetHandler/PROTOCOL-NONFUNGIBLE-TOKEN-HANDLER.md)/[ERC20Handler](../architecture/client/assetHandler/PROTOCOL-FUNGIBLE-TOKEN-HANDLER.md)*

## Data Recorded

This rule requires recording of the following information in the asset handler:

- **Volume Total For Period** (int256): the updated value for the total volume during the period. 
- **Total Supply For Period** (uint256): the updated value of the total supply for the period in the case of the first transaction in a period, or the fixed initial total supply for the period in the rest of the transactions.
- **Last Supply Update Time** (uint64): the Unix timestamp of the last update in the Total-Supply-For-Period variable

```c
uint64 private lastSupplyUpdateTime;
int256 private volumeTotalForPeriod;
uint256 private totalSupplyForPeriod;
```

*see [ERC721Handler](../architecture/client/assetHandler/PROTOCOL-NONFUNGIBLE-TOKEN-HANDLER.md)/[ERC20Handler](../architecture/client/assetHandler/PROTOCOL-FUNGIBLE-TOKEN-HANDLER.md)*

## Events

- **event AD1467_ProtocolRuleCreated(bytes32 indexed ruleType, uint32 indexed ruleId, bytes32[] extraTags)**: 
    - Emitted when: the rule has been created in the protocol.
    - Parameters:
        - ruleType: "TOKEN_MAX_SUPPLY_VOLATILITY".
        - ruleId: the index of the rule created in the protocol by rule type.
        - extraTags: an empty array.

- **event AD1467_ApplicationHandlerActionApplied(bytes32 indexed ruleType, ActionTypes action, uint32 indexed ruleId)**:
    - Emitted when: rule has been applied in an asset handler.
    - Parameters: 
        - ruleType: "TOKEN_MAX_SUPPLY_VOLATILITY".
        - action: the protocol action the rule is being applied to.
        - ruleId: the ruleId set for this rule in the handler.

- **event AD1467_ApplicationHandlerActionActivated(bytes32 indexed ruleType, ActionTypes actions, uint256 indexed ruleId)** 
    - Emitted when: A Transfer counter rule has been activated in an asset handler:
    - Parameters:
        - ruleType: "TOKEN_MAX_SUPPLY_VOLATILITY".
        - actions: the protocol actions for which the rule is being activated.
        - ruleId: a placeholder of 0 will be passed for ruleId
- **event AD1467_ApplicationHandlerActionDeactivated(bytes32 indexed ruleType, ActionTypes actions, uint256 indexed ruleId)** 
    - Emitted when: A Transfer counter rule has been deactivated in an asset handler:
    - Parameters:
        - ruleType: "TOKEN_MAX_SUPPLY_VOLATILITY".
        - actions: the protocol actions for which the rule is being deactivated.
        - ruleId: a placeholder of 0 will be passed for ruleId

## Dependencies

- **ERC721Enumerable**:  This rule utilizes the totalSupply function, requiring [ERC721Enumerable](https://eips.ethereum.org/EIPS/eip-721)

