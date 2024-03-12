# ERC20TaggedRuleFacet
[Git Source](https://github.com/thrackle-io/tron/blob/a1ed7a1196c8d6c5b62fc72c2a02c192f6b90700/src/client/token/handler/diamond/ERC20TaggedRuleFacet.sol)

**Inherits:**
[HandlerAccountMinMaxTokenBalance](/src/client/token/handler/ruleContracts/HandlerAccountMinMaxTokenBalance.sol/contract.HandlerAccountMinMaxTokenBalance.md), [FacetUtils](/src/client/token/handler/common/FacetUtils.sol/contract.FacetUtils.md)


## Functions
### checkTaggedAndTradingRules

*This function uses the protocol's ruleProcessor to perform the actual tagged rule checks.*


```solidity
function checkTaggedAndTradingRules(
    uint256 _balanceFrom,
    uint256 _balanceTo,
    address _from,
    address _to,
    uint256 _amount,
    ActionTypes action
) external;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_balanceFrom`|`uint256`|token balance of sender address|
|`_balanceTo`|`uint256`|token balance of recipient address|
|`_from`|`address`|address of the from account|
|`_to`|`address`|address of the to account|
|`_amount`|`uint256`|number of tokens transferred|
|`action`|`ActionTypes`|if selling or buying (of ActionTypes type)|


### _checkTaggedIndividualRules

*This function consolidates all the tagged rules that utilize account tags plus all trading rules.*


```solidity
function _checkTaggedIndividualRules(
    uint256 _balanceFrom,
    uint256 _balanceTo,
    address _from,
    address _to,
    uint256 _amount,
    ActionTypes action
) internal;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_balanceFrom`|`uint256`|token balance of sender address|
|`_balanceTo`|`uint256`|token balance of recipient address|
|`_from`|`address`|address of the from account|
|`_to`|`address`|address of the to account|
|`_amount`|`uint256`|number of tokens transferred|
|`action`|`ActionTypes`|if selling or buying (of ActionTypes type)|

