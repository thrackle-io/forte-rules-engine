# IProtocolTokenHandler
[Git Source](https://github.com/thrackle-io/forte-rules-engine/blob/6b9ac124d2cb0fe47a8b5c261a1dd458067f45ea/src/client/token/IProtocolTokenHandler.sol)

**Author:**
@ShaneDuncan602 @oscarsernarosero @TJ-Everett

*This interface provides the ABI for assets to access their handlers in an efficient way*


## Functions
### checkAllRules

*This function is the one called from the contract that implements this handler. It's the entry point to protocol.*


```solidity
function checkAllRules(
    uint256 balanceFrom,
    uint256 balanceTo,
    address _from,
    address _to,
    address _sender,
    uint256 value
) external returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`balanceFrom`|`uint256`|token balance of sender address|
|`balanceTo`|`uint256`|token balance of recipient address|
|`_from`|`address`|sender address|
|`_to`|`address`|recipient address|
|`_sender`|`address`|the address triggering the contract action|
|`value`|`uint256`|for ERC20s: the amount of tokens. For ERC721: the tokenId|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|Success equals true if all checks pass|


