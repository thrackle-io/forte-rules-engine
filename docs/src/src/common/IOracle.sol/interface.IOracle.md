# IOracle
[Git Source](https://github.com/thrackle-io/forte-rules-engine/blob/4a2e9b2745fc1ebf2913bcb6fdbbd0ad4f2bfe93/src/common/IOracle.sol)

**Author:**
@ShaneDuncan602, @oscarsernarosero, @TJ-Everett

This stores the function signature for external oracles

*Both "approve list" and "deny list" oracles will use this interface*


## Functions
### isDenied

*This function checks to see if the address is on the oracle's denied list. This is the DENIED_LIST type.*


```solidity
function isDenied(address _address) external view returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_address`|`address`|Account address to check|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|denied returns true if denied, false if not|


### isApproved

*This function checks to see if the address is on the oracle's approved list. This is the APPROVED_LIST type.*


```solidity
function isApproved(address _address) external view returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_address`|`address`|Account address to check|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|denied returns true if approved, false if not|


