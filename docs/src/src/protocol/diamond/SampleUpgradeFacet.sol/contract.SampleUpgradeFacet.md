# SampleUpgradeFacet
[Git Source](https://github.com/thrackle-io/forte-rules-engine/blob/6b9ac124d2cb0fe47a8b5c261a1dd458067f45ea/src/protocol/diamond/SampleUpgradeFacet.sol)

**Inherits:**
ERC173

This contract only exists for testing purposes. It is here to test diamond upgrades. It is named "Sample" instead
of "Test" because naming it "Test" causes problems with Foundry testing.


## State Variables
### SAMPLE_STORAGE_POSITION

```solidity
bytes32 constant SAMPLE_STORAGE_POSITION = keccak256("sample.storage");
```


## Functions
### s

Return the storage struct for reading and writing.


```solidity
function s() internal pure returns (SampleStorage storage storageStruct);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`storageStruct`|`SampleStorage`|The sample  storage struct.|


### sampleUpgradeFunction


```solidity
function sampleUpgradeFunction() external view onlyOwner returns (string memory);
```

## Structs
### SampleStorage

```solidity
struct SampleStorage {
    uint256 v1;
}
```

