# HandlerDiamond
[Git Source](https://github.com/thrackle-io/forte-rules-engine/blob/7ed34a62033174e2129a3d6ffafc4f97afb624f7/src/client/token/handler/diamond/HandlerDiamond.sol)

**Inherits:**
ERC173, [IHandlerDiamondEvents](/src/common/IEvents.sol/interface.IHandlerDiamondEvents.md)

**Author:**
@ShaneDuncan602 @oscarsernarosero @TJ-Everett

The diamond inherits ERC173 for ownership management.

*The proxy contract of the diamond pattern. Responsible for handling
the token rule configuration and communication with the application and protocol.*


## Functions
### constructor

*constructor creates facets for the diamond at deployment*


```solidity
constructor(FacetCut[] memory diamondCut, HandlerDiamondArgs memory args) payable;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`diamondCut`|`FacetCut[]`|Array of Facets to be created at deployment|
|`args`|`HandlerDiamondArgs`|Arguments for the Facets Position and Addresses|


### fallback

*Function finds facet for function that is called and execute the function if a facet is found and return any value.*


```solidity
fallback() external payable;
```

### receive

*Function for empty calldata*


```solidity
receive() external payable;
```

