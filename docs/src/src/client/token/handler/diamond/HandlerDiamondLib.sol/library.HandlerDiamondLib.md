# HandlerDiamondLib
[Git Source](https://github.com/thrackle-io/forte-rules-engine/blob/6b9ac124d2cb0fe47a8b5c261a1dd458067f45ea/src/client/token/handler/diamond/HandlerDiamondLib.sol)

**Author:**
@oscarsernarosero, built on top of Nick Mudge implementation.

Contract serves as library for the Processor Diamond

*Library contract of the diamond pattern. Responsible for checking
on rules compliance.*


## State Variables
### DIAMOND_CUT_STORAGE

```solidity
bytes32 constant DIAMOND_CUT_STORAGE = bytes32(uint256(keccak256("diamond-cut.storage")) - 1);
```


## Functions
### s

*Function for position of rules. Every rule has its own storage.*


```solidity
function s() internal pure returns (HandlerDiamondStorage storage ds);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`ds`|`HandlerDiamondStorage`|Data storage for Rule Processor Storage|


### diamondCut

*Internal function version of _diamondCut*


```solidity
function diamondCut(FacetCut[] memory _diamondCut, address init, bytes memory data) internal;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_diamondCut`|`FacetCut[]`|Facets Array|
|`init`|`address`|Address of the contract or facet to execute "data"|
|`data`|`bytes`|A function call, including function selector and arguments calldata is executed with delegatecall on "init"|


### addFunctions

*Add Function to Diamond*


```solidity
function addFunctions(address _facetAddress, bytes4[] memory _functionSelectors) internal;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_facetAddress`|`address`|Address of Facet|
|`_functionSelectors`|`bytes4[]`|Signature array of function selectors|


### replaceFunctions

*Replace Function from Diamond*


```solidity
function replaceFunctions(address _facetAddress, bytes4[] memory _functionSelectors) internal;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_facetAddress`|`address`|Address of Facet|
|`_functionSelectors`|`bytes4[]`|Signature array of function selectors|


### removeFunctions

can't replace immutable functions -- functions defined directly in the diamond in this case
replace old facet address

*Remove Function from Diamond*


```solidity
function removeFunctions(address _facetAddress, bytes4[] memory _functionSelectors) internal;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_facetAddress`|`address`|Address of Facet|
|`_functionSelectors`|`bytes4[]`|Signature array of function selectors|


### initializeDiamondCut

can't remove immutable functions -- functions defined directly in the diamond
replace selector with last selector
delete last selector

*Initialize Diamond Cut of new Facet*


```solidity
function initializeDiamondCut(address init, bytes memory data) internal;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`init`|`address`|The address of the contract or facet to execute "data"|
|`data`|`bytes`|A function call, including function selector and arguments calldata is executed with delegatecall on "init"|


### enforceHasContractCode

*Internal function to enforce contract has code*


```solidity
function enforceHasContractCode(address _contract, string memory _errorMessage) internal view;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_contract`|`address`|The address of the contract be checked or enforced|
|`_errorMessage`|`string`|Error for contract with non matching co|


## Events
### DiamondCut

```solidity
event DiamondCut(FacetCut[] _diamondCut, address init, bytes data);
```

