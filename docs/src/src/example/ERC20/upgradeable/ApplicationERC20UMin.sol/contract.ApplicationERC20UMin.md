# ApplicationERC20UMin
[Git Source](https://github.com/thrackle-io/forte-rules-engine/blob/6b9ac124d2cb0fe47a8b5c261a1dd458067f45ea/src/example/ERC20/upgradeable/ApplicationERC20UMin.sol)

**Inherits:**
[ProtocolERC20UMin](/src/client/token/ERC20/upgradeable/ProtocolERC20UMin.sol/contract.ProtocolERC20UMin.md)


## Functions
### initialize

*Initializer sets the the App Manager*


```solidity
function initialize(string memory _name, string memory _symbol, address _appManagerAddress) public initializer;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_name`|`string`|Name of the token|
|`_symbol`|`string`|Symbol of the token|
|`_appManagerAddress`|`address`|Address of App Manager|


### mint

*Function mints new tokens. Allows for minting of tokens.*


```solidity
function mint(address to, uint256 amount) public appAdministratorOnly(appManagerAddress);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`to`|`address`|recipient address|
|`amount`|`uint256`|number of tokens to mint|


### burn

*Function burns tokens. Allows for burning of tokens.*


```solidity
function burn(address account, uint256 amount) public;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|address tokens are burned from|
|`amount`|`uint256`|number of tokens to burn|


