# ApplicationERC20
[Git Source](https://github.com/thrackle-io/tron/blob/a1ed7a1196c8d6c5b62fc72c2a02c192f6b90700/src/example/ERC20/ApplicationERC20.sol)

**Inherits:**
[ProtocolERC20](/src/client/token/ERC20/ProtocolERC20.sol/contract.ProtocolERC20.md)

**Author:**
@ShaneDuncan602, @oscarsernarosero, @TJ-Everett

This is an example implementation that App Devs should use.

*During deployment _tokenName _tokenSymbol _appManagerAddress _handlerAddress are set in constructor*


## Functions
### constructor

*Constructor sets params*


```solidity
constructor(string memory _name, string memory _symbol, address _appManagerAddress)
    ProtocolERC20(_name, _symbol, _appManagerAddress);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_name`|`string`|Name of the token|
|`_symbol`|`string`|Symbol of the token|
|`_appManagerAddress`|`address`|App Manager address|


### mint

*Function mints new tokens. Allows for free and open minting of tokens. Comment out to use appAdministatorOnly minting.*


```solidity
function mint(address to, uint256 amount) public override;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`to`|`address`|recipient address|
|`amount`|`uint256`|number of tokens to mint|

