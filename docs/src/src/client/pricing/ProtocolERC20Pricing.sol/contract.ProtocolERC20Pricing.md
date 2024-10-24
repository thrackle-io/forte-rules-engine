# ProtocolERC20Pricing
[Git Source](https://github.com/thrackle-io/forte-rules-engine/blob/6b9ac124d2cb0fe47a8b5c261a1dd458067f45ea/src/client/pricing/ProtocolERC20Pricing.sol)

**Inherits:**
Ownable, [IApplicationEvents](/src/common/IEvents.sol/interface.IApplicationEvents.md), [IProtocolERC20Pricing](/src/common/IProtocolERC20Pricing.sol/interface.IProtocolERC20Pricing.md)

**Author:**
@ShaneDuncan602, @oscarsernarosero, @TJ-Everett

This contract is a simple pricing mechanism only. Its main purpose is to store prices.

*This contract doesn't allow any marketplace operations.*


## State Variables
### VERSION

```solidity
string private constant VERSION = "2.2.0";
```


### tokenPrices

```solidity
mapping(address => uint256) public tokenPrices;
```


## Functions
### setSingleTokenPrice

that the token is the whole token and not its atomic unit. This means that if an
ERC20 with 18 decimals has a price of 2 dollars, then its atomic unit would be 2/10^18 USD.
999_999_999_999_999_999 = 0xDE0B6B3A763FFFF, 1_000_000_000_000_000_000 = DE0B6B3A7640000

*set the price for a single Token*


```solidity
function setSingleTokenPrice(address tokenContract, uint256 price) external onlyOwner;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`tokenContract`|`address`|is the address of the Token contract|
|`price`|`uint256`|price of the Token in weis of dollars. 10^18 => $ 1.00 USD|


### getTokenPrice

that the price is for the whole token and not of its atomic unit. This means that if
an ERC20 with 18 decimals has a price of 2 dollars, then its atomic unit would be 2/10^18 USD.
999_999_999_999_999_999 = 0xDE0B6B3A763FFFF, 1_000_000_000_000_000_000 = DE0B6B3A7640000

*gets the price of a Token. It will return the Token's specific price.*


```solidity
function getTokenPrice(address tokenContract) external view returns (uint256 price);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`tokenContract`|`address`|is the address of the Token contract|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`price`|`uint256`|of the Token in weis of dollars. 10^18 => $ 1.00 USD|


### version

*gets the version of the contract*


```solidity
function version() external pure returns (string memory);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`string`|VERSION|


