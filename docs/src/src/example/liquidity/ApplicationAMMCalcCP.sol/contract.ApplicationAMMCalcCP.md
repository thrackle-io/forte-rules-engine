# ApplicationAMMCalcCP
[Git Source](https://github.com/thrackle-io/tron/blob/c915f21b8dd526456aab7e2f9388d412d287d507/src/example/liquidity/ApplicationAMMCalcCP.sol)

**Inherits:**
[IProtocolAMMCalculator](/src/liquidity/IProtocolAMMCalculator.sol/interface.IProtocolAMMCalculator.md)

**Author:**
@ShaneDuncan602 @oscarsernarosero @TJ-Everett

This contains the calculations for AMM swap.

*This is external and used by the ProtocolAMM. The intention is to be able to change the calculations
as needed. It contains an example Constant Product xy = k*


## Functions
### calculateSwap

*This performs the swap from token0 to token1.
Based on (x + a) * (y - b) = x * y
This is sometimes simplified as xy = k
x = _reserve0
y = _reserve1
a = _amount0
b = _amount1
k = _reserve0 * _reserve1*


```solidity
function calculateSwap(uint256 _reserve0, uint256 _reserve1, uint256 _amount0, uint256 _amount1)
    external
    pure
    returns (uint256);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_reserve0`|`uint256`|total amount of token0 in reserve|
|`_reserve1`|`uint256`|total amount of token1 in reserve|
|`_amount0`|`uint256`|amount of token0 possibly coming into the pool|
|`_amount1`|`uint256`|amount of token1 possibly coming into the pool|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint256`|_amountOut amount of alternate coming out of the pool|

