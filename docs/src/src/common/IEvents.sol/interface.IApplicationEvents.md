# IApplicationEvents
[Git Source](https://github.com/thrackle-io/tron/blob/ee06788a23623ed28309de5232eaff934d34a0fe/src/common/IEvents.sol)

**Author:**
@ShaneDuncan602 @oscarsernarosero @TJ-Everett

Application Events Library

*This library for all events for the Application ecosystems. Each Contract should inherit this library for emitting events.*


## Events
### HandlerConnected
Application Handler


```solidity
event HandlerConnected(address indexed handlerAddress, address indexed assetAddress);
```

### NewTokenDeployed
ProtocolERC20


```solidity
event NewTokenDeployed(address indexed applicationCoin, address indexed appManagerAddress);
```

### NewNFTDeployed
ProtocolERC721 & ERC721A


```solidity
event NewNFTDeployed(address indexed applicationNFT, address indexed appManagerAddress);
```

### AMMDeployed
AMM


```solidity
event AMMDeployed(address indexed ammAddress);
```

### Swap

```solidity
event Swap(address indexed tokenIn, uint256 amountIn, uint256 amountOut);
```

### AddLiquidity

```solidity
event AddLiquidity(address token0, address token1, uint256 amount0, uint256 amount1);
```

### RemoveLiquidity

```solidity
event RemoveLiquidity(address token, uint256 amount);
```

### TokenPrice
ERC20Pricing


```solidity
event TokenPrice(address indexed token, uint256 indexed price);
```

### SingleTokenPrice
NFTPricing


```solidity
event SingleTokenPrice(address indexed collection, uint256 indexed tokenID, uint256 indexed price);
```

### CollectionPrice

```solidity
event CollectionPrice(address indexed collection, uint256 indexed price);
```

### FeeType
Fees


```solidity
event FeeType(
    bytes32 indexed tag,
    bool indexed add,
    uint256 minBalance,
    uint256 maxBalance,
    int256 feePercentage,
    address targetAccount
);
```

### AppManagerAddressSet
AppManager set


```solidity
event AppManagerAddressSet(address indexed _address);
```
