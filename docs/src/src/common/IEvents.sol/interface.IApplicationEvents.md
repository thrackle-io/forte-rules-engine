# IApplicationEvents
[Git Source](https://github.com/thrackle-io/forte-rules-engine/blob/90e2ae1d7df03e5dac710c7ae0a8dd87e3b8b119/src/common/IEvents.sol)

**Inherits:**
[IAppManagerAddressSet](/src/common/IEvents.sol/interface.IAppManagerAddressSet.md)

Application Events Library

*This library for all events for the Application ecosystems.*


## Events
### AD1467_NewTokenDeployed
ProtocolERC20


```solidity
event AD1467_NewTokenDeployed(address indexed appManagerAddress);
```

### AD1467_NewNFTDeployed
ProtocolERC721


```solidity
event AD1467_NewNFTDeployed(address indexed appManagerAddress);
```

### AD1467_TokenPrice
ERC20Pricing


```solidity
event AD1467_TokenPrice(address indexed token, uint256 indexed price);
```

### AD1467_SingleTokenPrice
NFTPricing


```solidity
event AD1467_SingleTokenPrice(address indexed collection, uint256 indexed tokenID, uint256 indexed price);
```

### AD1467_CollectionPrice

```solidity
event AD1467_CollectionPrice(address indexed collection, uint256 indexed price);
```

### AD1467_FeeType
Fees


```solidity
event AD1467_FeeType(
    bytes32 indexed tag,
    bool indexed add,
    uint256 minBalance,
    uint256 maxBalance,
    int256 feePercentage,
    address targetAccount
);
```

