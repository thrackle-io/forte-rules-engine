# Overview

This is a protocol template for an ERC20-pricing contract. Any custom-made pricing contract that intends to be protocol compliant must implement the [IProtocolERC20Pricing](../../../src/common/IProtocolERC20Pricing.sol) interface, and follow the [price format](./README.md) guideline.

[This template](../../../src/client/pricing/ProtocolERC20Pricing.sol) is available for developers to quickly get their pricing modules up and running.

# Deployment

Refer to the deployment document [here](./DEPLOY-PRICING.md).

# Public Functions

## The price-setter function:

### Parameters:
- **tokenContract (address)**: the address for the token contract.
- **price (uint256)**: the price in wei of dollars for a whole token (see [example](./README.md)).

```c
function setSingleTokenPrice(address tokenContract, uint256 price) external onlyOwner;
```

Notice that only the owner of the pricing contract can successfully invoke this function.

## The price-getter function:
    
### Parameters:
- **tokenContract (address)**: the address for the token contract.

### Returns:
- **price (uint256)**: the price in wei of dollars for a whole token (see [example](./README.md)).

```c
function getTokenPrice(address tokenContract) external view returns (uint256 price);
```

## The version-getter function:
    
### Returns: 

- **version (string)**: the string of the protocol version of this template file.
```c
function version() external pure returns (string memory);
```

# Set an ERC20-Pricing Contract in an Asset Handler 

Use the following function in the [asset handler](../architecture/client/assetHandler/PROTOCOL-FUNGIBLE-TOKEN-HANDLER.md):

```c
function setERC20PricingAddress(
            address _address
        ) 
        external 
        appAdministratorOrOwnerOnly(appManagerAddress);
```
Notice that only accounts with the appAdministrator role can invoke this function successfully.

### Parameters:

- **_address (address)**: the address of the ERC20 pricing contract.

### Events:

- **event AD1467_ERC20PricingAddressSet(address indexed _address);**
    - Parameters:
        - _address: the address of the pricing contract.

### Upgrading: 

To upgrade the pricing contracts, ensure your new pricing contract is deployed to the same network your [Application Handler](../architecture/client/application/APPLICATION-HANDLER.md) is deployed to. Next, you will call the appropriate function `setERC20Pricing` or `setNFTPricing` from the Application Handler contract. 


```c
function setERC20PricingAddress(address _address) external ruleAdministratorOnly(appManagerAddress)
```

```c
function setNFTPricingAddress(address _address) external ruleAdministratorOnly(appManagerAddress)
```


Each set function requires the caller to be a [rule administrator](../permissions/ADMIN-ROLES.md). Each pricing contract must conform to either the [IProtocolERC721Pricing](../../../src/common/IProtocolERC721Pricing.sol) or [IProtocolERC20Pricing](../../../src/common/IProtocolERC20Pricing.sol).
