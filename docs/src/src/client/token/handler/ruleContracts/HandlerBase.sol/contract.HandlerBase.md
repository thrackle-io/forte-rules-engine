# HandlerBase
[Git Source](https://github.com/thrackle-io/tron/blob/a1ed7a1196c8d6c5b62fc72c2a02c192f6b90700/src/client/token/handler/ruleContracts/HandlerBase.sol)

**Inherits:**
[IZeroAddressError](/src/common/IErrors.sol/interface.IZeroAddressError.md), [ITokenHandlerEvents](/src/common/IEvents.sol/interface.ITokenHandlerEvents.md), [IOwnershipErrors](/src/common/IErrors.sol/interface.IOwnershipErrors.md), [AppAdministratorOrOwnerOnlyDiamondVersion](/src/client/token/handler/common/AppAdministratorOrOwnerOnlyDiamondVersion.sol/contract.AppAdministratorOrOwnerOnlyDiamondVersion.md)

**Author:**
@ShaneDuncan602, @oscarsernarosero, @TJ-Everett

This contract contains common variables and functions for all Protocol Asset Handlers


## State Variables
### MAX_ORACLE_RULES

```solidity
uint16 constant MAX_ORACLE_RULES = 10;
```


## Functions
### proposeAppManagerAddress

*this function proposes a new appManagerAddress that is put in storage to be confirmed in a separate process*


```solidity
function proposeAppManagerAddress(address _newAppManagerAddress)
    external
    appAdministratorOrOwnerOnly(lib.handlerBaseStorage().appManager);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_newAppManagerAddress`|`address`|the new address being proposed|


### confirmAppManagerAddress

*this function confirms a new appManagerAddress that was put in storageIt can only be confirmed by the proposed address*


```solidity
function confirmAppManagerAddress() external;
```
