# ProtocolTokenCommonU
[Git Source](https://github.com/thrackle-io/tron/blob/ee06788a23623ed28309de5232eaff934d34a0fe/src/client/token/ProtocolTokenCommonU.sol)

**Inherits:**
[AppAdministratorOnlyU](/src/protocol/economic/AppAdministratorOnlyU.sol/contract.AppAdministratorOnlyU.md), [IApplicationEvents](/src/common/IEvents.sol/interface.IApplicationEvents.md), [IZeroAddressError](/src/common/IErrors.sol/interface.IZeroAddressError.md), [IOwnershipErrors](/src/common/IErrors.sol/interface.IOwnershipErrors.md)

**Author:**
@ShaneDuncan602, @oscarsernarosero, @TJ-Everett

This contract contains common variables and functions for all Protocol Tokens


## State Variables
### newAppManagerAddress

```solidity
address newAppManagerAddress;
```


### appManagerAddress

```solidity
address appManagerAddress;
```


### appManager

```solidity
IAppManager appManager;
```


## Functions
### proposeAppManagerAddress

*this function proposes a new appManagerAddress that is put in storage to be confirmed in a separate process*


```solidity
function proposeAppManagerAddress(address _newAppManagerAddress) external appAdministratorOnly(appManagerAddress);
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

### getAppManagerAddress

*Function to get the appManagerAddress*

*AppAdministratorOnly modifier uses appManagerAddress. Only Addresses asigned as AppAdministrator can call function.*


```solidity
function getAppManagerAddress() external view returns (address);
```
