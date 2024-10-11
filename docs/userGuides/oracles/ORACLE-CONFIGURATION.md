# Oracle Configuration
[![Project Version][version-image]][version-url]

Oracles may be used with the protocol to provide approved and/or denied lists. These oracles are used in conjunction with either the [Account Approve Deny Oracle Rule](../rules/ACCOUNT-APPROVE-DENY-ORACLE.md) or the See [Account Approve Deny Oracle Flexible Rule](../rules/ACCOUNT-APPROVE-DENY-ORACLE-FLEXIBLE.md). which are created and applied like any other rule. Up to ten oracle rules may be applied per [action](../rules/ACTION-TYPES.md). The protocol provides example oracle contracts([OracleApproved](../../../src/example/OracleApproved.sol), [OracleDenied](../../../src/example/OracleDenied.sol)) or [external oracles](./EXTERNAL-ORACLE.md) can be created to suit the use case.

## Approval List Oracle

[OracleApproved](../../../src/example/OracleApproved.sol) allows for addresses to be added/removed from an internal list that is then checked by the [Account Approve Deny Oracle Rule](../rules/ACCOUNT-APPROVE-DENY-ORACLE.md) during the applied user action when the rule's **_oracleType** is 1.

### Add Functions

```c
function addToApprovedList(address[] memory newApproves) public onlyOwner
```
```c
function addAddressToApprovedList(address newApprove) public onlyOwner
```

### Remove Functions

```c
function removeFromAprovededList(address[] memory removeApprove) public onlyOwner 
```

### Check Functions
```c
function isApproved(address addr) public view returns (bool) 
```
```c
function isApprovedVerbose(address addr) public returns (bool)
```
### Parameters:

- **newApprove** (address): new approved address.
- **newApproves** (address[]): array of approved addresses.
- **removeApprove** (address): address to remove from approval list
- **addr** (address): address to check for approval


### Parameter Optionality:

There are no options for the parameters of the add or remove functions.

The implementations for each of the above functions can be found in the [OracleApproved](../../../src/example/OracleApproved.sol) contract.


## Denial List Oracle

[OracleDenied](../../../src/example/OracleDenied.sol) allows for addresses to be added/removed from an internal list that is then checked by the [Account Approve Deny Oracle Rule](../rules/ACCOUNT-APPROVE-DENY-ORACLE.md) during the applied user action when the rule's **oracleType** is 0.

### Add Functions

```c
function addToDeniedList(address[] memory newDeniedAddrs) public onlyOwner
```
```c
function addAddressToDeniedList(address newDeniedAddr) public onlyOwner
```

### Remove Functions

```c
function removeFromDeniedList(address[] memory removeDeniedAddrs) public onlyOwner 
```

### Check Functions
```c
function isDenied(address addr) public view returns (bool) 
```
```c
function isDeniedVerbose(address addr) public returns (bool)
```
### Parameters:

- **newDeniedAddr** (address): new denied address.
- **newDeniedAddrs** (address[]): array of denied addresses.
- **removeDeniedAddr** (address): address to remove from denied list
- **removeDeniedAddrs** (address[]): addresses to remove from denied list
- **addr** (address): address to check for denial


### Parameter Optionality:

There are no options for the parameters of the add or remove functions.

The implementations for each of the above functions can be found in the [OracleDenied](../../../src/example/OracleDenied.sol) contract.


## Upgrading: 

To upgrade to a new oracle address first create a new `AccountApproveOrDenyOracle` [rule](../rules/ACCOUNT-APPROVE-DENY-ORACLE.md) or `AccountApproveOrDenyOracleFlexible` [rule](../rules/ACCOUNT-APPROVE-DENY-ORACLE-FLEXIBLE.md)with the new oracle type and address. This requires the new oracle address to be deployed and conform to the [IOracle](../../../src/common/IOracle.sol) interface. Add the new rule with the [Rule Processor Diamond](../architecture/protocol/RULE-PROCESSOR-DIAMOND.md) and use the protocol generated `ruleId` to set the new oracle rule within the [asset handler](../architecture/client/assetHandler/PROTOCOL-ASSET-HANDLER-DIAMOND.md) to be upgraded. 

## Process for switching to an external access level provider

See [External Oracle](./EXTERNAL-ORACLE.md) for details.


<!-- These are the header links -->
[version-image]: https://img.shields.io/badge/Version-2.1.0-brightgreen?style=for-the-badge&logo=appveyor
[version-url]: https://github.com/thrackle-io/forte-rules-engine
