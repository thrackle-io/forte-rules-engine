# ApplicationHandler
[Git Source](https://github.com/thrackle-io/forte-rules-engine/blob/cb826e7b7899f2d90490d1eaeb0e665e017648fa/src/example/application/ApplicationHandler.sol)

**Inherits:**
[ProtocolApplicationHandler](/src/client/application/ProtocolApplicationHandler.sol/contract.ProtocolApplicationHandler.md)

**Author:**
@ShaneDuncan602, @oscarsernarosero, @TJ-Everett

This contract is the connector between the AppManagerRulesDiamond and the Application App Managers. It is maintained by the client application.
Deployment happens automatically when the AppManager is deployed.

*This contract is injected into the appManagerss.*


## Functions
### constructor

*Initializes the contract setting the owner as the one provided.*


```solidity
constructor(address _ruleProcessorProxyAddress, address _appManagerAddress)
    ProtocolApplicationHandler(_ruleProcessorProxyAddress, _appManagerAddress);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_ruleProcessorProxyAddress`|`address`|of the protocol's Rule Processor contract.|
|`_appManagerAddress`|`address`|address of the application AppManager.|


