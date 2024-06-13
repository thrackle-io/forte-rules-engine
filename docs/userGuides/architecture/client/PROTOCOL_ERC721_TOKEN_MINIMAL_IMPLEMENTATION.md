# Protocol ERC721 Token Minimal Implementation

## Purpose

The [IProtocolER721Min](../../../../src/client/token/ERC721/IProtocolERC721Min.sol) interface contains the minimal set of functions that must be implemented in order for an ERC721 token to be compatible with the protocol.

## Function Overview

The following functions have been defined in the IProtocolERC721Min interface and must be implemented:

- connectHandlerToToken: Used to connect a deployed Protocol Token Handler to the token.

```c
function connectHandlerToToken(address _handlerAddress) external appAdministratorOnly(appManagerAddress)
```

- getHandlerAddress: used to retrieve the address of the Protocol Token Handler.

```c
function getHandlerAddress() external view override returns (address)
```

## checkAllRules Hook

The token must also override the _beforeTokenTransfer function and add a call to the checkAllRules hook defined in the IProtocolTokenHandler interface (using the handler address set in the above functions).
Example:

```c
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override {
        /// Rule Processor Module Check
        require(IProtocolTokenHandler(address(handler)).checkAllRules(balanceOf(from), balanceOf(to), from, to, _msgSender(), amount));
        super._beforeTokenTransfer(from, to, amount);
    }
```