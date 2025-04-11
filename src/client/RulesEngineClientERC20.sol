// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./RulesEngineClient.sol";

/**
 * @title Rules Engine Client
 * @author @ShaneDuncan602
 * @dev The abstract contract containing modifiers used by Rules Engine ERC20 clients. It is intended to be inherited and implemented by client contracts. It is self-contained and requires no additional imports.
 * It contains modifiers for the following functions: 
 *          mint(address,uint256)
 *          transfer(address,uint256)
 *          transferFrom(address,address,uint256)
 */
abstract contract RulesEngineClientERC20 is RulesEngineClient {

    /**
     * @dev This is the modifier used by Rules Engine transfer function. It checks policies before executing the calling function's logic.
     * @param to receiving address
     * @param value amount transferred
     */
    modifier checksPoliciesERC20TransferBefore(address to, uint256 value, uint256 balanceFrom, uint256 balanceTo, uint256 blockTime) {
        _checksPoliciesERC20Transfer(to, value, balanceFrom, balanceTo, blockTime);
        _;
    }

    /**
     * @dev This is the modifier used by Rules Engine transfer function. It checks policies after executing the calling function's logic.
     * @param to receiving address
     * @param value amount transferred
     */
    modifier checksPoliciesERC20TransferAfter(address to, uint256 value, uint256 balanceFrom, uint256 balanceTo, uint256 blockTime) {
        _;
        _checksPoliciesERC20Transfer(to, value, balanceFrom, balanceTo, blockTime);
    }

    /**
     * @dev This is the modifier used by Rules Engine client transferFrom function. It checks policies before executing the calling function's logic.
     * @param from sending address
     * @param to receiving address
     * @param value amount transferred
     */
    modifier checksPoliciesERC20TransferFromBefore(address from, address to, uint256 value, uint256 balanceFrom, uint256 balanceTo, uint256 blockTime) {
        _checksPoliciesERC20TransferFrom(from, to, value, balanceFrom, balanceTo, blockTime);
        _;
    }

    /**
     * @dev This is the modifier used by Rules Engine client transferFrom function. It checks policies before executing the calling function's logic.
     * @param from sending address
     * @param to receiving address
     * @param value amount transferred
     */
    modifier checksPoliciesERC20TransferFromAfter(address from, address to, uint256 value, uint256 balanceFrom, uint256 balanceTo, uint256 blockTime) {
        _;
        _checksPoliciesERC20TransferFrom(from, to, value, balanceFrom, balanceTo, blockTime);
    }

    /**
     * @dev This is the modifier used by Rules Engine mint function. It checks policies before executing the calling function's logic.
     * @param to receiving address
     * @param amount amount transferred
     */
    modifier checksPoliciesERC20MintBefore(address to, uint256 amount, uint256 balanceFrom, uint256 balanceTo, uint256 blockTime) {
        _checksPoliciesERC20Mint(to, amount, balanceFrom, balanceTo, blockTime);
        _;
    }

    /**
     * @dev This is the modifier used by Rules Engine mint function. It checks policies after executing the calling function's logic.
     * @param to receiving address
     * @param amount amount transferred
     */
    modifier checksPoliciesERC20MintAfter(address to, uint256 amount, uint256 balanceFrom, uint256 balanceTo, uint256 blockTime) {
        _;
        _checksPoliciesERC20Mint(to, amount, balanceFrom, balanceTo, blockTime);
    }
    
    /**
     * @dev This function makes the call to the Rules Engine with standard variables for ERC20 Transfer
     * @param to receiving address
     * @param value amount transferred
     */
    function _checksPoliciesERC20Transfer(address to, uint256 value, uint256 balanceFrom, uint256 balanceTo, uint256 blockTime) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, to, value, msg.sender, balanceFrom, balanceTo, blockTime);
        _invokeRulesEngine(encoded);
    }

    /**
     * @dev This function makes the call to the Rules Engine with standard variables for ERC20 transferFrom
     * @param from sending address
     * @param to receiving address
     * @param value amount transferred
     */
    function _checksPoliciesERC20TransferFrom(address from, address to, uint256 value, uint256 balanceFrom, uint256 balanceTo, uint256 blockTime) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, from, to, value, msg.sender, balanceFrom, balanceTo, blockTime);
        _invokeRulesEngine(encoded);
    }

    /**
     * @dev This function makes the call to the Rules Engine with standard variables for ERC20 mint
     * @param to receiving address
     * @param amount amount transferred
     */
    function _checksPoliciesERC20Mint(address to, uint256 amount, uint256 balanceFrom, uint256 balanceTo, uint256 blockTime) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, to, amount, msg.sender, balanceFrom, balanceTo, blockTime);
        _invokeRulesEngine(encoded);
    }
}
