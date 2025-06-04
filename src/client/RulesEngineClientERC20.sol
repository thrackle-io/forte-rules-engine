// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./RulesEngineClient.sol";

/**
 * @title Rules Engine Client ERC20
 * @dev Abstract contract containing modifiers and functions for integrating ERC20 token operations with the Rules Engine.
 *      This contract provides policy checks for `mint`, `transfer`, and `transferFrom` operations, both before and after execution.
 * @notice This contract is intended to be inherited and implemented by ERC20 token contracts requiring Rules Engine integration.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
abstract contract RulesEngineClientERC20 is RulesEngineClient {

    /**
     * @notice Modifier for checking policies before executing the `transfer` function.
     * @dev Calls the `_checksPoliciesERC20Transfer` function to evaluate policies.
     * @param to The receiving address.
     * @param value The amount to transfer.
     * @param balanceFrom The sender's balance before the transfer.
     * @param balanceTo The receiver's balance before the transfer.
     * @param blockTime The current block timestamp.
     */
    modifier checksPoliciesERC20TransferBefore(address to, uint256 value, uint256 balanceFrom, uint256 balanceTo, uint256 blockTime) {
        _checksPoliciesERC20Transfer(to, value, balanceFrom, balanceTo, blockTime);
        _;
    }

    /**
     * @notice Modifier for checking policies after executing the `transfer` function.
     * @dev Calls the `_checksPoliciesERC20Transfer` function to evaluate policies.
     * @param to The receiving address.
     * @param value The amount to transfer.
     * @param balanceFrom The sender's balance after the transfer.
     * @param balanceTo The receiver's balance after the transfer.
     * @param blockTime The current block timestamp.
     */
    modifier checksPoliciesERC20TransferAfter(address to, uint256 value, uint256 balanceFrom, uint256 balanceTo, uint256 blockTime) {
        _;
        _checksPoliciesERC20Transfer(to, value, balanceFrom, balanceTo, blockTime);
    }

    /**
     * @notice Modifier for checking policies before executing the `transferFrom` function.
     * @dev Calls the `_checksPoliciesERC20TransferFrom` function to evaluate policies.
     * @param from The sending address.
     * @param to The receiving address.
     * @param value The amount to transfer.
     * @param balanceFrom The sender's balance before the transfer.
     * @param balanceTo The receiver's balance before the transfer.
     * @param blockTime The current block timestamp.
     */
    modifier checksPoliciesERC20TransferFromBefore(address from, address to, uint256 value, uint256 balanceFrom, uint256 balanceTo, uint256 blockTime) {
        _checksPoliciesERC20TransferFrom(from, to, value, balanceFrom, balanceTo, blockTime);
        _;
    }

    /**
     * @notice Modifier for checking policies after executing the `transferFrom` function.
     * @dev Calls the `_checksPoliciesERC20TransferFrom` function to evaluate policies.
     * @param from The sending address.
     * @param to The receiving address.
     * @param value The amount to transfer.
     * @param balanceFrom The sender's balance after the transfer.
     * @param balanceTo The receiver's balance after the transfer.
     * @param blockTime The current block timestamp.
     */
    modifier checksPoliciesERC20TransferFromAfter(address from, address to, uint256 value, uint256 balanceFrom, uint256 balanceTo, uint256 blockTime) {
        _;
        _checksPoliciesERC20TransferFrom(from, to, value, balanceFrom, balanceTo, blockTime);
    }

    /**
     * @notice Modifier for checking policies before executing the `mint` function.
     * @dev Calls the `_checksPoliciesERC20Mint` function to evaluate policies.
     * @param to The receiving address.
     * @param amount The amount to mint.
     * @param balanceFrom The sender's balance before the mint.
     * @param balanceTo The receiver's balance before the mint.
     * @param blockTime The current block timestamp.
     */
    modifier checksPoliciesERC20MintBefore(address to, uint256 amount, uint256 balanceFrom, uint256 balanceTo, uint256 blockTime) {
        _checksPoliciesERC20Mint(to, amount, balanceFrom, balanceTo, blockTime);
        _;
    }

    /**
     * @notice Modifier for checking policies after executing the `mint` function.
     * @dev Calls the `_checksPoliciesERC20Mint` function to evaluate policies.
     * @param to The receiving address.
     * @param amount The amount to mint.
     * @param balanceFrom The sender's balance after the mint.
     * @param balanceTo The receiver's balance after the mint.
     * @param blockTime The current block timestamp.
     */
    modifier checksPoliciesERC20MintAfter(address to, uint256 amount, uint256 balanceFrom, uint256 balanceTo, uint256 blockTime) {
        _;
        _checksPoliciesERC20Mint(to, amount, balanceFrom, balanceTo, blockTime);
    }

    /**
     * @notice Calls the Rules Engine to evaluate policies for an ERC20 `transfer` operation.
     * @dev Encodes the parameters and invokes the `_invokeRulesEngine` function.
     * @param _to The receiving address.
     * @param _value The amount to transfer.
     * @param _balanceFrom The sender's balance.
     * @param _balanceTo The receiver's balance.
     * @param _blockTime The current block timestamp.
     */
    function _checksPoliciesERC20Transfer(address _to, uint256 _value, uint256 _balanceFrom, uint256 _balanceTo, uint256 _blockTime) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _to, _value, msg.sender, _balanceFrom, _balanceTo, _blockTime);
        _invokeRulesEngine(encoded);
    }

    /**
     * @notice Calls the Rules Engine to evaluate policies for an ERC20 `transferFrom` operation.
     * @dev Encodes the parameters and invokes the `_invokeRulesEngine` function.
     * @param _from The sending address.
     * @param _to The receiving address.
     * @param _value The amount to transfer.
     * @param _balanceFrom The sender's balance.
     * @param _balanceTo The receiver's balance.
     * @param _blockTime The current block timestamp.
     */
    function _checksPoliciesERC20TransferFrom(address _from, address _to, uint256 _value, uint256 _balanceFrom, uint256 _balanceTo, uint256 _blockTime) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _from, _to, _value, msg.sender, _balanceFrom, _balanceTo, _blockTime);
        _invokeRulesEngine(encoded);
    }

    /**
     * @notice Calls the Rules Engine to evaluate policies for an ERC20 `mint` operation.
     * @dev Encodes the parameters and invokes the `_invokeRulesEngine` function.
     * @param _to The receiving address.
     * @param _amount The amount to mint.
     * @param _balanceFrom The sender's balance.
     * @param _balanceTo The receiver's balance.
     * @param _blockTime The current block timestamp.
     */
    function _checksPoliciesERC20Mint(address _to, uint256 _amount, uint256 _balanceFrom, uint256 _balanceTo, uint256 _blockTime) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _to, _amount, msg.sender, _balanceFrom, _balanceTo, _blockTime);
        _invokeRulesEngine(encoded);
    }
}