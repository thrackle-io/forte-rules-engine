// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./RulesEngineClient.sol";

/**
 * @title Rules Engine Client ERC1155
 * @dev Abstract contract containing modifiers and functions for integrating ERC1155 token operations with the Rules Engine.
 *      This contract provides policy checks for `safeMint`, `transferFrom`, and `safeTransferFrom` operations, both before and after execution.
 * @notice This contract is intended to be inherited and implemented by ERC1155 token contracts requiring Rules Engine integration.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220, @Palmerg4
 */
abstract contract RulesEngineClientERC1155 is RulesEngineClient {
    
    /**
     * @notice Modifier for checking policies before executing the `safeMint` function.
     * @dev Calls the `_checkPoliciesERC1155SafeMint` function to evaluate policies.
     * @param to The receiving address.
     */
    modifier checksPoliciesERC1155SafeMintBefore(address to) {
        _checkPoliciesERC1155SafeMint(to);
        _;
    }

    /**
     * @notice Modifier for checking policies after executing the `safeMint` function.
     * @dev Calls the `_checkPoliciesERC1155SafeMint` function to evaluate policies.
     * @param to The receiving address.
     */
    modifier checksPoliciesERC1155SafeMintAfter(address to) {
        _;
        _checkPoliciesERC1155SafeMint(to);
    }

    /**
     * @notice Modifier for checking policies before executing the `safeTransferFrom` function.
     * @dev Calls the `_checkPoliciesERC1155SafeTransferFrom` function to evaluate policies.
     * @param from The sending address.
     * @param to The receiving address.
     * @param tokenId The token identifier.
     * @param data Generic data to pass along with the transfer.
     */
    modifier checksPoliciesERC1155SafeTransferFromBefore(address from, address to, uint256 tokenId, bytes memory data) {
       _checkPoliciesERC1155SafeTransferFrom(from, to, tokenId, data);
        _;
    }

    /**
     * @notice Modifier for checking policies after executing the `safeTransferFrom` function.
     * @dev Calls the `_checkPoliciesERC1155SafeTransferFrom` function to evaluate policies.
     * @param from The sending address.
     * @param to The receiving address.
     * @param tokenId The token identifier.
     * @param data Generic data to pass along with the transfer.
     */
    modifier checksPoliciesERC1155SafeTransferFromAfter(address from, address to, uint256 tokenId, bytes memory data) {
        _;
        _checkPoliciesERC1155SafeTransferFrom(from, to, tokenId, data);
    }

    /**
     * @notice Modifier for checking policies before executing the `transferFrom` function.
     * @dev Calls the `_checkPoliciesERC1155TransferFrom` function to evaluate policies.
     * @param from The sending address.
     * @param to The receiving address.
     * @param tokenId The token identifier.
     */
    modifier checksPoliciesERC1155TransferFromBefore(address from, address to, uint256 tokenId) {
       _checkPoliciesERC1155TransferFrom(from, to, tokenId);
        _;
    }

    /**
     * @notice Modifier for checking policies after executing the `transferFrom` function.
     * @dev Calls the `_checkPoliciesERC1155TransferFrom` function to evaluate policies.
     * @param from The sending address.
     * @param to The receiving address.
     * @param tokenId The token identifier.
     */
    modifier checksPoliciesERC1155TransferFromAfter(address from, address to, uint256 tokenId) {
        _;
        _checkPoliciesERC1155TransferFrom(from, to, tokenId);
    }
    
    /**
     * @notice Calls the Rules Engine to evaluate policies for an ERC1155 `safeMint` operation.
     * @dev Encodes the parameters and invokes the `_invokeRulesEngine` function.
     * @param to The receiving address.
     */
    function _checkPoliciesERC1155SafeMint(address to) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, to, msg.sender);
        _invokeRulesEngine(encoded);
    }

    /**
     * @notice Calls the Rules Engine to evaluate policies for an ERC1155 `safeTransferFrom` operation.
     * @dev Encodes the parameters and invokes the `_invokeRulesEngine` function.
     * @param from The sending address.
     * @param to The receiving address.
     * @param tokenId The token identifier.
     * @param data Generic data to pass along with the transfer.
     */
    function _checkPoliciesERC1155SafeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, from, to, tokenId, data, msg.sender);
        _invokeRulesEngine(encoded);
    }

    /**
     * @notice Calls the Rules Engine to evaluate policies for an ERC1155 `transferFrom` operation.
     * @dev Encodes the parameters and invokes the `_invokeRulesEngine` function.
     * @param from The sending address.
     * @param to The receiving address.
     * @param tokenId The token identifier.
     */
    function _checkPoliciesERC1155TransferFrom(address from, address to, uint256 tokenId) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, from, to, tokenId, msg.sender);
        _invokeRulesEngine(encoded);
    }
}