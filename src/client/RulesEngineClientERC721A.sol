// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./RulesEngineClient.sol";

/**
 * @title Rules Engine Client ERC721A
 * @dev Abstract contract containing modifiers and functions for integrating ERC721A token operations with the Rules Engine.
 *      This contract provides policy checks for `mint`, `safeBatchtransferFrom`, and `safeTransferFrom` operations, both before and after execution.
 * @notice This contract is intended to be inherited and implemented by ERC721A token contracts requiring Rules Engine integration.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220, @Palmerg4
 */
abstract contract RulesEngineClientERC721A is RulesEngineClient {
    /**
     * @notice Modifier for checking policies before executing the `safeTransferFrom` function.
     * @dev Calls the `_checkPoliciesERC721ASafeTransferFrom` function to evaluate policies.
     * @param from The sending address.
     * @param to The receiving address.
     * @param tokenId The token identifier.
     */
    modifier checksPoliciesERC721ASafeTransferFromBefore(address from, address to, uint256 tokenId) {
       _checkPoliciesERC721ASafeTransferFrom(from, to, tokenId);
        _;
    }

    /**
     * @notice Modifier for checking policies after executing the `safeTransferFrom` function.
     * @dev Calls the `_checkPoliciesERC721SafeTransferFrom` function to evaluate policies.
     * @param from The sending address.
     * @param to The receiving address.
     * @param tokenId The token identifier.
     */
    modifier checksPoliciesERC721ASafeTransferFromAfter(address from, address to, uint256 tokenId) {
        _;
        _checkPoliciesERC721ASafeTransferFrom(from, to, tokenId);
    }

    /**
     * @notice Modifier for checking policies before executing the `safeBatchTransferFrom` function.
     * @dev Calls the `_checkPoliciesERC721ASafeTransferFrom` function to evaluate policies.
     * @param by The approved address.
     * @param from The sending address.
     * @param to The receiving address.
     * @param tokenIds The token identifiers.
     * @param data Generic data to pass along with the transfer.
     */
    modifier checksPoliciesERC721ASafeBatchTransferFromBefore(address by, address from, address to, uint256[] memory tokenIds, bytes memory data) {
       _checkPoliciesERC721ASafeBatchTransferFrom(by, from, to, tokenIds, data);
        _;
    }

    /**
     * @notice Modifier for checking policies after executing the `safeBatchTransferFrom` function.
     * @dev Calls the `_checkPoliciesERC721SafeBatchTransferFrom` function to evaluate policies.
     * @param by The approved address.
     * @param from The sending address.
     * @param to The receiving address.
     * @param tokenIds The token identifiers.
     * @param data Generic data to pass along with the transfer.
     */
    modifier checksPoliciesERC721ASafeBatchTransferFromAfter(address by, address from, address to, uint256[] memory tokenIds, bytes memory data) {
        _;
        _checkPoliciesERC721ASafeBatchTransferFrom(by, from, to, tokenIds, data);
    }

    /**
     * @notice Modifier for checking policies before executing the `mint` function.
     * @dev Calls the `_checkPoliciesERC721SafeMint` function to evaluate policies.
     * @param to The receiving address.
     * @param quantity The amount of tokens minted.
     */
    modifier checksPoliciesERC721AMintBefore(address to, uint256 quantity) {
        _checkPoliciesERC721AMint(to, quantity);
        _;
    }

    /**
     * @notice Modifier for checking policies after executing the `mint` function.
     * @dev Calls the `_checkPoliciesERC721AMint` function to evaluate policies.
     * @param to The receiving address.
     * @param quantity The amount of tokens minted.
     */
    modifier checksPoliciesERC721AMintAfter(address to, uint256 quantity) {
        _;
        _checkPoliciesERC721AMint(to, quantity);
    }

    /**
     * @notice Calls the Rules Engine to evaluate policies for an ERC721A `safeTransferFrom` operation.
     * @dev Encodes the parameters and invokes the `_invokeRulesEngine` function.
     * @param _from The sending address.
     * @param _to The receiving address.
     * @param _tokenId The token identifier.
     */
    function _checkPoliciesERC721ASafeTransferFrom(address _from, address _to, uint256 _tokenId) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _from, _to, _tokenId, msg.sender);
        _invokeRulesEngine(encoded);
    }

    /**
     * @notice Calls the Rules Engine to evaluate policies for an ERC721A `safeTransferFrom` operation.
     * @dev Encodes the parameters and invokes the `_invokeRulesEngine` function.
     * @param _from The sending address.
     * @param _to The receiving address.
     * @param _tokenIds The token identifiers.
     * @param _data Generic data to pass along with the transfer.
     */
    function _checkPoliciesERC721ASafeBatchTransferFrom(address _by, address _from, address _to, uint256[] memory _tokenIds, bytes memory _data) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _by, _from, _to, _tokenIds, _data, msg.sender);
        _invokeRulesEngine(encoded);
    }

    /**
     * @notice Calls the Rules Engine to evaluate policies for an ERC721 `safeMint` operation.
     * @dev Encodes the parameters and invokes the `_invokeRulesEngine` function.
     * @param _to The receiving address.
     * @param _quantity The amount of tokens minted.
     */
    function _checkPoliciesERC721AMint(address _to, uint256 _quantity) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _to, _quantity, msg.sender);
        _invokeRulesEngine(encoded);
    }
}