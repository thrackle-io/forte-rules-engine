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
     * @param tokenId The token identifier.
     * @param value The value of tokenId being transfered.
     * @param data Generic data to pass along with the transfer.
     */
    modifier checksPoliciesERC1155MintBefore(address to, uint256 tokenId, uint256 value, bytes memory data) {
        _checkPoliciesERC1155Mint(to, tokenId, value, data);
        _;
    }

    /**
     * @notice Modifier for checking policies after executing the `safeMint` function.
     * @dev Calls the `_checkPoliciesERC1155SafeMint` function to evaluate policies.
     * @param to The receiving address.
     * @param tokenId The token identifier.
     * @param value The value of tokenId being transfered.
     * @param data Generic data to pass along with the transfer.
     */
    modifier checksPoliciesERC1155MintAfter(address to, uint256 tokenId, uint256 value, bytes memory data) {
        _;
        _checkPoliciesERC1155Mint(to, tokenId, value, data);
    }

    /**
     * @notice Modifier for checking policies before executing the `safeMint` function.
     * @dev Calls the `_checkPoliciesERC1155SafeMint` function to evaluate policies.
     * @param to The receiving address.
     * @param tokenIds The token identifiers.
     * @param values The values of tokenIds being transfered.
     * @param data Generic data to pass along with the transfer.
     */
    modifier checksPoliciesERC1155BatchMintBefore(address to, uint256[] memory tokenIds, uint256[] memory values, bytes memory data) {
        _checkPoliciesERC1155MintBatch(to, tokenIds, values, data);
        _;
    }

    /**
     * @notice Modifier for checking policies after executing the `safeMint` function.
     * @dev Calls the `_checkPoliciesERC1155SafeMint` function to evaluate policies.
     * @param to The receiving address.
     * @param tokenIds The token identifiers.
     * @param values The values of tokenIds being transfered.
     * @param data Generic data to pass along with the transfer.
     */
    modifier checksPoliciesERC1155BatchMintAfter(address to, uint256[] memory tokenIds, uint256[] memory values, bytes memory data) {
        _;
        _checkPoliciesERC1155MintBatch(to, tokenIds, values, data);
    }

    /**
     * @notice Modifier for checking policies before executing the `safeTransferFrom` function.
     * @dev Calls the `_checkPoliciesERC1155SafeTransferFrom` function to evaluate policies.
     * @param from The sending address.
     * @param to The receiving address.
     * @param tokenId The token identifier.
     * @param value The value of tokenId being transfered.
     * @param data Generic data to pass along with the transfer.
     */
    modifier checksPoliciesERC1155SafeTransferFromBefore(address from, address to, uint256 tokenId, uint256 value, bytes memory data) {
       _checkPoliciesERC1155SafeTransferFrom(from, to, tokenId, value, data);
        _;
    }

    /**
     * @notice Modifier for checking policies after executing the `safeTransferFrom` function.
     * @dev Calls the `_checkPoliciesERC1155SafeTransferFrom` function to evaluate policies.
     * @param from The sending address.
     * @param to The receiving address.
     * @param tokenId The token identifier.
     * @param value The value of tokenId being transfered.
     * @param data Generic data to pass along with the transfer.
     */
    modifier checksPoliciesERC1155SafeTransferFromAfter(address from, address to, uint256 tokenId, uint256 value, bytes memory data) {
        _;
        _checkPoliciesERC1155SafeTransferFrom(from, to, tokenId, value, data);
    }

    /**
     * @notice Modifier for checking policies before executing the `transferFrom` function.
     * @dev Calls the `_checkPoliciesERC1155TransferFrom` function to evaluate policies.
     * @param from The sending address.
     * @param to The receiving address.
     * @param tokenIds The token identifiers.
     * @param values The values of tokenIds being transfered.
     */
    modifier checksPoliciesERC1155SafeBatchTransferFromBefore(address from, address to, uint256[] memory tokenIds, uint256[] memory values, bytes memory data) {
       _checkPoliciesERC1155SafeBatchTransferFrom(from, to, tokenIds, values, data);
        _;
    }

    /**
     * @notice Modifier for checking policies before executing the `transferFrom` function.
     * @dev Calls the `_checkPoliciesERC1155TransferFrom` function to evaluate policies.
     * @param from The sending address.
     * @param to The receiving address.
     * @param tokenIds The token identifiers.
     * @param values The values of tokenIds being transfered.
     */
    modifier checksPoliciesERC1155SafeBatchTransferFromAfter(address from, address to, uint256[] memory tokenIds, uint256[] memory values, bytes memory data) {
        _;
        _checkPoliciesERC1155SafeBatchTransferFrom(from, to, tokenIds, values, data);
    }

    /**
     * @notice Calls the Rules Engine to evaluate policies for an ERC1155 `Mint` operation.
     * @dev Encodes the parameters and invokes the `_invokeRulesEngine` function.
     * @param _to The receiving address.
     * @param _tokenId The token identifier.
     * @param _value The value of tokenId being transfered.
     * @param _data Generic data to pass along with the transfer.
     */
    function _checkPoliciesERC1155Mint(address _to, uint256 _tokenId, uint256 _value, bytes memory _data) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _to, _tokenId, _value, _data, msg.sender);
        _invokeRulesEngine(encoded);
    }

    /**
     * @notice Calls the Rules Engine to evaluate policies for an ERC1155 `MintBatch` operation.
     * @dev Encodes the parameters and invokes the `_invokeRulesEngine` function.
     * @param _to The receiving address.
     * @param _tokenIds The token identifiers.
     * @param _values The values of tokenIds being transfered.
     * @param _data Generic data to pass along with the transfer.
     */
    function _checkPoliciesERC1155MintBatch(address _to, uint256[] memory _tokenIds, uint256[] memory _values, bytes memory _data) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _to, _tokenIds, _values, _data, msg.sender);
        _invokeRulesEngine(encoded);
    }

    /**
     * @notice Calls the Rules Engine to evaluate policies for an ERC1155 `safeTransferFrom` operation.
     * @dev Encodes the parameters and invokes the `_invokeRulesEngine` function.
     * @param _from The sending address.
     * @param _to The receiving address.
     * @param _tokenId The token identifier.
     * @param _value The value of tokenId being transfered.
     * @param _data Generic data to pass along with the transfer.
     */
    function _checkPoliciesERC1155SafeTransferFrom(address _from, address _to, uint256 _tokenId, uint256 _value, bytes memory _data) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _from, _to, _tokenId, _value, _data, msg.sender);
        _invokeRulesEngine(encoded);
    }

    /**
     * @notice Calls the Rules Engine to evaluate policies for an ERC1155 `safeTransferFrom` operation.
     * @dev Encodes the parameters and invokes the `_invokeRulesEngine` function.
     * @param _from The sending address.
     * @param _to The receiving address.
     * @param _tokenIds The token identifiers.
     * @param _values The values of tokenIds being transfered.
     * @param _data Generic data to pass along with the transfer.
     */
    function _checkPoliciesERC1155SafeBatchTransferFrom(address _from, address _to, uint256[] memory _tokenIds, uint256[] memory _values, bytes memory _data) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _from, _to, _tokenIds, _values, _data, msg.sender);
        _invokeRulesEngine(encoded);
    }

    /**
     * @notice Calls the Rules Engine to evaluate policies for an ERC1155 `transferFrom` operation.
     * @dev Encodes the parameters and invokes the `_invokeRulesEngine` function.
     * @param _from The sending address.
     * @param _to The receiving address.
     * @param _tokenId The token identifier.
     */
    function _checkPoliciesERC1155TransferFrom(address _from, address _to, uint256 _tokenId) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _from, _to, _tokenId, msg.sender);
        _invokeRulesEngine(encoded);
    }
}