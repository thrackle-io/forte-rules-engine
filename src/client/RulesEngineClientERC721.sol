// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./IRulesEngine.sol";

/**
 * @title Rules Engine Client ERC721
 * @author @ShaneDuncan602
 * @dev The abstract contract containing modifiers used by Rules Engine clients. It is intended to be inherited and implemented by client contracts. It is self-contained and requires no additional imports.
 * It contains before and after modifiers for the following functions: 
 *          transferFrom(address,address,uint256)
 *          safeTransferFrom(address,address,uint256,bytes)
 *          safeMint(address)
 */
abstract contract RulesEngineClientERC721 {
    
    address public rulesEngineAddress;

    /**
     * Set the Rules Engine address
     * @param rulesEngine rules engine address
     */
    function setRulesEngineAddress(address rulesEngine) public {
        rulesEngineAddress = rulesEngine;
    }

    /**
     * @dev This is the modifier used by Rules Engine safeMint function. It checks policies before executing the calling function's logic.
     * @param to receiving address
     */
    modifier checksPoliciesERC721SafeMintBefore(address to) {
        _checkPoliciesERC721SafeMint(to);
        _;
    }

    /**
     * @dev This is the modifier used by Rules Engine safeMint function. It checks policies after executing the calling function's logic.
     * @param to receiving address
     */
    modifier checksPoliciesERC721SafeMintAfter(address to) {
        _;
        _checkPoliciesERC721SafeMint(to);
    }

    /**
     * @dev This is the modifier used by Rules Engine safeTransferFrom function. It checks policies before executing the calling function's logic.
     * @param from sending address
     * @param to receiving address
     * @param tokenId token identifier
     * @param data generic data
     */
    modifier checksPoliciesERC721SafeTransferFromBefore(address from, address to, uint256 tokenId, bytes memory data) {
       _checkPoliciesERC721SafeTransferFrom(from, to, tokenId, data);
        _;
    }

    /**
     * @dev This is the modifier used by Rules Engine safeTransferFrom function. It checks policies after executing the calling function's logic.
     * @param from sending address
     * @param to receiving address
     * @param tokenId token identifier
     * @param data generic data
     */
    modifier checksPoliciesERC721SafeTransferFromAfter(address from, address to, uint256 tokenId, bytes memory data) {
        _;
        _checkPoliciesERC721SafeTransferFrom(from, to, tokenId, data);
    }

    /**
     * @dev This is the modifier used by Rules Engine transferFrom function. It checks policies before executing the calling function's logic.
     * @param from sending address
     * @param to receiving address
     * @param tokenId token identifier
     */
    modifier checksPoliciesERC721TransferFromBefore(address from, address to, uint256 tokenId) {
       _checkPoliciesERC721TransferFrom(from, to, tokenId);
        _;
    }

    /**
     * @dev This is the modifier used by Rules Engine transferFrom function. It checks policies after executing the calling function's logic.
     * @param from sending address
     * @param to receiving address
     * @param tokenId token identifier
     */
    modifier checksPoliciesERC721TransferFromAfter(address from, address to, uint256 tokenId) {
        _;
        _checkPoliciesERC721TransferFrom(from, to, tokenId);
    }
    
    /**
     * @dev This function makes the call to the Rules Engine with standard variables for safeMint
     * @param to receiving address
     */
    function _checkPoliciesERC721SafeMint(address to) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, to, msg.sender);
        _invokeRulesEngine(encoded);
    }

    /**
     * @dev This function makes the call to the Rules Engine with standard variables for safeTransferFrom
     * @param from sending address
     * @param to receiving address
     * @param tokenId token identifier
     * @param data generic data
     */
    function _checkPoliciesERC721SafeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, from, to, tokenId, data, msg.sender);
        _invokeRulesEngine(encoded);
    }

    /**
     * @dev This function makes the call to the Rules Engine with standard variables for safeTransferFrom
     * @param from sending address
     * @param to receiving address
     * @param tokenId token identifier
     */
    function _checkPoliciesERC721TransferFrom(address from, address to, uint256 tokenId) internal {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, from, to, tokenId, msg.sender);
        _invokeRulesEngine(encoded);
    }

    /**
     * @dev This function makes the call to the Rules Engine
     * @param args function signature's arguments
     * @return retval return value from the rules engine
     */
    function _invokeRulesEngine(bytes memory args) internal returns (uint256 retval) {
        if (rulesEngineAddress != address(0)) return IRulesEngine(rulesEngineAddress).checkPolicies(address(this), args);
    }
}
