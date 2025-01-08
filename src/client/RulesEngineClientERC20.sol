// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./IRulesEngine.sol";

/**
 * @title Rules Engine Client
 * @author @ShaneDuncan602
 * @dev The abstract contract containing modifiers used by Rules Engine ERC20 clients. It is intended to be inherited and implemented by client contracts. It is self-contained and requires no additional imports.
 * It contains modifiers for the following functions: 
 *          mint(address,uint256)
 *          transfer(address,uint256)
 *          transferFrom(address,address,uint256)
 */
abstract contract RulesEngineClientERC20 {
    struct Arguments {
        // Parameter types of arguments in order
        IRulesEngine.PT[] argumentTypes;
        // The actual values of the arguments in order
        bytes[] values;
    }
    
    address public rulesEngineAddress;

    /**
     * Set the Rules Engine address
     * @param rulesEngine rules engine address
     */
    function setRulesEngineAddress(address rulesEngine) public {
        rulesEngineAddress = rulesEngine;
    }

    /**
     * @dev This is the modifier used by Rules Engine transfer function. It checks policies before executing the calling function's logic.
     * @param to receiving address
     * @param value amount transferred
     */
    modifier checksPoliciesERC20TransferBefore(address to, uint256 value) {
        _checksPoliciesERC20Transfer(to, value);
        _;
    }

    /**
     * @dev This is the modifier used by Rules Engine transfer function. It checks policies after executing the calling function's logic.
     * @param to receiving address
     * @param value amount transferred
     */
    modifier checksPoliciesERC20TransferAfter(address to, uint256 value) {
        _;
        _checksPoliciesERC20Transfer(to, value);
    }

    /**
     * @dev This is the modifier used by Rules Engine client transferFrom function. It checks policies before executing the calling function's logic.
     * @param from sending address
     * @param to receiving address
     * @param value amount transferred
     */
    modifier checksPoliciesERC20TransferFromBefore(address from, address to, uint256 value) {
        _checksPoliciesERC20TransferFrom(from, to, value);
        _;
    }

    /**
     * @dev This is the modifier used by Rules Engine client transferFrom function. It checks policies before executing the calling function's logic.
     * @param from sending address
     * @param to receiving address
     * @param value amount transferred
     */
    modifier checksPoliciesERC20TransferFromAfter(address from, address to, uint256 value) {
        _;
        _checksPoliciesERC20TransferFrom(from, to, value);
    }

    /**
     * @dev This is the modifier used by Rules Engine mint function. It checks policies before executing the calling function's logic.
     * @param to receiving address
     * @param amount amount transferred
     */
    modifier checksPoliciesERC20MintBefore(address to, uint256 amount) {
        _checksPoliciesERC20Mint(to, amount);
        _;
    }

    /**
     * @dev This is the modifier used by Rules Engine mint function. It checks policies after executing the calling function's logic.
     * @param to receiving address
     * @param amount amount transferred
     */
    modifier checksPoliciesERC20MintAfter(address to, uint256 amount) {
        _;
        _checksPoliciesERC20Mint(to, amount);
    }
    
    /**
     * @dev This function makes the call to the Rules Engine with standard variables for ERC20 Transfer
     * @param to receiving address
     * @param value amount transferred
     */
    function _checksPoliciesERC20Transfer(address to, uint256 value) internal {
        Arguments memory args;
        args.values = new bytes[](3);
        args.values[0] = abi.encode(address(to));
        args.values[1] = abi.encode(uint256(value));
        args.values[2] = abi.encode(msg.sender);
        args.argumentTypes = new IRulesEngine.PT[](3);
        args.argumentTypes[0] = IRulesEngine.PT.ADDR;
        args.argumentTypes[1] = IRulesEngine.PT.UINT;
        args.argumentTypes[2] = IRulesEngine.PT.ADDR;
        bytes memory encoded = abi.encode(args);
        _invokeRulesEngine(bytes4(keccak256("transfer(address,uint256)")), encoded);
    }

    /**
     * @dev This function makes the call to the Rules Engine with standard variables for ERC20 transferFrom
     * @param from sending address
     * @param to receiving address
     * @param value amount transferred
     */
    function _checksPoliciesERC20TransferFrom(address from, address to, uint256 value) internal {
        Arguments memory args;
        args.values = new bytes[](4);
        args.values[0] = abi.encode(address(from));
        args.values[1] = abi.encode(address(to));
        args.values[2] = abi.encode(uint256(value));
        args.values[3] = abi.encode(msg.sender);
        args.argumentTypes = new IRulesEngine.PT[](4);
        args.argumentTypes[0] = IRulesEngine.PT.ADDR;
        args.argumentTypes[1] = IRulesEngine.PT.ADDR;
        args.argumentTypes[2] = IRulesEngine.PT.UINT;
        args.argumentTypes[3] = IRulesEngine.PT.ADDR;
        bytes memory encoded = abi.encode(args);
        _invokeRulesEngine(bytes4(keccak256("transferFrom(address,address,uint256)")), encoded);
    }

    /**
     * @dev This function makes the call to the Rules Engine with standard variables for ERC20 mint
     * @param to receiving address
     * @param amount amount transferred
     */
    function _checksPoliciesERC20Mint(address to, uint256 amount) internal {
        Arguments memory args;
        args.values = new bytes[](3);
        args.values[0] = abi.encode(to);
        args.values[1] = abi.encode(amount);
        args.values[2] = abi.encode(msg.sender);
        args.argumentTypes = new IRulesEngine.PT[](3);
        args.argumentTypes[0] = IRulesEngine.PT.ADDR;
        args.argumentTypes[1] = IRulesEngine.PT.UINT;
        args.argumentTypes[2] = IRulesEngine.PT.ADDR;
        bytes memory encoded = abi.encode(args);
        _invokeRulesEngine(bytes4(keccak256("mint(address,uint256)")), encoded);
    }

    /**
     * @dev This function makes the call to the Rules Engine
     * @param signature calling function signature
     * @param args function signature's arguments
     * @return retval return value from the rules engine
     */
    function _invokeRulesEngine(bytes4 signature, bytes memory args) internal returns (uint256 retval) {
        if (rulesEngineAddress != address(0)) return IRulesEngine(rulesEngineAddress).checkPolicies(address(this), signature, args);
    }
}
