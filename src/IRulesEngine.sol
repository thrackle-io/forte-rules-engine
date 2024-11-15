// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/**
 * @title Interface for the Rules Engine Run Logic
 * @author @mpetersoCode55 
 */
interface IRulesEngine {
    /**
     * @dev evaluates the conditions associated with all applicable rules and returns the result
     * @param contractAddress the address of the rules-enabled contract, used to pull the applicable rules
     * @param functionSignature the signature of the function that initiated the transaction, used to pull the applicable rules.
     */
    function checkPolicies(address contractAddress, bytes calldata functionSignature, bytes calldata arguments) external returns (bool);
}