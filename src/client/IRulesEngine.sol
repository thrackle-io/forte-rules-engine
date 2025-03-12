// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/**
 * @title Interface for the Rules Engine Run Logic
 * @author @mpetersoCode55 
 */
interface IRulesEngine {

    // Supported Parameter Types
    enum PT {
        ADDR,
        STR,
        UINT,
        BOOL,
        VOID,
        BYTES
    }
    
    /**
     * @dev evaluates the conditions associated with all applicable rules and returns the result
     * @param contractAddress the address of the rules-enabled contract, used to pull the applicable rules
     * @param arguments Think of this as msg.data and whatever other context and global variables you would like to pass in to check.
     */
    function checkPolicies(address contractAddress, bytes calldata arguments) external returns (uint256);

     /**
     * @dev Function to grant calling contract admin role 
     * @dev Call this function from your contract to set calling contract admin 
     * @param _callingContract policy Id 
     * @param _account address to assign admin role Id 
     * @return bytes32 adminRoleId 
     */
    function grantCallingContractRole(address _callingContract, address _account) external returns (bytes32);
}
