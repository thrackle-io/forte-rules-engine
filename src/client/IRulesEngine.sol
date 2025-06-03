/// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.13;

/**
 * @title IRulesEngine
 * @dev Interface for the Rules Engine Run Logic. This interface defines the core functions and data types 
 *      required for evaluating rules and managing roles in a rules-enabled contract.
 * @notice This interface is intended to be implemented by contracts that require rules evaluation and role management.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
interface IRulesEngine {
    
    /**
     * @notice Evaluates the conditions associated with all applicable rules and returns the result.
     * @dev This function checks the rules associated with the provided contract address and arguments.
     * @param contractAddress The address of the rules-enabled contract, used to pull the applicable rules.
     * @param arguments Additional context and global variables to pass in for evaluation, similar to `msg.data`.
     * @return uint256 The result of the rules evaluation.
     */
    function checkPolicies(address contractAddress, bytes calldata arguments) external returns (uint256);

    /**
     * @notice Grants the calling contract admin role to a specified account.
     * @dev Call this function from your contract to assign the admin role for a specific calling contract.
     * @param _callingContract The address of the calling contract for which the admin role is being assigned.
     * @param _account The address of the account to assign the admin role.
     * @return bytes32 The ID of the assigned admin role.
     */
    function grantCallingContractRole(address _callingContract, address _account) external returns (bytes32);
}
