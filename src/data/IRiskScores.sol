// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.17;

import "./IDataModule.sol";

/**
 * @title Risk Scores interface Contract
 * @notice Data interface to store risk scores for user accounts
 * @dev This interface contains storage and retrieval function definitions
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett
 */
interface IRiskScores is IDataModule {
    /**
     * @dev Add the risk score to the account. Restricted to the owner
     * @param _address address of the account
     * @param _score risk score (0-100)
     */
    function addScore(address _address, uint8 _score) external;

    /**
     * @dev Remove the risk score for the account. Restricted to the owner
     * @param _account address of the account
     */
    function removeScore(address _account) external;

    /**
     * @dev Get the risk score for the account. Restricted to the owner
     * @param _account address of the account
     */
    function getRiskScore(address _account) external view returns (uint8);
}
