// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.24;

import "safe-smart-account/libraries/Enum.sol";
import "safe-smart-account/base/GuardManager.sol";
import "src/client/RulesEngineClient.sol";
import "forge-std/src/console.sol";

/**
 * @title Rules Engine Guard for Safe Smart Account
 * @dev This contract serves as a Guard for Gnosis Safe smart accounts, integrating with the Rules Engine
 *      to enforce compliance policies before transaction execution. The guard intercepts Safe transactions
 *      and validates them against configured rules via the Rules Engine.
 * @notice This guard implements the Safe Guard interface and calls the Rules Engine's checkPolicies function
 *         to ensure all transactions comply with defined policies before execution.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */

// Mock interfaces for Safe Guard (since we don't have the actual Safe contracts as dependencies)
// In production, you would import these from @safe-global/safe-contracts

/**
 * @title Enum - Collection of enums
 * @author Richard Meissner - <richard@gnosis.pm>
 */


/**
 * @title Guard Interface
 * @dev Interface for transaction guards that can inspect and validate transactions
 */

/**
 * @title Rules Engine Interface
 * @dev Interface for interacting with the Rules Engine
 */
// interface IRulesEngine {
//     function checkPolicies(bytes calldata arguments) external returns (uint256);
// }

/**
 * @title Rules Engine Guard
 * @dev Safe Guard implementation that validates transactions through the Rules Engine
 */
contract RulesEngineGuard is BaseTransactionGuard, RulesEngineClient {
    
    // ====================================
    // Events
    // ====================================
    
    event RulesEngineSet(address indexed rulesEngine);
    event TransactionValidated(address indexed safe, bytes32 indexed txHash, bool passed);
    event PolicyCheckFailed(address indexed safe, bytes32 indexed txHash, string reason);
    
    // ====================================
    // Errors
    // ====================================
    
    error RulesEngineNotSet();
    error PolicyViolation(string reason);
    error ZeroAddress();
    error OnlyOwner();
    
    // ====================================
    // State Variables
    // ====================================
    
    /// @notice Owner of this guard contract
    address public owner;
    
    // ====================================
    // Modifiers
    // ====================================
    
    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }
    
    modifier rulesEngineConfigured() {
        if (rulesEngineAddress == address(0)) revert RulesEngineNotSet();
        _;
    }
    
    // ====================================
    // Constructor
    // ====================================
    
    /**
     * @notice Constructor to initialize the Rules Engine Guard
     * @param _rulesEngine Address of the Rules Engine contract
     */
    constructor(address _rulesEngine) {
        if (_rulesEngine == address(0)) revert ZeroAddress();
        rulesEngineAddress = _rulesEngine;
        owner = msg.sender;
        emit RulesEngineSet(_rulesEngine);
    }
    
    // ====================================
    // Guard Interface Implementation
    // ====================================
    
    /**
     * @notice Validates a Safe transaction before execution using the Rules Engine
     * @dev This function is called by the Safe before executing a transaction. It encodes
     *      the transaction parameters and calls the Rules Engine's checkPolicies function.
     * @param to Destination address of Safe transaction
     * @param value Ether value of Safe transaction
     * @param data Data payload of Safe transaction
     * @param operation Operation type of Safe transaction (Call or DelegateCall)
     * @param safeTxGas Gas that should be used for the Safe transaction
     * @param baseGas Gas costs that are independent of the transaction execution
     * @param gasPrice Gas price that should be used for the payment calculation
     * @param gasToken Token address (or 0x0 if ETH) that is used for the payment
     * @param refundReceiver Address of receiver of gas payment (or 0x0 if tx.origin)
     * @param signatures Signature data of the Safe transaction
     * @param msgSender Address that called execTransaction
     */
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    ) external override rulesEngineConfigured {
        
        // Encode the transaction data to pass to the Rules Engine
        // The Rules Engine expects: function signature (4 bytes) + arguments
        bytes memory transactionData = bytes.concat(data, abi.encode(to), abi.encode(msgSender));

        console.log("transactionData");
        console.logBytes(transactionData);
        // Call the Rules Engine to check policies
        // The calling contract (Safe) is msg.sender
        uint256 policyResult;
        try IRulesEngine(rulesEngineAddress).checkPolicies(transactionData) returns (uint256 result) {
            policyResult = result;
        } catch Error(string memory reason) {
            revert PolicyViolation(reason);
        }
    }
    
    /**
     * @notice Called after Safe transaction execution
     * @dev This function is called after the Safe transaction is executed. 
     *      Can be used for post-execution validation or logging.
     * @param txHash Hash of the executed transaction
     * @param success Whether the transaction was successful
     */
    function checkAfterExecution(bytes32 txHash, bool success) external override {
        // Post-execution logic can be implemented here if needed
        // For now, we just emit an event for logging purposes
        emit TransactionValidated(msg.sender, txHash, success);
    }
    
    // ====================================
    // Administrative Functions
    // ====================================
    
    /**
     * @notice Updates the Rules Engine address
     * @dev Only the owner can update the Rules Engine address
     * @param _rulesEngine New Rules Engine contract address
     */
    function setRulesEngine(address _rulesEngine) external onlyOwner {
        if (_rulesEngine == address(0)) revert ZeroAddress();
        rulesEngineAddress = _rulesEngine;
        emit RulesEngineSet(_rulesEngine);
    }
    
    /**
     * @notice Transfers ownership of the guard
     * @dev Only the current owner can transfer ownership
     * @param newOwner Address of the new owner
     */
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        owner = newOwner;
    }
    
    // ====================================
    // View Functions
    // ====================================
    
    /**
     * @notice Returns the current Rules Engine address
     * @return Address of the Rules Engine contract
     */
    function getRulesEngine() external view returns (address) {
        return rulesEngineAddress;
    }
    
    /**
     * @notice Returns the current owner of the guard
     * @return Address of the owner
     */
    function getOwner() external view returns (address) {
        return owner;
    }
    
    /**
     * @notice Checks if the guard is properly configured
     * @return True if Rules Engine is set, false otherwise
     */
    function isConfigured() external view returns (bool) {
        return rulesEngineAddress != address(0);
    }
} 