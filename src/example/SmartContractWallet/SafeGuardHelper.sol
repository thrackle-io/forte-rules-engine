// SPDX-License-Identifier: Unlicensed
pragma solidity ^0.8.24;

import "safe-smart-account/base/GuardManager.sol";
import "safe-smart-account/Safe.sol";
import "forge-std/src/Script.sol";

contract SafeGuardTestHelper is Script {
    
    /**
     * @dev Simplest way to add a guard to a Safe in tests
     * @param safe The Safe instance
     * @param guard Address of the guard contract
     * @param owners Array of owner private keys or addresses
     */
    function addGuardToSafe(
        Safe safe,
        address guard,
        address[] memory owners
    ) internal {
        // Encode the setGuard call
        bytes memory guardData = abi.encodeCall(GuardManager.setGuard, (guard));
        
        // Execute the transaction to set the guard
        executeSafeTransaction(
            safe,
            address(safe),  // target: the Safe itself
            0,              // value: 0 ETH
            guardData,      // data: setGuard call
            owners          // signers
        );
    }
    
    /**
     * @dev Helper to execute Safe transactions with proper signatures
     */
    function executeSafeTransaction(
        Safe safe,
        address to,
        uint256 value,
        bytes memory data,
        address[] memory signers
    ) internal {
        uint256 nonce = safe.nonce();
        
        // Get transaction hash
        bytes32 txHash = safe.getTransactionHash(
            to,
            value,
            data,
            Enum.Operation.Call,  // operation
            0,                    // safeTxGas
            0,                    // baseGas
            0,                    // gasPrice
            address(0),           // gasToken
            payable(address(0)),  // refundReceiver
            nonce
        );
        
        // Generate signatures (sorted by signer address)
        bytes memory signatures = generateSignatures(txHash, signers);
        
        // Execute the transaction
        safe.execTransaction(
            to,
            value,
            data,
            Enum.Operation.Call,
            0,                    // safeTxGas
            0,                    // baseGas
            0,                    // gasPrice
            address(0),           // gasToken
            payable(address(0)),  // refundReceiver
            signatures
        );
    }
    
    /**
     * @dev Generate sorted signatures for Safe transaction
     */
    function generateSignatures(
        bytes32 txHash,
        address[] memory signers
    ) internal pure returns (bytes memory) {
        // Sort signers by address (required by Safe)
        for (uint i = 0; i < signers.length - 1; i++) {
            for (uint j = i + 1; j < signers.length; j++) {
                if (signers[i] > signers[j]) {
                    address temp = signers[i];
                    signers[i] = signers[j];
                    signers[j] = temp;
                }
            }
        }
        
        bytes memory signatures;
        for (uint i = 0; i < signers.length; i++) {
            // In tests, you can use vm.sign() if you have private keys
            // For simplicity, this assumes you're using addresses directly
            // and implementing the signature logic based on your test setup
            
            // This is a simplified version - you'll need to implement
            // actual signature generation based on your test framework
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(
                1, // private key (you'll use actual private keys)
                txHash
            );
            
            signatures = abi.encodePacked(signatures, r, s, v);
        }
        
        return signatures;
    }
}