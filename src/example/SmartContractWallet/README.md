# Rules Engine Guard for Safe Smart Accounts

This directory contains a Safe Guard implementation that integrates with the Aquifi Rules Engine to enforce compliance policies on Safe smart account transactions.

## Overview

The `RulesEngineGuard` is a Smart Contract Guard that implements the Safe Guard interface and validates transactions through the Rules Engine before they are executed. When a Safe transaction is submitted, the guard:

1. Intercepts the transaction parameters
2. Encodes them into the format expected by the Rules Engine
3. Calls the Rules Engine's `checkPolicies` function
4. Either allows the transaction to proceed or reverts if policies are violated

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Safe Smart    │    │ Rules Engine     │    │   Rules Engine  │
│   Account       │────▶│ Guard           │────▶│   Processor     │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
        │                        │                        │
        │                        │                        │
        ▼                        ▼                        ▼
   Transaction              Validation               Policy Check
   Execution                 Logic                   & Rules
```

## Key Components

### RulesEngineGuard.sol

The main guard contract that:
- Implements the Safe Guard interface (`checkTransaction` and `checkAfterExecution`)
- Validates transactions through the Rules Engine
- Provides administrative functions for configuration
- Emits events for monitoring and debugging

### Integration Points

1. **Safe Smart Account**: The guard is installed on a Safe and called before/after transaction execution
2. **Rules Engine**: The guard calls `checkPolicies(bytes calldata arguments)` to validate transactions
3. **Policy Configuration**: Policies are configured in the Rules Engine to define transaction restrictions

## Usage

### 1. Deploy the Guard

```solidity
// Deploy the guard with the Rules Engine address
RulesEngineGuard guard = new RulesEngineGuard(rulesEngineAddress);
```

### 2. Install the Guard on a Safe

```solidity
// From within the Safe or via a Safe transaction
safe.setGuard(address(guard));
```

### 3. Configure Policies

Configure policies in the Rules Engine that will be checked for transactions from the Safe address:

```solidity
// Example: Set up policies for the Safe address in the Rules Engine
// This is done through the Rules Engine's policy management functions
```

### 4. Transaction Validation

Once installed, every transaction through the Safe will:

1. Be intercepted by the guard's `checkTransaction` function
2. Have its parameters encoded and sent to the Rules Engine
3. Either proceed (if policies pass) or revert (if policies fail)

## Transaction Data Encoding

The guard encodes transaction parameters as follows:

```solidity
bytes memory transactionData = abi.encodeWithSignature(
    "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
    to,           // Destination address
    value,        // ETH value
    data,         // Transaction data
    operation,    // Call (0) or DelegateCall (1)
    safeTxGas,    // Gas for Safe transaction
    baseGas,      // Base gas costs
    gasPrice,     // Gas price
    gasToken,     // Token for gas payment (0x0 for ETH)
    refundReceiver, // Gas refund receiver
    signatures    // Transaction signatures
);
```

This encoded data is passed to `checkPolicies(transactionData)` in the Rules Engine.

## Events

The guard emits several events for monitoring:

```solidity
event RulesEngineSet(address indexed rulesEngine);
event TransactionValidated(address indexed safe, bytes32 indexed txHash, bool passed);
event PolicyCheckFailed(address indexed safe, bytes32 indexed txHash, string reason);
```

## Error Handling

The guard defines custom errors for different failure scenarios:

```solidity
error RulesEngineNotSet();
error PolicyViolation(string reason);
error ZeroAddress();
error OnlyOwner();
```

## Administrative Functions

### Update Rules Engine

```solidity
guard.setRulesEngine(newRulesEngineAddress);
```

### Transfer Ownership

```solidity
guard.transferOwnership(newOwner);
```

### Check Configuration

```solidity
bool configured = guard.isConfigured();
address rulesEngine = guard.getRulesEngine();
address owner = guard.getOwner();
```

## Testing

Run the comprehensive test suite:

```bash
forge test --match-contract RulesEngineGuardTest
```

The test suite includes:
- Constructor validation
- Transaction validation scenarios
- Policy violation handling
- Administrative function testing
- Integration tests with mock Safe
- Fuzz testing for different transaction parameters

## Integration Example

Here's a complete example of setting up a Safe with the Rules Engine Guard:

```solidity
// 1. Deploy Rules Engine (assumed to be already deployed)
address rulesEngineAddress = 0x...; // Your Rules Engine address

// 2. Deploy the Guard
RulesEngineGuard guard = new RulesEngineGuard(rulesEngineAddress);

// 3. Deploy or connect to existing Safe
Safe safe = Safe(safeAddress);

// 4. Set the guard on the Safe (requires Safe owner signature)
bytes memory setGuardData = abi.encodeWithSignature(
    "setGuard(address)", 
    address(guard)
);

// Execute transaction to set guard
safe.execTransaction(
    address(safe),  // to
    0,              // value
    setGuardData,   // data
    Enum.Operation.Call, // operation
    0,              // safeTxGas
    0,              // baseGas
    0,              // gasPrice
    address(0),     // gasToken
    payable(0),     // refundReceiver
    signatures      // signatures from Safe owners
);

// 5. Configure policies in Rules Engine for the Safe address
// (This step depends on your Rules Engine's policy management interface)
```

## Security Considerations

1. **Guard Ownership**: Only trusted parties should own the guard contract
2. **Rules Engine Trust**: The guard trusts the configured Rules Engine completely
3. **Policy Configuration**: Ensure policies are properly configured to avoid blocking legitimate transactions
4. **Upgrade Path**: Consider implementing upgrade mechanisms for the guard if needed

## Production Deployment

For production deployment:

1. **Use Real Safe Contracts**: Import actual Safe contracts instead of mock interfaces
2. **Audit**: Thoroughly audit both the guard and its integration with your Rules Engine
3. **Testing**: Test extensively on testnets before mainnet deployment
4. **Monitor**: Set up monitoring for guard events and policy violations
5. **Backup**: Ensure Safe owners can disable the guard if needed

## Limitations

- The guard currently encodes all transaction parameters - consider optimizing for gas if needed
- Error messages from the Rules Engine are passed through but may be truncated
- The guard adds gas overhead to every Safe transaction

## Support

For questions or issues with the Rules Engine Guard:
1. Review the test suite for usage examples
2. Check event logs for debugging information
3. Ensure proper policy configuration in the Rules Engine
4. Verify the guard is correctly installed on the Safe 