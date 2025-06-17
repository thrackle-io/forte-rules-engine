// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/example/SmartContractWallet/RulesEngineGuard.sol";
import "src/example/SmartContractWallet/SafeGuardHelper.sol";
import "test/utils/RulesEngineCommon.t.sol";

import "safe-smart-account/proxies/SafeProxyFactory.sol";

import "@openzeppelin/token/ERC20/ERC20.sol";



contract TestERC20 is ERC20 {
    constructor() ERC20("Test Token", "TT") {}

    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}

/**
 * @title Rules Engine Guard Test Suite
 * @dev Comprehensive tests for the Rules Engine Guard implementation
 */
contract RulesEngineGuardTest is SafeGuardTestHelper, RulesEngineCommon {
    
    // ====================================
    // Test Contracts and Variables
    // ====================================
    

    Safe public safe;
    SafeProxyFactory public safeProxyFactory;
    address public guardContract;
    RulesEngineGuard public guard;
    address public safeAddress;
    address public safeProxyAddress;
    address public guardAddress;


    address[] public owners;
    Vm.Wallet public owner;
    Vm.Wallet public delegate;

    TestERC20 public token;
    
    // Test transaction parameters
    address public constant TEST_TO = address(0x123);
    uint256 public constant TEST_VALUE = 1 ether;
    bytes public constant TEST_DATA = "0x1234";
    Enum.Operation public constant TEST_OPERATION = Enum.Operation.Call;
    uint256 public constant TEST_SAFE_TX_GAS = 100000;
    uint256 public constant TEST_BASE_GAS = 21000;
    uint256 public constant TEST_GAS_PRICE = 20 gwei;
    address public constant TEST_GAS_TOKEN = address(0);
    address payable public constant TEST_REFUND_RECEIVER = payable(address(0));
    bytes public constant TEST_SIGNATURES = "0x5678";
    
    // ====================================
    // Events
    // ====================================
    
    event RulesEngineSet(address indexed rulesEngine);
    event TransactionValidated(address indexed safe, bytes32 indexed txHash, bool passed);
    event PolicyCheckFailed(address indexed safe, bytes32 indexed txHash, string reason);
    
    // ====================================
    // Setup
    // ====================================
    
    function setUp() public {
        owner = vm.createWallet(uint256(keccak256("owner")));
        delegate = vm.createWallet(uint256(keccak256("delegate")));

        owners.push(owner.addr);
    

        bytes memory initData = abi.encodeWithSelector(Safe.setup.selector, owners, 1, address(0x0), "", address(0x0), address(0x0), 0, payable(address(0x0)));

        safeProxyFactory = new SafeProxyFactory();
        safe = new Safe();
        safeAddress = address(safe);
        SafeProxy safeProxy = safeProxyFactory.createProxyWithNonce(address(safe), initData, uint256(0));
        safe = Safe(payable(address(safeProxy)));
        safeProxyAddress = address(safeProxy);
        
        // Deploy the guard
        red = createRulesEngineDiamond(address(0xB0b)); 
        vm.startPrank(owner.addr);
        guard = new RulesEngineGuard(address(red));
        guardAddress = address(guard);
        vm.stopPrank();

    

        bytes memory guardData = abi.encodeCall(GuardManager.setGuard, (address(guard)));
        execTransactionWithSafe(
            {
                to: address(safe),
                value: 0,
                data: guardData
            }
        );

        RulesEngineClient(address(guard)).setCallingContractAdmin(address(owner.addr));

        token = new TestERC20();

        token.mint(safeAddress, 100000);

        vm.prank(safeAddress);
        token.approve(safeAddress, 100000);
        
    }

    function execTransactionWithSafe(address to, uint256 value, bytes memory data) internal {

        uint256 nonce = safe.nonce();

        bytes32 txHash = safe.getTransactionHash({
            to: to,
            value: value,
            data: data,
            operation: Enum.Operation.Call,
            safeTxGas: TEST_SAFE_TX_GAS,
            baseGas: TEST_BASE_GAS,
            gasPrice: TEST_GAS_PRICE,
            gasToken: address(0),
            refundReceiver: address(0),
            _nonce: nonce
        });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.privateKey, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        safe.execTransaction(
            {
                to: to,
                value: value,
                data: data,
                operation: Enum.Operation.Call,
                safeTxGas: TEST_SAFE_TX_GAS,
                baseGas: TEST_BASE_GAS,
                gasPrice: TEST_GAS_PRICE,
                gasToken: address(0),
                refundReceiver: payable(address(0)),
                signatures: signature
            }
        );
    }

    function getTransactionToExecuteExpectRevert(address to, uint256 value, bytes memory data) internal returns (bytes memory) {
        uint256 nonce = safe.nonce();

        bytes32 txHash = safe.getTransactionHash({
            to: to,
            value: value,
            data: data,
            operation: Enum.Operation.Call,
            safeTxGas: TEST_SAFE_TX_GAS,
            baseGas: TEST_BASE_GAS,
            gasPrice: TEST_GAS_PRICE,
            gasToken: address(0),
            refundReceiver: address(0),
            _nonce: nonce
        });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(owner.privateKey, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        vm.expectRevert();
        safe.execTransaction(
            {
                to: to,
                value: value,
                data: data,
                operation: Enum.Operation.Call,
                safeTxGas: TEST_SAFE_TX_GAS,
                baseGas: TEST_BASE_GAS,
                gasPrice: TEST_GAS_PRICE,
                gasToken: address(0),
                refundReceiver: payable(address(0)),
                signatures: signature
            }
        );
    }

    function setupRuleWithoutForeignCallOnSafe() internal ifDeploymentTestsEnabled endWithStopPrank {
        // Initial setup for what we'll need later
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        vm.startPrank(policyAdmin);
        policyIds[0] = RulesEnginePolicyFacet(address(red)).createPolicy(PolicyType.OPEN_POLICY);
        vm.stopPrank();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;

        vm.startPrank(callingContractAdmin);
        _addCallingFunctionToPolicy(policyIds[0]);
        vm.stopPrank();
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = _createEffectRevert("Amount is less than 4");

        // Save the rule
        vm.startPrank(policyAdmin);
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).openPolicy(policyIds[0]);
        vm.stopPrank();
        
        vm.startPrank(owner.addr);
        // Apply the policy 
        RulesEnginePolicyFacet(address(red)).applyPolicy(guardAddress, policyIds);
    }
    
    // ====================================
    // Constructor Tests
    // ====================================
    
    function test_Constructor_Success() public {
        assertEq(guard.rulesEngineAddress(), address(red));
        assertEq(guard.owner(), address(owner.addr));
        assertTrue(guard.isConfigured());
    }
    
    function test_Constructor_ZeroAddress_Reverts() public {
        vm.expectRevert(RulesEngineGuard.ZeroAddress.selector);
        new RulesEngineGuard(address(0));
    }
    
    // ====================================
    // checkTransaction Tests
    // ====================================
    
    function test_guardFailsWhenInstructionFails() public {
        setupRuleWithoutForeignCallOnSafe();

        bytes memory data = abi.encodeWithSelector(
            ERC20.transfer.selector,
            TEST_TO,
            3 // less than 4 therefore should revert
        );

        getTransactionToExecuteExpectRevert(TEST_TO, 0, data);
        // vm.expectRevert();
        // execTransactionWithSafe(
        //     {
        //         to: address(token),
        //         value: 0,
        //         data: data
        //     }
        // );
        
    }
    
    // function test_CheckTransaction_PolicyViolation_Reverts() public {
    //     // Set up mock to return failure (0)
    //     mockRulesEngine.setReturnValue(0);
        
    //     vm.expectRevert(abi.encodeWithSelector(
    //         RulesEngineGuard.PolicyViolation.selector,
    //         "Transaction violates configured policies"
    //     ));
        
    //     guard.checkTransaction(
    //         TEST_TO,
    //         TEST_VALUE,
    //         TEST_DATA,
    //         TEST_OPERATION,
    //         TEST_SAFE_TX_GAS,
    //         TEST_BASE_GAS,
    //         TEST_GAS_PRICE,
    //         TEST_GAS_TOKEN,
    //         TEST_REFUND_RECEIVER,
    //         TEST_SIGNATURES,
    //         address(this)
    //     );
    // }
    
    // function test_CheckTransaction_RulesEngineRevert_Reverts() public {
    //     // Set up mock to revert with custom message
    //     mockRulesEngine.setShouldRevert(true);
    //     mockRulesEngine.setRevertMessage("Custom revert message");
        
    //     vm.expectRevert(abi.encodeWithSelector(
    //         RulesEngineGuard.PolicyViolation.selector,
    //         "Custom revert message"
    //     ));
        
    //     guard.checkTransaction(
    //         TEST_TO,
    //         TEST_VALUE,
    //         TEST_DATA,
    //         TEST_OPERATION,
    //         TEST_SAFE_TX_GAS,
    //         TEST_BASE_GAS,
    //         TEST_GAS_PRICE,
    //         TEST_GAS_TOKEN,
    //         TEST_REFUND_RECEIVER,
    //         TEST_SIGNATURES,
    //         address(this)
    //     );
    // }
    
    // function test_CheckTransaction_RulesEngineNotSet_Reverts() public {
    //     // Deploy guard with zero address (this will fail)
    //     // Instead, let's deploy normally and then set to zero via administrative function
    //     guard.setRulesEngine(address(1)); // Set to non-zero first
        
    //     // Now create a new guard with zero rules engine by testing the modifier
    //     MockRulesEngine zeroEngine = new MockRulesEngine();
    //     RulesEngineGuard testGuard = new RulesEngineGuard(address(zeroEngine));
        
    //     // Set to zero address by transferring ownership and updating
    //     testGuard.setRulesEngine(address(0));
        
    //     vm.expectRevert(RulesEngineGuard.RulesEngineNotSet.selector);
    //     testGuard.checkTransaction(
    //         TEST_TO,
    //         TEST_VALUE,
    //         TEST_DATA,
    //         TEST_OPERATION,
    //         TEST_SAFE_TX_GAS,
    //         TEST_BASE_GAS,
    //         TEST_GAS_PRICE,
    //         TEST_GAS_TOKEN,
    //         TEST_REFUND_RECEIVER,
    //         TEST_SIGNATURES,
    //         address(this)
    //     );
    // }
    
    // function test_CheckTransaction_EncodesDataCorrectly() public {
    //     mockRulesEngine.setReturnValue(1);
        
    //     // Call checkTransaction and verify the encoded data was passed correctly
    //     guard.checkTransaction(
    //         TEST_TO,
    //         TEST_VALUE,
    //         TEST_DATA,
    //         TEST_OPERATION,
    //         TEST_SAFE_TX_GAS,
    //         TEST_BASE_GAS,
    //         TEST_GAS_PRICE,
    //         TEST_GAS_TOKEN,
    //         TEST_REFUND_RECEIVER,
    //         TEST_SIGNATURES,
    //         address(this)
    //     );
        
    //     // Verify the mock received the correct encoded data
    //     bytes memory expectedData = abi.encodeWithSignature(
    //         "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
    //         TEST_TO,
    //         TEST_VALUE,
    //         TEST_DATA,
    //         TEST_OPERATION,
    //         TEST_SAFE_TX_GAS,
    //         TEST_BASE_GAS,
    //         TEST_GAS_PRICE,
    //         TEST_GAS_TOKEN,
    //         TEST_REFUND_RECEIVER,
    //         TEST_SIGNATURES
    //     );
        
    //     assertEq(mockRulesEngine.lastCallData(), expectedData);
    // }
    
    // // ====================================
    // // checkAfterExecution Tests
    // // ====================================
    
    // function test_CheckAfterExecution_Success() public {
    //     bytes32 testTxHash = keccak256("test_transaction");
        
    //     vm.expectEmit(true, true, false, true);
    //     emit TransactionValidated(address(this), testTxHash, true);
        
    //     guard.checkAfterExecution(testTxHash, true);
    // }
    
    // function test_CheckAfterExecution_Failure() public {
    //     bytes32 testTxHash = keccak256("test_transaction");
        
    //     vm.expectEmit(true, true, false, true);
    //     emit TransactionValidated(address(this), testTxHash, false);
        
    //     guard.checkAfterExecution(testTxHash, false);
    // }
    
    // // ====================================
    // // Administrative Function Tests
    // // ====================================
    
    // function test_SetRulesEngine_Success() public {
    //     address newRulesEngine = makeAddr("newRulesEngine");
        
    //     vm.expectEmit(true, false, false, true);
    //     emit RulesEngineSet(newRulesEngine);
        
    //     guard.setRulesEngine(newRulesEngine);
        
    //     assertEq(guard.rulesEngine(), newRulesEngine);
    // }
    
    // function test_SetRulesEngine_ZeroAddress_Reverts() public {
    //     vm.expectRevert(RulesEngineGuard.ZeroAddress.selector);
    //     guard.setRulesEngine(address(0));
    // }
    
    // function test_SetRulesEngine_OnlyOwner() public {
    //     address newRulesEngine = makeAddr("newRulesEngine");
        
    //     vm.prank(user1);
    //     vm.expectRevert(RulesEngineGuard.OnlyOwner.selector);
    //     guard.setRulesEngine(newRulesEngine);
    // }
    
    // function test_TransferOwnership_Success() public {
    //     guard.transferOwnership(user1);
    //     assertEq(guard.owner(), user1);
    // }
    
    // function test_TransferOwnership_ZeroAddress_Reverts() public {
    //     vm.expectRevert(RulesEngineGuard.ZeroAddress.selector);
    //     guard.transferOwnership(address(0));
    // }
    
    // function test_TransferOwnership_OnlyOwner() public {
    //     vm.prank(user1);
    //     vm.expectRevert(RulesEngineGuard.OnlyOwner.selector);
    //     guard.transferOwnership(user2);
    // }
    
    // // ====================================
    // // View Function Tests
    // // ====================================
    
    // function test_GetRulesEngine() public {
    //     assertEq(guard.getRulesEngine(), address(mockRulesEngine));
    // }
    
    // function test_GetOwner() public {
    //     assertEq(guard.getOwner(), owner);
    // }
    
    // function test_IsConfigured() public {
    //     assertTrue(guard.isConfigured());
        
    //     guard.setRulesEngine(address(0));
    //     assertFalse(guard.isConfigured());
    // }
    
    // // ====================================
    // // Integration Tests
    // // ====================================
    
    // function test_IntegrationWithSafe() public {
    //     // Set up mock safe to call guard
    //     mockSafe.setGuard(address(guard));
    //     mockRulesEngine.setReturnValue(1);
        
    //     // Mock safe executes transaction which should call guard
    //     vm.prank(address(mockSafe));
    //     guard.checkTransaction(
    //         TEST_TO,
    //         TEST_VALUE,
    //         TEST_DATA,
    //         TEST_OPERATION,
    //         TEST_SAFE_TX_GAS,
    //         TEST_BASE_GAS,
    //         TEST_GAS_PRICE,
    //         TEST_GAS_TOKEN,
    //         TEST_REFUND_RECEIVER,
    //         TEST_SIGNATURES,
    //         address(mockSafe)
    //     );
        
    //     // Verify the transaction was validated
    //     assertTrue(mockRulesEngine.wasCalled());
    // }
    
    // // ====================================
    // // Fuzz Tests
    // // ====================================
    
    // function testFuzz_CheckTransaction_DifferentValues(
    //     address to,
    //     uint256 value,
    //     bytes memory data
    // ) public {
    //     mockRulesEngine.setReturnValue(1);
        
    //     guard.checkTransaction(
    //         to,
    //         value,
    //         data,
    //         TEST_OPERATION,
    //         TEST_SAFE_TX_GAS,
    //         TEST_BASE_GAS,
    //         TEST_GAS_PRICE,
    //         TEST_GAS_TOKEN,
    //         TEST_REFUND_RECEIVER,
    //         TEST_SIGNATURES,
    //         address(this)
    //     );
        
    //     assertTrue(mockRulesEngine.wasCalled());
    // }
}