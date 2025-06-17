pragma solidity ^0.8.0;

import {RulesEngine7702ExampleWallet} from "src/example/SmartContractWallet/RulesEngine7702ExampleWallet.sol";
import {RulesEngineClient} from "src/client/RulesEngineClient.sol";
import {RulesEngineCommon} from "test/utils/RulesEngineCommon.t.sol";
import {RulesEnginePolicyFacet} from "src/engine/facets/RulesEnginePolicyFacet.sol";
import {RulesEngineRuleFacet} from "src/engine/facets/RulesEngineRuleFacet.sol";
import {PolicyType, ParamTypes, Rule, Effect, Placeholder} from "src/engine/RulesEngineStorageStructure.sol";
import "forge-std/src/Test.sol";

import {ERC20} from "@openzeppelin/token/ERC20/ERC20.sol";

contract TestERC20 is ERC20 {
    constructor() ERC20("Test Token", "TT") {}

    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}

contract EIP7702WalletTest is Test, RulesEngineCommon {
    RulesEngine7702ExampleWallet public wallet;
    Vm.Wallet public owner;
    Vm.Wallet public some_dude;
    TestERC20 public token;

    modifier someDudeBroadcasting() {
        vm.broadcast(some_dude.addr);
        _;
    }

    function setUp() public {
        token = new TestERC20();

        red = createRulesEngineDiamond(address(0xB0b));

        owner = vm.createWallet(uint256(keccak256("owner")));
        some_dude = vm.createWallet(uint256(keccak256("some_dude")));

        vm.startPrank(owner.addr);
        wallet = new RulesEngine7702ExampleWallet(address(red));
        vm.stopPrank();

        vm.signAndAttachDelegation(address(wallet), owner.privateKey);
        vm.startBroadcast(some_dude.addr);
        RulesEngineClient(owner.addr).setRulesEngineAddress(address(red));
        RulesEngine7702ExampleWallet(owner.addr).setCallingContractAdmin(owner.addr);
        bytes memory code = address(owner.addr).code;
        require(code.length > 0, "Owner has no code");
        require(RulesEngine7702ExampleWallet(owner.addr).rulesEngineAddress() == address(red), "Rules Engine address not set");
        vm.stopBroadcast();
    }

    function _setupRuleWithoutForeignCallOn7702Wallet() internal ifDeploymentTestsEnabled endWithStopPrank {
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
        RulesEnginePolicyFacet(address(red)).applyPolicy(owner.addr, policyIds);
    }

    function testSimpleExecuteTransaction() public someDudeBroadcasting {
        RulesEngine7702ExampleWallet.Call[] memory calls = new RulesEngine7702ExampleWallet.Call[](1);

        calls[0] = RulesEngine7702ExampleWallet.Call({
            to: address(token),
            value: 0,
            data: abi.encodeWithSelector(TestERC20.mint.selector, owner.addr, 1000)
        });
        
        RulesEngine7702ExampleWallet(owner.addr).executeTransaction(calls);

        assertEq(token.balanceOf(owner.addr), 1000);
    }

    function testSimpleExecuteTransactionWithRevert() public someDudeBroadcasting {
        RulesEngine7702ExampleWallet.Call[] memory calls = new RulesEngine7702ExampleWallet.Call[](1);

        calls[0] = RulesEngine7702ExampleWallet.Call({
            to: address(token),
            value: 0,
            data: abi.encodeWithSelector(TestERC20.mint.selector, owner.addr, 1000)
        });

        RulesEngine7702ExampleWallet(owner.addr).executeTransaction(calls);

        assertEq(token.balanceOf(owner.addr), 1000);


        _setupRuleWithoutForeignCallOn7702Wallet();

        calls[0] = RulesEngine7702ExampleWallet.Call({
            to: address(token),
            value: 0,
            data: abi.encodeWithSelector(ERC20.transfer.selector, owner.addr, 3)
        });

        vm.expectRevert();
        RulesEngine7702ExampleWallet(owner.addr).executeTransaction(calls);

    }
}