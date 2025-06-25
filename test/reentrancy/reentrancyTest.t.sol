pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "test/clientContractExamples/ExampleReentrancy.sol";
import "src/example/ExampleERC20.sol";

import "src/client/RulesEngineClientERC20.sol";
import "@openzeppelin/token/ERC20/ERC20.sol";

contract NewExampleERC20 is ERC20, RulesEngineClientERC20 {
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {}

    function mint(address to, uint256 amount) public virtual {
        _mint(to, amount);
    }

    function transfer(address to, uint256 amount) public override checksPoliciesERC20TransferBefore(to, amount, balanceOf(msg.sender), balanceOf(to), block.timestamp) returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public override checksPoliciesERC20TransferFromBefore(from, to, amount, balanceOf(from), balanceOf(to), block.timestamp) returns (bool) {
        _transfer(from, to, amount);
        return true;
    }
}

contract ReentrancyTest is RulesEngineCommon {

    ExampleReentrancy reentrancy;
    NewExampleERC20 erc20;

    function setUp() public {
        red = createRulesEngineDiamond(address(0xB0b));
        reentrancy = new ExampleReentrancy(address(erc20), true);
        erc20 = new NewExampleERC20("Test", "TEST");
        erc20.setRulesEngineAddress(address(red));
        erc20.setCallingContractAdmin(address(policyAdmin));
        
        
        vm.startPrank(user1);
        erc20.mint(user1, 1000000000);
        vm.stopPrank();
    }

    function _createTrackerUpdateInstructionSet() internal pure returns (uint256[] memory) {
        uint256[] memory instructionSet = new uint256[](6);
        // Tracker Placeholder to increment transaction count
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = 0;
        // Tracker Index
        instructionSet[2] = uint(LogicalOp.NUM);
        instructionSet[3] = 1;
        // Tracker Value
        instructionSet[4] = uint(LogicalOp.ADD);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        instructionSet[7] = uint(LogicalOp.TRU);
        instructionSet[8] = 1;
        instructionSet[9] = 2;
        instructionSet[10] = uint(TrackerTypes.MEMORY);
        instructionSet[11] = uint(LogicalOp.PLH);
        instructionSet[12] = 1;
        instructionSet[13] = uint(LogicalOp.PLH);
        instructionSet[14] = 3;
        instructionSet[15] = uint(LogicalOp.ADD);
        instructionSet[16] = 4;
        instructionSet[17] = 5;
        instructionSet[18] = uint(LogicalOp.NUM);
        instructionSet[19] = 1;
        instructionSet[17] = uint(LogicalOp.TRUM);
        instructionSet[18] = 3;
        instructionSet[19] = 2;
        return instructionSet;
    }

    function mimickReentrancyRuleHackForeignCall() internal {
        // Initial setup for what we'll need later
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        vm.startPrank(policyAdmin);
        policyIds[0] = _createBlankPolicy();
        RulesEngineComponentFacet(address(red)).addClosedPolicySubscriber(policyIds[0], policyAdmin); 
        vm.stopPrank();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0]);
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        rule.posEffects = new Effect[](1);
        rule.posEffects[0].instructionSet = _createTrackerUpdateInstructionSet();
        rule.posEffects[0].effectType = EffectTypes.EXPRESSION;

        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[2].typeSpecificIndex = 2;

        rule.effectPlaceHolders = new Placeholder[](2);
        rule.effectPlaceHolders[0].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[0].typeSpecificIndex = 1;
        rule.effectPlaceHolders[1].pType = ParamTypes.ADDRESS;
        rule.effectPlaceHolders[1].typeSpecificIndex = 0;
        rule.effectPlaceHolders[2].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[2].flags = FLAG_TRACKER_VALUE;
        rule.effectPlaceHolders[2].typeSpecificIndex = 1;
        rule.effectPlaceHolders[3].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[3].flags = FLAG_TRACKER_VALUE;
        rule.effectPlaceHolders[3].typeSpecificIndex = 2;

        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule);

        Trackers memory tracker1;
        tracker1.pType = ParamTypes.UINT;
        tracker1.trackerValue = abi.encode(0);
        tracker1.mapped = false;
        tracker1.set = true;

        Trackers memory tracker2;
        tracker2.pType = ParamTypes.UINT;
        tracker2.trackerValue = abi.encode(0);
        tracker2.mapped = true;
        tracker2.trackerKeyType = ParamTypes.ADDR;
        tracker2.set = true;

        // Create a tracker for the rule
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker1, "totalVolume");      
        int8[] memory typeSpecificIndices = new int8[](2);
        typeSpecificIndices[0] = 0;
        typeSpecificIndices[1] = 1;

        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = pTypes;
        fc.foreignCallAddress = address(reentrancy);
        fc.signature = bytes4(keccak256(bytes("transfer(address,uint256)")));
        fc.returnType = ParamTypes.BOOL;
        fc.foreignCallIndex = 0;
        RulesEngineComponentFacet(address(red)).createForeignCall(policyIds[0], fc, "fcName");



        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        vm.startPrank(policyAdmin);
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(erc20), policyIds);
        vm.stopPrank();
    }

    function test_reentrancy_rule_hack_foreign_call() public ifDeploymentTestsEnabled endWithStopPrank {
        mimickReentrancyRuleHackForeignCall();
        vm.startPrank(user1);
        vm.expectRevert();
        erc20.transfer(address(USER_ADDRESS_2), 5);
        vm.stopPrank();
    }

    function test_reentrancy_rule_foreign_call_try_modify_tracker_with_delegatecall() public ifDeploymentTestsEnabled endWithStopPrank {
        mimickReentrancyRuleHackForeignCall();
        reentrancy.setCallData(abi.encode(address(USER_ADDRESS_2), 5));
        reentrancy.setDelegatecall(true);
        vm.startPrank(user1);
        vm.expectRevert();
        erc20.transfer(address(USER_ADDRESS_2), 5);
        vm.stopPrank();
    }

    function test_reentrancy_fuzz_reentrancy_contract(bytes memory data, bool delegatecall) public ifDeploymentTestsEnabled endWithStopPrank {
        mimickReentrancyRuleHackForeignCall();
        reentrancy.setCallData(data);
        reentrancy.setDelegatecall(delegatecall);
        vm.startPrank(user1);
        vm.expectRevert();
        erc20.transfer(address(USER_ADDRESS_2), 5);
        vm.stopPrank();
    }

    function test_reentrancy_fuzz_storage_reads_and_writes(bytes memory data, bool delegatecall) public ifDeploymentTestsEnabled endWithStopPrank {
        mimickReentrancyRuleHackForeignCall();
        reentrancy.setCallData(data);
        reentrancy.setDelegatecall(delegatecall);
        vm.startPrank(user1);
        erc20.transfer(address(USER_ADDRESS_2), 5);
        vm.stopPrank();
    }
}