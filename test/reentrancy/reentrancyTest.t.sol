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
        uint256[] memory instructionSet = new uint256[](11);
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
        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[1].typeSpecificIndex = 1;

        rule.effectPlaceHolders = new Placeholder[](3);
        rule.effectPlaceHolders[0].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[0].typeSpecificIndex = 1;
        rule.effectPlaceHolders[1].pType = ParamTypes.ADDR;
        rule.effectPlaceHolders[1].typeSpecificIndex = 0;
        rule.effectPlaceHolders[2].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[2].flags = FLAG_TRACKER_VALUE;
        rule.effectPlaceHolders[2].typeSpecificIndex = 1;

        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule);

        Trackers memory tracker1;
        tracker1.pType = ParamTypes.UINT;
        tracker1.trackerValue = abi.encode(0);
        tracker1.mapped = false;
        tracker1.set = true;

        // Create a tracker for the rule
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker1, "totalVolume");      
        ForeignCallEncodedIndex[] memory encodedIndices = new ForeignCallEncodedIndex[](2);
        encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        encodedIndices[0].index = 0;
        encodedIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
        encodedIndices[1].index = 1;

        ForeignCall memory fc;
        fc.encodedIndices = encodedIndices;
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

    function _mimickReentrancyMultiplePolicies() internal {
        uint256[] memory policyIds = new uint256[](2);
        // blank slate policy
        vm.startPrank(policyAdmin);
        policyIds[0] = _createBlankPolicy();
        policyIds[1] = _createBlankPolicy();

        RulesEngineComponentFacet(address(red)).addClosedPolicySubscriber(policyIds[0], policyAdmin); 
        RulesEngineComponentFacet(address(red)).addClosedPolicySubscriber(policyIds[1], policyAdmin); 
        vm.stopPrank();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        uint256 callingFunctionId1 = _addCallingFunctionToPolicy(policyIds[0]);
        uint256 callingFunctionId2 = _addCallingFunctionToPolicy(policyIds[1]);
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        rule.posEffects = new Effect[](1);
        rule.posEffects[0].instructionSet = _createTrackerUpdateInstructionSet();
        rule.posEffects[0].effectType = EffectTypes.EXPRESSION;

        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[1].typeSpecificIndex = 1;

        rule.effectPlaceHolders = new Placeholder[](3);
        rule.effectPlaceHolders[0].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[0].typeSpecificIndex = 1;
        rule.effectPlaceHolders[1].pType = ParamTypes.ADDR;
        rule.effectPlaceHolders[1].typeSpecificIndex = 0;
        rule.effectPlaceHolders[2].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[2].flags = FLAG_TRACKER_VALUE;
        rule.effectPlaceHolders[2].typeSpecificIndex = 1;

        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule);
        uint256 ruleId2 = RulesEngineRuleFacet(address(red)).createRule(policyIds[1], rule);

        Trackers memory tracker1;
        tracker1.pType = ParamTypes.UINT;
        tracker1.trackerValue = abi.encode(0);
        tracker1.mapped = false;
        tracker1.set = true;

        // Create a tracker for the rule
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker1, "totalVolume");      
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[1], tracker1, "totalVolume");      
        ForeignCallEncodedIndex[] memory encodedIndices = new ForeignCallEncodedIndex[](2);
        encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        encodedIndices[0].index = 0;
        encodedIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
        encodedIndices[1].index = 1;

        ForeignCall memory fc;
        fc.encodedIndices = encodedIndices;
        fc.parameterTypes = pTypes;
        fc.foreignCallAddress = address(reentrancy);
        fc.signature = bytes4(keccak256(bytes("transfer(address,uint256)")));
        fc.returnType = ParamTypes.BOOL;
        fc.foreignCallIndex = 0;
        RulesEngineComponentFacet(address(red)).createForeignCall(policyIds[0], fc, "fcName");
        RulesEngineComponentFacet(address(red)).createForeignCall(policyIds[1], fc, "fcName");



        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        vm.startPrank(policyAdmin);
        bytes4[] memory callingFunctionsNew = new bytes4[](1);
        callingFunctionsNew[0] = bytes4(keccak256(bytes("transfer(address,uint256)")));
        uint256[] memory callingFunctionIdsNew = new uint256[](1);
        callingFunctionIdsNew[0] = callingFunctionId1;

        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[0], callingFunctionsNew, callingFunctionIdsNew, ruleIds, PolicyType.CLOSED_POLICY);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyIds[1], callingFunctionsNew, callingFunctionIdsNew, ruleIds, PolicyType.CLOSED_POLICY);
        // _addRuleIdsToPolicy(policyIds[0], ruleIds);
        // _addRuleIdsToPolicy(policyIds[1], ruleIds);
        
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

    function test_reentrancy_multiple_policies(bytes memory data, bool delegatecall) public ifDeploymentTestsEnabled endWithStopPrank {
        _mimickReentrancyMultiplePolicies();
        reentrancy.setCallData(data);
        reentrancy.setDelegatecall(delegatecall);
        vm.startPrank(user1);
        vm.expectRevert();
        erc20.transfer(address(USER_ADDRESS_2), 5);
        vm.stopPrank();
    }
}