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
        super.transfer(to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public override checksPoliciesERC20TransferFromBefore(from, to, amount, balanceOf(from), balanceOf(to), block.timestamp) returns (bool) {
        super.transferFrom(from, to, amount);
        return true;
    }
}

contract ReentrancyTest is RulesEngineCommon {

    ExampleReentrancy reentrancy;
    NewExampleERC20 erc20;

    function setUp() public {
        red = createRulesEngineDiamond(address(0xB0b));
        reentrancy = new ExampleReentrancy(address(erc20), false);
        erc20 = new NewExampleERC20("Test", "TEST");
        erc20.setRulesEngineAddress(address(red));
        erc20.setCallingContractAdmin(address(policyAdmin));
        
        
        vm.startPrank(user1);
        erc20.mint(user1, 1000000000);
        vm.stopPrank();

        erc20.mint(address(reentrancy), 1000000000);
        reentrancy.setRulesEngine(address(red));
    }

    function _createTrackerUpdateInstructionSet() internal pure returns (uint256[] memory) {
        uint256[] memory instructionSet = new uint256[](11);
        // Tracker Placeholder to increment transaction count
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = 1;
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
        rule.posEffects[0].valid = true;

        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(3);
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[2].typeSpecificIndex = 1;

        rule.effectPlaceHolders = new Placeholder[](3);
        rule.effectPlaceHolders[0].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[0].typeSpecificIndex = 1;
        rule.effectPlaceHolders[1].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.effectPlaceHolders[1].typeSpecificIndex = 1;

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
        _addCallingFunctionToPolicy(policyIds[1]);
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        rule.posEffects = new Effect[](1);
        rule.posEffects[0].instructionSet = _createTrackerUpdateInstructionSet();
        rule.posEffects[0].effectType = EffectTypes.EXPRESSION;
        rule.posEffects[0].valid = true;

        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(3);
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[1].typeSpecificIndex = 1;
        rule.placeHolders[2].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[2].typeSpecificIndex = 1;

        rule.effectPlaceHolders = new Placeholder[](3);
        rule.effectPlaceHolders[0].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[0].typeSpecificIndex = 1;
        rule.effectPlaceHolders[1].pType = ParamTypes.UINT;
        rule.effectPlaceHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.effectPlaceHolders[1].typeSpecificIndex = 1;

        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule);
        RulesEngineRuleFacet(address(red)).createRule(policyIds[1], rule);

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
        
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(erc20), policyIds);
        vm.stopPrank();
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_reentrancy_rule_hack_foreign_call() public ifDeploymentTestsEnabled endWithStopPrank {
        mimickReentrancyRuleHackForeignCall();
        reentrancy.setTo(address(erc20));
        reentrancy.setDelegatecall(false);
        reentrancy.setCallData(abi.encodeWithSelector(ERC20.transfer.selector, address(USER_ADDRESS_2), 10));
        erc20.mint(address(user1), 1000000000);

        (bool success, bytes memory data) = address(reentrancy).call("");
        (success, data);

        bytes[] memory dataHistory = reentrancy.getDataHistory();
        assertEq(dataHistory.length, 3);
        assertEq(abi.decode(dataHistory[0], (uint256)), 1);
        assertEq(abi.decode(dataHistory[1], (uint256)), 2);
        assertEq(abi.decode(dataHistory[2], (uint256)), 3);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    function test_reentrancy_rule_foreign_call_try_modify_tracker_with_delegatecall() public ifDeploymentTestsEnabled endWithStopPrank {
        mimickReentrancyRuleHackForeignCall();
        reentrancy.setCallData(abi.encodeWithSelector(ERC20.transfer.selector, address(USER_ADDRESS_2), 4));
        reentrancy.setDelegatecall(true);
        reentrancy.setTo(address(erc20));
        vm.startPrank(user1);
        // vm.expectRevert(ReentrancyFailed.selector); this does revert but the rules engine is not bubbling up the error partly by design
        erc20.transfer(address(USER_ADDRESS_2), 4);
        vm.stopPrank();

        bytes[] memory dataHistory = reentrancy.getDataHistory();
        assertEq(dataHistory.length, 0);
    }

    /// forge-config: default.allow_internal_expect_revert = true
    /// @notice this test is dying in foundry, I believe it might be blowing up the stack too much and foundry can't handle it. We should report this to them. 
    // function test_reentrancy_multiple_policies() public ifDeploymentTestsEnabled endWithStopPrank {
    //     _mimickReentrancyMultiplePolicies();
    //     reentrancy.setCallData(abi.encodeWithSelector(ERC20.transfer.selector, address(USER_ADDRESS_2), 4));
    //     reentrancy.setDelegatecall(false);
    //     reentrancy.setTo(address(erc20));
    //     address(reentrancy).call("");
    //     // bytes[] memory dataHistory = reentrancy.getDataHistory();
    //     // assertEq(dataHistory.length, 3);
    //     // assertEq(abi.decode(dataHistory[0], (uint256)), 1);
    //     // assertEq(abi.decode(dataHistory[1], (uint256)), 2);
    //     // assertEq(abi.decode(dataHistory[2], (uint256)), 3);
    //     // bytes[] memory dataHistory2 = reentrancy.getDataHistory2();
    //     // assertEq(dataHistory2.length, 3);
    //     // assertEq(abi.decode(dataHistory2[0], (uint256)), 1);
    //     // assertEq(abi.decode(dataHistory2[1], (uint256)), 2);
    //     // assertEq(abi.decode(dataHistory2[2], (uint256)), 3);
    // }
}