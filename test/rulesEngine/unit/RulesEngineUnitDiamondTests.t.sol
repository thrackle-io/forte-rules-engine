/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "src/utils/DiamondMine.sol";
import "forge-std/src/Test.sol";
import "src/engine/facets/NativeFacet.sol";
import "src/engine/facets/RulesEnginePolicyFacet.sol";
import "src/engine/RulesEngineStorageStructure.sol";
import "src/example/ExampleUserContract.sol";

contract RulesEngineUnitDiamondTests is DiamondMine, Test {
    
    string callingFunction = "transfer(address,uint256) returns (bool)";
    bytes4[] callingFunctions;        
    uint256[] callingFunctionIds;
    uint256[][] ruleIds;
    ExampleUserContract userContract;
    address userContractAddress; 
    address callingContractAdmin = address(0x12345);

    function setUp() public {
        red = createRulesEngineDiamond(address(0xB0b)); 
        userContract = new ExampleUserContract();
        userContractAddress = address(userContract); 
        userContract.setRulesEngineAddress(address(red));
        userContract.setCallingContractAdmin(callingContractAdmin);     
    }

    function testRulesEngine_Unit_Diamond_diamondOwner_Positive() public view {
        assertEq(NativeFacet(address(red)).owner(), OWNER);
    }

    function testRulesEngine_Unit_Diamond_ForeignCallStorage_Positive() public {
        uint256 policyId = _createBlankPolicy(); // create blank policy just to assign policyAdmin
        address _address = address(22);
        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        int8[] memory typeSpecificIndices = new int8[](1);
        typeSpecificIndices[0] = 0;
        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = _address;
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 0;
        uint256 foreignCallId = RulesEngineComponentFacet(address(red))
            .createForeignCall(
                policyId,
                fc,
                "simpleCheck(uint256)"
            );

        fc = RulesEngineComponentFacet(address(red)).getForeignCall(
            policyId,
            foreignCallId
        );
        assertEq(fc.foreignCallAddress, _address);
    }

    function testRulesEngine_Unit_Diamond_TrackerStorage_Positive() public {
        uint256 policyId = _createBlankPolicy();
        // Build the tracker
        Trackers memory tracker;
        uint256 trackerValue = 5150;

        /// build the members of the struct:
        tracker.pType = ParamTypes.UINT;
        tracker.trackerValue = abi.encode(trackerValue);
        // Add the tracker
        uint256 trackerIndex = RulesEngineComponentFacet(address(red)).createTracker(
            policyId,
            tracker,
            "trName"
        );
        assertEq(
            abi.encode(trackerValue),
            RulesEngineComponentFacet(address(red))
                .getTracker(policyId, trackerIndex)
                .trackerValue
        );
    }

    function testRulesEngine_Unit_Diamond_FunctioncallingFunctionstorage_Positive() public {
        uint256 policyId = _createBlankPolicy();
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(keccak256(bytes(callingFunction))),
            pTypes,
            "transfer(address,uint256) returns (bool)",
            "address,uint256"
        );
        CallingFunctionStorageSet memory sig = RulesEngineComponentFacet(address(red)).getCallingFunction(policyId, callingFunctionId);
        assertEq(sig.signature, bytes4(keccak256(bytes(callingFunction))));
    }

    function testRulesEngine_Unit_Diamond_RuleStorage_Positive() public {
        uint256 policyId = _createBlankPolicy();
        
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder 
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyId, 0, rule);
        RuleStorageSet memory rss = RulesEngineRuleFacet(address(red)).getRule(policyId, ruleId);
        assertEq(rss.rule.placeHolders[0].typeSpecificIndex, 1);
    }

    function testRulesEngine_Unit_Diamond_PolicyStorage_Positive() public {
        // Initial setup for what we'll need later
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        policyIds[0] = _createBlankPolicy();
        // Add the calling function to the policy
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _addCallingFunctionToPolicy(policyIds[0], bytes4(keccak256(bytes(callingFunction))), pTypes, "transfer(address,uint256) returns (bool)");
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder 
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyIds[0], 0, rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        // Apply the policy 
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        // unable to add a getter for policy because it contains a nested mapping. If the components added without reversion, it passes.
        uint256[] memory savedPolicies = RulesEnginePolicyFacet(address(red)).getAppliedPolicyIds(userContractAddress);
        assertEq(savedPolicies.length, policyIds.length);
        assertEq(savedPolicies[0], policyIds[0]);        
    }

    function _createInstructionSet(uint256 plh1) public pure returns (uint256[] memory instructionSet) {
        instructionSet = new uint256[](7);
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LogicalOp.NUM);
        instructionSet[3] = plh1;
        instructionSet[4] = uint(LogicalOp.GT);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
    }
     function _createBlankPolicy() internal returns (uint256) {
        CallingFunctionStorageSet[] memory functioncallingFunctions = new CallingFunctionStorageSet[](0); 
        Rule[] memory rules = new Rule[](0); 
        uint256 policyId = RulesEnginePolicyFacet(address(red)).createPolicy(functioncallingFunctions, rules, PolicyType.CLOSED_POLICY);
        RulesEngineComponentFacet(address(red)).addClosedPolicySubscriber(policyId, callingContractAdmin); 
        return policyId;
    }

    function _addCallingFunctionToPolicy(uint256 policyId, bytes4 _callingFunction, ParamTypes[] memory pTypes, string memory callingFunctionName) internal returns (uint256) {
        // Save the calling function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId, 
            bytes4(_callingFunction), 
            pTypes, 
            callingFunctionName,
            "");
        // Save the Policy
        callingFunctions.push(_callingFunction);
        callingFunctionIds.push(callingFunctionId);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, callingFunctions, callingFunctionIds, blankRuleIds, PolicyType.CLOSED_POLICY);
        return callingFunctionId;
    }

    function _addRuleIdsToPolicy(uint256 policyId, uint256[][] memory _ruleIds) internal {
        RulesEnginePolicyFacet(address(red)).updatePolicy(policyId, callingFunctions, callingFunctionIds, _ruleIds, PolicyType.CLOSED_POLICY);
    }
}
