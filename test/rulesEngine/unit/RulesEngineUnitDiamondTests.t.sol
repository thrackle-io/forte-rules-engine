/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "src/utils/DiamondMine.sol";
import "lib/forge-std/src/Test.sol";
import "src/engine/facets/NativeFacet.sol";
import "src/engine/facets/RulesEngineDataFacet.sol";
import "src/engine/RulesEngineStorageStructure.sol";

contract RulesEngineUnitDiamondTests is DiamondMine, Test {
    
    string functionSignature = "transfer(address,uint256) returns (bool)";
    bytes4[] signatures;        
    uint256[] functionSignatureIds;
    uint256[][] ruleIds;
    address constant CONTRACT_ADDRESS = address(22);

    function setUp() public {
        red = _createRulesEngineDiamond(address(0xB0b));        
    }

    function testRulesEngine_Unit_Diamond_diamondOwner_Positive() public view {
        assertEq(NativeFacet(address(red)).owner(), OWNER);
    }

    function testRulesEngine_Unit_Diamond_ForeignCallStorage_Positive() public {
        address _address = address(22);
        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 0;
        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = _address;
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 0;
        RulesEngineDataFacet(address(red))
            .createForeignCall(
                1,
                fc
            );

        fc = RulesEngineDataFacet(address(red)).getForeignCall(
            1,
            0
        );
        assertEq(fc.foreignCallAddress, _address);
    }

    function testRulesEngine_Unit_Diamond_TrackerStorage_Positive() public {
        // Build the tracker
        Trackers memory tracker;
        uint256 trackerValue = 5150;

        /// build the members of the struct:
        tracker.pType = PT.UINT;
        tracker.trackerValue = abi.encode(trackerValue);
        // Add the tracker
        uint256 trackerIndex = RulesEngineDataFacet(address(red)).createTracker(
            1,
            tracker
        );
        assertEq(
            abi.encode(trackerValue),
            RulesEngineDataFacet(address(red))
                .getTracker(1, trackerIndex)
                .trackerValue
        );
    }

    function testRulesEngine_Unit_Diamond_FunctionSignatureStorage_Positive() public {
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        uint256 functionSignatureId = RulesEngineDataFacet(address(red)).updateFunctionSignature(0, bytes4(keccak256(bytes(functionSignature))), pTypes);
        FunctionSignatureStorageSet memory sig = RulesEngineDataFacet(address(red)).getFunctionSignature(functionSignatureId);
        assertEq(sig.signature, bytes4(keccak256(bytes(functionSignature))));
    }

    function testRulesEngine_Unit_Diamond_RuleStorage_Positive() public {
        uint256 policyId = _createBlankPolicy();
        
        Rule memory rule;
        // Instruction set: LC.PLH, 0, LC.NUM, 4, LC.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder 
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.policyId = policyId;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0,rule);
        RuleStorageSet memory rss = RulesEngineDataFacet(address(red)).getRule(ruleId);
        assertEq(rss.rule.placeHolders[0].typeSpecificIndex, 1);
    }

    function testRulesEngine_Unit_Diamond_PolicyStorage_Positive() public {
        // Initial setup for what we'll need later
        uint256[] memory policyIds = new uint256[](1);
        // blank slate policy
        policyIds[0] = _createBlankPolicy();
        // Add the function signature to the policy
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _addFunctionSignatureToPolicy(policyIds[0], bytes4(keccak256(bytes(functionSignature))), pTypes);
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Instruction set: LC.PLH, 0, LC.NUM, 4, LC.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder 
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.policyId = policyIds[0];
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0,rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        // Apply the policy 
        RulesEngineDataFacet(address(red)).applyPolicy(CONTRACT_ADDRESS, policyIds);
        // unable to add a getter for policy because it contains a nested mapping. If the components added without reversion, it passes.
        uint256[] memory savedPolicies = RulesEngineDataFacet(address(red)).getAppliedPolicyIds(CONTRACT_ADDRESS);
        assertEq(savedPolicies.length, policyIds.length);
        assertEq(savedPolicies[0], policyIds[0]);        
    }

    function _createInstructionSet(uint256 plh1) public pure returns (uint256[] memory instructionSet) {
        instructionSet = new uint256[](7);
        instructionSet[0] = uint(LC.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LC.NUM);
        instructionSet[3] = plh1;
        instructionSet[4] = uint(LC.GT);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
    }
     function _createBlankPolicy() internal returns (uint256) {
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        uint256 policyId = RulesEngineDataFacet(address(red)).createPolicy(blankSignatures, blankFunctionSignatureIds, blankRuleIds);
        return policyId;
    }

    function _addFunctionSignatureToPolicy(uint256 policyId, bytes4 _functionSignature, PT[] memory pTypes) internal returns (uint256) {
        // Save the function signature
        uint256 functionSignatureId = RulesEngineDataFacet(address(red)).updateFunctionSignature(0, bytes4(_functionSignature), pTypes);
        // Save the Policy
        signatures.push(_functionSignature);
        functionSignatureIds.push(functionSignatureId);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEngineDataFacet(address(red)).updatePolicy(policyId, signatures, functionSignatureIds, blankRuleIds);
        return functionSignatureId;
    }

    function _addRuleIdsToPolicy(uint256 policyId, uint256[][] memory _ruleIds) internal {
        RulesEngineDataFacet(address(red)).updatePolicy(policyId, signatures, functionSignatureIds, _ruleIds);
    }
}
