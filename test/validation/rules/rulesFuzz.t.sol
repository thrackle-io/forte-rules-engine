/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract rulesFuzz is RulesEngineCommon {
    /**
     *
     *
     * Validation fuzz tests for rules within the rules engine
     *
     *
     */

    function testRulesEngine_Fuzz_createRule_InvalidInstruction(uint8 _opA, uint8 _opB) public {
        uint256 opA = uint256(_opA);
        uint256 opB = uint256(_opB);

        (uint opAElements, uint opBElements) = findArgumentSize(opA, opB);
        uint256[] memory instructionSet = buildInstructionSet(opA, opB, opAElements, opBElements, 0);

        // rule setup
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        rule.instructionSet = instructionSet;
        // test
        if (opA > opTotalSize || opB > opTotalSize) vm.expectRevert("Invalid Instruction");
        RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
    }

    function testRulesEngine_Fuzz_createRule_negInvalidInstructionSet(uint8 _opA, uint8 _opB, uint _opAElements, uint _opBElements) public {
        uint256 opA = bound(_opA, 0, opTotalSize - 1);
        uint256 opB = bound(_opB, 0, opTotalSize - 1);
        _opAElements = bound(_opAElements, 1, 4);
        _opBElements = bound(_opBElements, 1, 4);

        (uint opAElements, uint opBElements) = findArgumentSize(opA, opB);
        uint totalElements = _opAElements + _opBElements + 2; // 2 for the opA and opB themselves
        uint256[] memory instructionSet = buildInstructionSet(opA, opB, _opAElements, _opBElements, 20);

        // rule setup
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        rule.instructionSet = instructionSet;
        // test
        /// @notice we could revert for 2 reasons so we cannot check for a specific string
        /// @notice we can also run into a scenario where instruction _a_ can take 3 or 4 elements and total instructions are 4 or 5,
        /// which would match a valid case, so we have to account for that exception
        if ((opAElements != _opAElements || opBElements != _opBElements) && totalElements != opAElements + 1) vm.expectRevert();
        RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
    }

    function testRulesEngine_Fuzz_createRule_memoryOverFlow(uint8 _opA, uint8 _opB, uint8 _data) public {
        // we avoid opcode 0 as it is the only one whose element won't be checked
        uint256 opA = bound(_opA, 1, opTotalSize - 1);
        uint256 opB = bound(_opB, 1, opTotalSize - 1);

        (uint opAElements, uint opBElements) = findArgumentSize(opA, opB);
        uint256[] memory instructionSet = buildInstructionSet(opA, opB, opAElements, opBElements, _data);

        // rule setup
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        rule.instructionSet = instructionSet;
        // test
        if (_data > memorySize) vm.expectRevert("Memory Overflow");
        RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
    }

    function testRulesEngine_Fuzz_createRule_simple(uint256 _ruleValue, uint256 _transferValue) public {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"

        // _createAllEffects();
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(_ruleValue);

        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        // Save the calling function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(keccak256(bytes(callingFunction))),
            pTypes,
            callingFunction,
            ""
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            callingFunctionIds,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        vm.startPrank(userContractAddress);
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), _transferValue);
        if (_ruleValue >= _transferValue) vm.expectRevert();
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
    }

    function findArgumentSize(uint opA, uint opB) internal view returns (uint opAElements, uint opBElements) {
        opAElements = 1;
        opBElements = 1;
        if (opA >= opsSize1) opAElements = 2;
        if (opA >= opSizeUpTo2) opAElements = 3;
        if (opA >= opSizeUpTo3) opAElements = 4;
        if (opB >= opsSize1) opBElements = 2;
        if (opB >= opSizeUpTo2) opBElements = 3;
        if (opB >= opSizeUpTo3) opBElements = 4;
    }

    function buildInstructionSet(
        uint256 opA,
        uint256 opB,
        uint256 opAElements,
        uint256 opBElements,
        uint256 data
    ) internal pure returns (uint256[] memory) {
        uint totalElements = opAElements + opBElements + 2; // 2 for the opA and opB themselves
        uint256[] memory instructionSet = new uint256[](totalElements);
        instructionSet[0] = opA;
        instructionSet[1 + opAElements] = opB;
        // we fill the instructions with the data
        for (uint i = 1; i < 1 + opAElements; i++) instructionSet[i] = uint(data);
        for (uint i = 2 + opAElements; i < instructionSet.length; i++) instructionSet[i] = uint(data);
        return instructionSet;
    }
}
