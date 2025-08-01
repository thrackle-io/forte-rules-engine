/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract storageTest is RulesEngineCommon {
    /**
     * Storage tests for policies within the rules engine
     */

    function testPolicyStorageFuzz(uint16 total) public {
        uint256 index = bound(uint256(total), 0, 3000);
        for (uint256 i = 0; i < index; i++) {
            uint256 policyId = _createBlankPolicy();
            PolicyMetadata memory metadata2 = RulesEnginePolicyFacet(address(red)).getPolicyMetadata(policyId);
            assertEq(policyName, metadata2.policyName);
        }
    }

    function testRuleStorageFuzz(uint16 total) public {
        uint256 index = bound(uint256(total), 0, 2000);
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        uint256 ruleId;
        for (uint256 i = 0; i < index; i++) {
            // Save the rule
            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);
            RuleMetadata memory metadata2 = RulesEngineRuleFacet(address(red)).getRuleMetadata(policyId, ruleId);
            assertEq(ruleName, metadata2.ruleName);
        }
    }

    function testRuleAssociationStorageFuzz(uint16 total) public {
        uint256 index = bound(uint256(total), 0, 1000);
        uint256 policyId = _createBlankPolicy();
        Rule memory rule;
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, 4, LogicalOp.GT, 0, 1
        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = _createInstructionSet(4);
        // Build the calling function argument placeholder
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;

        ruleIds.push(new uint256[](1));
        uint256 ruleId;
        for (uint256 i = 0; i < index; i++) {
            // Save the rule
            ruleId = RulesEngineRuleFacet(address(red)).createRule(policyId, rule, ruleName, ruleDescription);
            ruleIds[0].push(ruleId);
            RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyId,
                callingFunctions,
                callingFunctionIds,
                ruleIds,
                PolicyType.CLOSED_POLICY,
                policyName,
                policyDescription
            );
        }
    }

    function testCallingFunctionAssociationStorage(uint16 total) public {
        uint256 index = bound(uint256(total), 0, 500);
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        uint256 callingFunctionId;
        for (uint256 i = 0; i < index; i++) {
            // Save the calling function
            callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
                policyIds[0],
                bytes4(bytes4(keccak256(bytes(callingFunction)))),
                pTypes,
                callingFunction,
                ""
            );
            // Save the Policy
            callingFunctions.push(bytes4(keccak256(bytes(callingFunction))));
            callingFunctionIds.push(callingFunctionId);
            uint256[][] memory blankRuleIds = new uint256[][](0);
            RulesEnginePolicyFacet(address(red)).updatePolicy(
                policyIds[0],
                callingFunctions,
                callingFunctionIds,
                blankRuleIds,
                PolicyType.CLOSED_POLICY,
                policyName,
                policyDescription
            );
        }
    }

    function testCallingFunctionStorage(uint16 total) public {
        uint256 index = bound(uint256(total), 0, 1000);
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        uint256 callingFunctionId;
        for (uint256 i = 0; i < index; i++) {
            // Save the calling function
            callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
                policyIds[0],
                bytes4(bytes4(keccak256(bytes(callingFunction)))),
                pTypes,
                callingFunction,
                ""
            );
        }
    }
}
