// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/RulesEngineAdminRolesFacet.sol";
import "src/engine/facets/RulesEngineComponentFacet.sol";
import {RulesEngineStorageLib as StorageLib} from "src/engine/facets/RulesEngineStorageLib.sol";

/**
 * @title Rules Engine Policy Facet
 * @dev This contract serves as the primary data facet for the Rules Engine rules. It is responsible for creating, updating,
 *      retrieving, and managing rules. It enforces role-based access control and ensures that only authorized
 *      users can modify or retrieve data. The contract also supports policy cementing to prevent further modifications.
 * @notice This contract is a critical component of the Rules Engine, enabling secure and flexible policy management.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract RulesEngineRuleFacet is FacetCommonImports {
    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Rule Management
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Creates a rule in storage.
     * @dev Adds a new rule to the specified policy. Only accessible by policy admins.
     * @param policyId ID of the policy the rule will be added to.
     * @param rule The rule to create.
     * @return ruleId The generated rule ID.
     */
    function createRule(uint256 policyId, Rule calldata rule) external policyAdminOnly(policyId, msg.sender) returns (uint256) {
        _validateRule(rule);
        StorageLib._notCemented(policyId);
        RuleStorage storage data = lib._getRuleStorage();
        uint256 ruleId = ++data.ruleIdCounter[policyId];
        _storeRule(data, policyId, ruleId, rule);
        data.ruleIdCounter[policyId] = ruleId;
        emit RuleCreated(policyId, ruleId);
        return ruleId;
    }

    /**
     * @notice Updates a rule in storage.
     * @dev Modifies an existing rule in the specified policy. Only accessible by policy admins.
     * @param policyId ID of the policy the rule belongs to.
     * @param ruleId The ID of the rule to update.
     * @param rule The updated rule data.
     * @return ruleId The updated rule ID.
     */
    function updateRule(
        uint256 policyId,
        uint256 ruleId,
        Rule calldata rule
    ) external policyAdminOnly(policyId, msg.sender) returns (uint256) {
        _validateRule(rule);
        StorageLib._notCemented(policyId);
        // Load the rule data from storage
        RuleStorage storage data = lib._getRuleStorage();
        _storeRule(data, policyId, ruleId, rule);
        emit RuleUpdated(policyId, ruleId);
        return ruleId;
    }

    /**
     * @notice Retrieves all rules associated with a specific policy.
     * @param policyId The ID of the policy.
     * @return rules A two-dimensional array of rules grouped by calling functions.
     */
    function getAllRules(uint256 policyId) external view returns (Rule[][] memory) {
        // Load the policy data from storage
        Policy storage data = lib._getPolicyStorage().policyStorageSets[policyId].policy;
        bytes4[] memory callingFunctions = data.callingFunctions;
        Rule[][] memory rules = new Rule[][](callingFunctions.length);
        // Data validation will always ensure callingFunctions.length will be less than MAX_LOOP
        for (uint256 i = 0; i < callingFunctions.length; i++) {
            uint256[] memory ruleIds = data.callingFunctionsToRuleIds[callingFunctions[i]];
            rules[i] = new Rule[](ruleIds.length);
            // Data validation will always ensure ruleIds.length will be less than MAX_LOOP
            for (uint256 j = 0; j < ruleIds.length; j++) {
                if (lib._getRuleStorage().ruleStorageSets[policyId][ruleIds[j]].set) {
                    rules[i][j] = lib._getRuleStorage().ruleStorageSets[policyId][ruleIds[j]].rule;
                }
            }
        }
        return rules;
    }

    /**
     * @notice Deletes a rule from storage.
     * @param policyId The ID of the policy the rule belongs to.
     * @param ruleId The ID of the rule to delete.
     */
    function deleteRule(uint256 policyId, uint256 ruleId) public policyAdminOnly(policyId, msg.sender) {
        StorageLib._notCemented(policyId);
        delete lib._getRuleStorage().ruleStorageSets[policyId][ruleId];
        emit RuleDeleted(policyId, ruleId);
    }

    /**
     * @notice Retrieves a rule from storage.
     * @param policyId The ID of the policy the rule belongs to.
     * @param ruleId The ID of the rule to retrieve.
     * @return ruleStorageSets The rule data.
     */
    function getRule(uint256 policyId, uint256 ruleId) public view returns (RuleStorageSet memory) {
        // Load the rule data from storage
        return lib._getRuleStorage().ruleStorageSets[policyId][ruleId];
    }

    /**
     * @notice Stores a rule in storage.
     * @dev Validates the policy existence before storing the rule.
     * @param _data The rule storage structure.
     * @param _policyId The ID of the policy the rule belongs to.
     * @param _ruleId The ID of the rule to store.
     * @param _rule The rule to store.
     * @return ruleId The stored rule ID.
     */
    function _storeRule(RuleStorage storage _data, uint256 _policyId, uint256 _ruleId, Rule calldata _rule) internal returns (uint256) {
        // Validate that the policy exists
        if (!lib._getPolicyStorage().policyStorageSets[_policyId].set) revert("Invalid PolicyId");

        _data.ruleStorageSets[_policyId][_ruleId].set = true;
        _data.ruleStorageSets[_policyId][_ruleId].rule = _rule;
        return _ruleId;
    }

    function _validateRule(Rule calldata rule) internal pure {
        // instructionSet
        if (rule.instructionSet.length == 0) revert(EMPTY_INSTRUCTION_SET); // only applies to top level instruction set
        _validateInstructionSet(rule.instructionSet);
        // rawData
        for (uint i = 0; i < rule.rawData.instructionSetIndex.length; i++) {
            _validateInstructionSetIndex(rule.rawData.instructionSetIndex[i]);
        }
        for (uint i = 0; i < rule.rawData.argumentTypes.length; i++) {
            _validateParamType(rule.rawData.argumentTypes[i]);
        }
        // placeholders
        _validatePlaceholders(rule.placeHolders);
        _validatePlaceholders(rule.effectPlaceHolders);
        // effects
        _validateEffects(rule.posEffects);
        _validateEffects(rule.negEffects);
    }

    /**
     * @notice Validates an array of effects.
     * @param effects The effects to validate.
     */
    function _validateEffects(Effect[] calldata effects) internal pure {
        for (uint256 i = 0; i < effects.length; i++) {
            _validateEffectType(effects[i].effectType);
            _validateParamType(effects[i].pType);
            _validateInstructionSet(effects[i].instructionSet);
        }
    }

    /**
     * @notice Validates an array of placeholders.
     * @param placeholders The placeholders to validate.
     */
    function _validatePlaceholders(Placeholder[] calldata placeholders) internal pure {
        for (uint256 i = 0; i < placeholders.length; i++) {
            _validateParamType(placeholders[i].pType);
            _validateInstructionSetIndex(placeholders[i].typeSpecificIndex);
        }
    }

    /**
     * @notice Validates an instruction set.
     * @param instructionSet The instructionSet to validate.
     */
    function _validateInstructionSet(uint256[] calldata instructionSet) internal pure {
        uint memorySize = 90; // size of the mem array
        uint opsSize1 = 3; // the first 3 opcodes use only one argument
        uint opSizeUpTo2 = 16; // the first 16 opcodes use up to two arguments
        uint opSizeUpTo3 = 17; // the first 17 opcodes use up to three arguments
        uint opTotalSize = 18; // there are a total of 18 opcode in the set LogicalOp
        uint expectedDataElements; // the number of expected data elements in the instruction set (memory pointers)
        bool isData; // the first item of an instruction set must be an opcode, so isData must be "initialized" to false

        // we loop through the instructionSet to validate it
        for (uint256 i = 0; i < instructionSet.length; i++) {
            // we extract the specific item from the validation set which is in memory, and we place it in the stack to save some gas
            uint instruction = instructionSet[i];
            if (isData) {
                // if the instruction is data, we just check that it won't point to an index outside of max memory size
                if (instruction > memorySize) revert(MEMORY_OVERFLOW);
                // we reduce the expectedDataElements count by one, but only if necessary
                if (expectedDataElements > 1) --expectedDataElements;
                else {
                    // if we have no more expected data elements, we can reset the isData flag, and we set the expectedDataElements to 0
                    isData = false;
                    delete expectedDataElements;
                }
            } else {
                // if the instruction is not data, we check that it is a valid opcode
                if (instruction > opTotalSize) revert(INVALID_INSTRUCTION);
                // NUM is a special case since it can expect any data, so no check is needed next
                if (instruction == uint(LogicalOp.NUM)) {
                    unchecked {
                        ++i; // we simply incrememt the iterator to skip the next data element
                    }
                    // we skip setting the isData flag and the expectedDataElements since we won't go through any data
                    continue;
                }
                //we set the expectedDataElements based its position inside the LogicalOp enum
                if (instruction < opsSize1) expectedDataElements = 1;
                else if (instruction < opSizeUpTo2) expectedDataElements = 2;
                else if (instruction < opSizeUpTo3) expectedDataElements = 3;
                else expectedDataElements = 4;
                isData = true; // we know that following instruction(s) is a data pointer
            }
        }
        // if we have any expected data elements left, it means the instruction set is invalid
        if (expectedDataElements > 0 || isData) revert(INVALID_INSTRUCTION_SET);
    }

    /**
     * @notice Validates a paramType.
     * @param paramType The paramType to validate.
     */
    function _validateParamType(ParamTypes paramType) internal pure {
        uint paramTypesSize = 8;
        if (uint(paramType) >= paramTypesSize) revert(INVALID_PARAM_TYPE);
    }

    /**
     * @notice Validates an effect type.
     * @param effectType The effectType to validate.
     */
    function _validateEffectType(EffectTypes effectType) internal pure {
        uint EffectTypesSize = 3;
        if (uint(effectType) >= EffectTypesSize) revert(INVALID_EFFECT_TYPE);
    }

    /**
     * @notice Validates an instruction set index type.
     * @param index The index to validate.
     */
    function _validateInstructionSetIndex(uint256 index) internal pure {
        uint memorySize = 90;
        if (index > memorySize) revert(MEMORY_OVERFLOW);
    }
}
