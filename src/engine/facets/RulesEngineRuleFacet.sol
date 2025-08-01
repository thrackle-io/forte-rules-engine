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
    uint public constant memorySize = 90; // size of the mem array
    uint public constant opsSize1 = 3; // the first 3 opcodes use only one argument
    uint public constant opsSizeUpTo2 = 17; // the first 16 opcodes use up to two arguments
    uint public constant opsSizeUpTo3 = 18; // the first 17 opcodes use up to three arguments
    uint public constant opsTotalSize = 19; // there are a total of 18 opcode in the set LogicalOp
    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Rule Management
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Creates a rule in storage.
     * @dev Adds a new rule to the specified policy. Only accessible by policy admins.
     * @param policyId ID of the policy the rule will be added to.
     * @param rule The rule to create.
     * @param ruleName The name of the rule
     * @param ruleDescription The description of the rule
     * @return ruleId The generated rule ID.
     */
    function createRule(
        uint256 policyId,
        Rule calldata rule,
        string calldata ruleName,
        string calldata ruleDescription
    ) external returns (uint256) {
        if (policyId == 0) revert(POLICY_ID_0);
        _policyAdminOnly(policyId, msg.sender);
        _validateRule(rule);
        StorageLib._notCemented(policyId);
        RuleStorage storage data = lib._getRuleStorage();
        uint256 ruleId = _incrementRuleId(data, policyId);
        _storeRuleData(data, policyId, ruleId, rule, ruleName, ruleDescription);
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
        Rule calldata rule,
        string calldata ruleName,
        string calldata ruleDescription
    ) external returns (uint256) {
        if (policyId == 0) revert(POLICY_ID_0);
        _policyAdminOnly(policyId, msg.sender);
        _validateRule(rule);
        StorageLib._notCemented(policyId);
        // Load the rule data from storage
        RuleStorage storage data = lib._getRuleStorage();
        _storeRuleData(data, policyId, ruleId, rule, ruleName, ruleDescription);
        emit RuleUpdated(policyId, ruleId);
        return ruleId;
    }

    /**
     * @notice Retrieves all rules associated with a specific policy.
     * @param policyId The ID of the policy.
     * @return rules A two-dimensional array of rules grouped by calling functions.
     */
    function getAllRules(uint256 policyId) external view returns (Rule[][] memory) {
        if (policyId == 0) revert(POLICY_ID_0);
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
     * @notice Retrieves the metadata of a rule.
     * @param policyId The ID of the policy the rule belongs to.
     * @param ruleId The ID of the rule to retrieve metadata for.
     * @return RuleMetadata The metadata of the specified rule.
     */
    function getRuleMetadata(uint256 policyId, uint256 ruleId) external view returns (RuleMetadata memory) {
        if (policyId == 0) revert(POLICY_ID_0);
        return (lib._getRulesMetadataStorage().ruleMetadata[policyId][ruleId]);
    }

    /**
     * @notice Deletes a rule from storage.
     * @param policyId The ID of the policy the rule belongs to.
     * @param ruleId The ID of the rule to delete.
     */
    function deleteRule(uint256 policyId, uint256 ruleId) public {
        if (policyId == 0) revert(POLICY_ID_0);
        if (!lib._getRuleStorage().ruleStorageSets[policyId][ruleId].set) revert(INVALID_RULE);
        _policyAdminOnly(policyId, msg.sender);
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
        if (policyId == 0) revert(POLICY_ID_0);
        // Load the rule data from storage
        return lib._getRuleStorage().ruleStorageSets[policyId][ruleId];
    }

    /**
     * @notice Stores rule data in storage.
     * @dev This function is used to store the rule and its metadata.
     * @param data The rule storage structure.
     * @param policyId The ID of the policy the rule belongs to.
     * @param ruleId The ID of the rule to store.
     * @param rule The rule to store.
     * @param ruleName The name of the rule.
     * @param ruleDescription The description of the rule.
     */
    function _storeRuleData(
        RuleStorage storage data,
        uint256 policyId,
        uint256 ruleId,
        Rule calldata rule,
        string calldata ruleName,
        string calldata ruleDescription
    ) private {
        _storeRule(data, policyId, ruleId, rule);
        _storeRuleMetadata(policyId, ruleId, ruleName, ruleDescription);
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
        if (!lib._getPolicyStorage().policyStorageSets[_policyId].set) revert(POLICY_ID_INV);

        _data.ruleStorageSets[_policyId][_ruleId].set = true;
        _data.ruleStorageSets[_policyId][_ruleId].rule = _rule;
        return _ruleId;
    }

    /**
     * @notice Increments the rule ID counter for a specific policy.
     * @dev This function is used to generate a new rule ID for a policy.
     * @param data The rule storage structure.
     * @param _policyId The ID of the policy to increment the rule ID for.
     * @return The incremented rule ID.
     */
    function _incrementRuleId(RuleStorage storage data, uint256 _policyId) private returns (uint256) {
        return ++data.ruleIdCounter[_policyId];
    }

    /**
     * @notice function to store the metadata for a rule.
     * @dev This function is used to store the metadata for a rule, such as its name and description.
     * @param _policyId The ID of the policy the rule belongs to.
     * @param _ruleId The ID of the rule to store metadata for.
     * @param _ruleName The name of the rule.
     * @param _description The description of the rule.
     */
    function _storeRuleMetadata(uint256 _policyId, uint256 _ruleId, string calldata _ruleName, string calldata _description) internal {
        RulesMetadataStruct storage metadata = lib._getRulesMetadataStorage();
        metadata.ruleMetadata[_policyId][_ruleId].ruleName = _ruleName;
        metadata.ruleMetadata[_policyId][_ruleId].ruleDescription = _description;
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
        require(rule.posEffects.length > 0 || rule.negEffects.length > 0, EFFECT_REQ);
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
                if (instruction > opsTotalSize) revert(INVALID_INSTRUCTION);
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
                else if (instruction < opsSizeUpTo2) expectedDataElements = 2;
                else if (instruction < opsSizeUpTo3) expectedDataElements = 3;
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
        if (index > memorySize) revert(MEMORY_OVERFLOW);
    }

    /**
     * @notice Checks that the caller is a policy admin
     * @param _policyId The ID of the policy.
     * @param _address The address to check for policy admin status.
     */
    function _policyAdminOnly(uint256 _policyId, address _address) internal {
        // 0x901cee11 = isPolicyAdmin(uint256,address)
        (bool success, bytes memory res) = _callAnotherFacet(
            0x901cee11,
            abi.encodeWithSignature("isPolicyAdmin(uint256,address)", _policyId, _address)
        );
        bool returnBool;
        if (success) {
            if (res.length >= 4) {
                assembly {
                    returnBool := mload(add(res, 32))
                }
            } else {
                returnBool = false;
            }
            // returned false so revert with error
            if (!returnBool) revert(NOT_AUTH_POLICY);
        }
    }
}
