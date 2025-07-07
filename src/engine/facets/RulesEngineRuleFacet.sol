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
        for (uint256 i = 0; i < callingFunctions.length; i++) {
            uint256[] memory ruleIds = data.callingFunctionsToRuleIds[callingFunctions[i]];
            rules[i] = new Rule[](ruleIds.length);
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
}
