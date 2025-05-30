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
     * @param _policyId ID of the policy the rule will be added to.
     * @param _rule The rule to create.
     * @return ruleId The generated rule ID.
     */
    function createRule(uint256 _policyId, Rule calldata _rule) external policyAdminOnly(_policyId, msg.sender) returns (uint256) {
        StorageLib.notCemented(_policyId);
        RuleS storage data = lib.getRuleStorage();
        uint256 ruleId = ++data.ruleIdCounter[_policyId];
        _storeRule(data, _policyId, ruleId, _rule);
        data.ruleIdCounter[_policyId] = ruleId;
        emit RuleCreated(_policyId, ruleId);
        return ruleId;
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
    function _storeRule(RuleS storage _data, uint256 _policyId, uint256 _ruleId, Rule calldata _rule) internal returns (uint256) {
        // TODO: Add validations for rule
        
        // Validate that the policy exists
        if(!lib.getPolicyStorage().policyStorageSets[_policyId].set) revert ("Invalid PolicyId");

        _data.ruleStorageSets[_policyId][_ruleId].set = true;
        _data.ruleStorageSets[_policyId][_ruleId].rule = _rule;
        return _ruleId;
    }

    /**
     * @notice Updates a rule in storage.
     * @dev Modifies an existing rule in the specified policy. Only accessible by policy admins.
     * @param _policyId ID of the policy the rule belongs to.
     * @param _ruleId The ID of the rule to update.
     * @param _rule The updated rule data.
     * @return ruleId The updated rule ID.
     */
    function updateRule(
        uint256 _policyId,
        uint256 _ruleId,
        Rule calldata _rule
    ) external policyAdminOnly(_policyId, msg.sender) returns (uint256) {
        StorageLib.notCemented(_policyId);
        // Load the rule data from storage
        RuleS storage data = lib.getRuleStorage();
        _storeRule(data, _policyId, _ruleId, _rule);
        emit RuleUpdated(_policyId, _ruleId);
        return _ruleId;
    }

    /**
     * @notice Retrieves a rule from storage.
     * @param _policyId The ID of the policy the rule belongs to.
     * @param _ruleId The ID of the rule to retrieve.
     * @return ruleStorageSets The rule data.
     */
    function getRule(uint256 _policyId, uint256 _ruleId) public view returns (RuleStorageSet memory) {
        // Load the rule data from storage
        return lib.getRuleStorage().ruleStorageSets[_policyId][_ruleId];
    }

    /**
     * @notice Deletes a rule from storage.
     * @param _policyId The ID of the policy the rule belongs to.
     * @param _ruleId The ID of the rule to delete.
     */
    function deleteRule(uint256 _policyId, uint256 _ruleId) public policyAdminOnly(_policyId, msg.sender) {
        StorageLib.notCemented(_policyId);
        delete lib.getRuleStorage().ruleStorageSets[_policyId][_ruleId];
        emit RuleDeleted(_policyId, _ruleId); 
    }

    /**
     * @notice Retrieves all rules associated with a specific policy.
     * @param _policyId The ID of the policy.
     * @return rules A two-dimensional array of rules grouped by calling functions.
     */
    function getAllRules(uint256 _policyId) external view returns (Rule[][] memory) {
        // Load the policy data from storage
        Policy storage data = lib.getPolicyStorage().policyStorageSets[_policyId].policy;
        bytes4[] memory callingFunctions = data.callingFunctions;
        Rule[][] memory rules = new Rule[][](callingFunctions.length);
        for (uint256 i = 0; i < callingFunctions.length; i++) {
            uint256[] memory ruleIds = data.callingFunctionsToRuleIds[callingFunctions[i]];
            rules[i] = new Rule[](ruleIds.length);
            for (uint256 j = 0; j < ruleIds.length; j++) {
                if (lib.getRuleStorage().ruleStorageSets[_policyId][ruleIds[j]].set) {
                    rules[i][j] = lib.getRuleStorage().ruleStorageSets[_policyId][ruleIds[j]].rule;
                }
            }
        }
        return rules;
    }

}
