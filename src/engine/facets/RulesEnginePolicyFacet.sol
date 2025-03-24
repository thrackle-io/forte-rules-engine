// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetCommonImports.sol";
import "src/engine/facets/RulesEngineAdminRolesFacet.sol";
import "src/engine/facets/RulesEngineComponentFacet.sol";

/**
 * @title Rules Engine Data Facet
 * @author @ShaneDuncan602 
 * @dev This contract serves as the primary data facet for the rules engine. It is responsible for mutating and serving all the policy data.
 * @notice Data facet for the Rules Engine
 */
contract RulesEnginePolicyFacet is FacetCommonImports {

    /**
     * Create a rule in storage.
     * @param _policyId ID of the policy the rule will be added to
     * @param _rule the rule to create
     * @return ruleId the generated ruleId
     */
    function createRule(uint256 _policyId, Rule calldata _rule) public policyAdminOnly(_policyId, msg.sender) notCemented(_policyId) returns (uint256) {
        RuleS storage data = lib.getRuleStorage();
        uint256 ruleId = ++data.ruleIdCounter[_policyId];
        _storeRule(data, _policyId, ruleId, _rule);
        data.ruleIdCounter[_policyId] = ruleId;
        emit RuleCreated(_policyId, ruleId);
        return ruleId;
    }

    /**
     * Add a rule to storage.
     * @param _ruleId the ruleId to add
     * @param _rule the rule to add
     * @return ruleId the generated ruleId
     */
    function _storeRule(RuleS storage _data, uint256 _policyId, uint256 _ruleId, Rule calldata _rule) internal returns (uint256) {
        // TODO: Add validations for rule
        
        // Validate that the policy exists
        if(!lib.getPolicyStorage().policyStorageSets[_policyId].set) revert ("Invalid PolicyId");

        _data.ruleStorageSets[_policyId][_ruleId].set = true;
        _data.ruleStorageSets[_policyId][_ruleId].rule = _rule;
        return _ruleId;
    }

    /// Rule Storage
    /**
     * Update a rule in storage.
     * @param _policyId ID of the policy the rule belongs to
     * @param _ruleId the id of the rule
     * @param _rule the rule to update
     * @return ruleId the generated ruleId
     */
    function updateRule(
        uint256 _policyId,
        uint256 _ruleId,
        Rule calldata _rule
    ) external policyAdminOnly(_policyId, msg.sender) notCemented(_policyId) returns (uint256) {
        // Load the function signature data from storage
        RuleS storage data = lib.getRuleStorage();
        _storeRule(data, _policyId, _ruleId, _rule);
        emit RuleUpdated(_policyId, _ruleId);
        return _ruleId;
    }

    /**
     * Get a rule from storage.
     * @param _ruleId ruleId
     * @return ruleStorageSets rule
     */
    function getRule(uint256 _policyId, uint256 _ruleId) public view returns (RuleStorageSet memory) {
        // Load the function signature data from storage
        return lib.getRuleStorage().ruleStorageSets[_policyId][_ruleId];
    }

    /**
     * Get all rules from storage.
     * @param _policyId the policyId the rules are associated with
     * @return rules rules
     */
    function getAllRules(uint256 _policyId) external view returns (Rule[][] memory) {
        // Load the function signature data from storage
        Policy storage data = lib.getPolicyStorage().policyStorageSets[_policyId].policy;
        bytes4[] memory signatures = data.signatures;
        Rule[][] memory rules = new Rule[][](signatures.length);
        for (uint256 i = 0; i < signatures.length; i++) {
            uint256[] memory ruleIds = data.signatureToRuleIds[signatures[i]];
            rules[i] = new Rule[](ruleIds.length);
            for (uint256 j = 0; j < ruleIds.length; j++) {
                if (lib.getRuleStorage().ruleStorageSets[_policyId][ruleIds[j]].set) {
                    rules[i][j] = lib.getRuleStorage().ruleStorageSets[_policyId][ruleIds[j]].rule;
                }
            }
        }
        return rules;
    }


    /// Policy Storage
    /**
     * Update a Policy in Storage
     * @param _policyId id of of the policy 
     * @param _signatures all signatures in the policy
     * @param _functionSignatureIds corresponding signature ids in the policy. The elements in this array are one to one matches of the elements in _signatures array. They store the functionSignatureId for each of the signatures in _signatures array.
     * @param _ruleIds two dimensional array of the rules. This array contains a simple count at first level and the second level is the array of ruleId's within the policy.
     * @param _policyType type of policy (CLOSED_POLICY or OPEN_POLICY)
     * @return policyId generated policyId
     * @dev The parameters had to be complex because nested structs are not allowed for externally facing functions
     */
    function updatePolicy(
        uint256 _policyId, 
        bytes4[] calldata _signatures, 
        uint256[] calldata _functionSignatureIds, 
        uint256[][] calldata _ruleIds,
        PolicyType _policyType
    ) external policyAdminOnly(_policyId, msg.sender) notCemented(_policyId) returns(uint256) {
        // signature length must match the signature id length
        if (_signatures.length != _functionSignatureIds.length) revert(SIGNATURES_INCONSISTENT); 
        // if policy ID is zero no policy has been created and cannot be updated. 
        if (_policyId == 0) revert(POLICY_ID_0);
        emit PolicyUpdated(_policyId);
        // Update the policy type
        return _storePolicyData(_policyId, _signatures, _functionSignatureIds, _ruleIds, _policyType);
    }

    /**
     * Close the Policy 
     * @param _policyId id of of the policy 
     * @dev The parameters had to be complex because nested structs are not allowed for externally facing functions
     */
    function closePolicy(uint256 _policyId) external policyAdminOnly(_policyId, msg.sender) notCemented(_policyId) {
        _processPolicyTypeChange(_policyId, PolicyType.CLOSED_POLICY);        
        emit PolicyClosed(_policyId);
    }

    /**
     * Open the policy
     * @param _policyId id of of the policy 
     * @dev The parameters had to be complex because nested structs are not allowed for externally facing functions
     */
    function openPolicy(uint256 _policyId) external policyAdminOnly(_policyId, msg.sender) notCemented(_policyId) {
        _processPolicyTypeChange(_policyId, PolicyType.OPEN_POLICY);        
        emit PolicyOpened(_policyId);
    }

    /**
     * Function to check if a policy is closed
     * @param _policyId policyId
     * @return true/false
     */
    function isClosedPolicy(uint256 _policyId) external view returns (bool) {
        return (lib.getPolicyStorage().policyStorageSets[_policyId].policy.policyType == PolicyType.CLOSED_POLICY);
    }

    /**
     * Delete a Policy from Storage
     * @param _policyId the id of the policy to delete
     */
    function deletePolicy(uint256 _policyId) public policyAdminOnly(_policyId, msg.sender) notCemented(_policyId){
        PolicyStorageSet storage data = lib.getPolicyStorage().policyStorageSets[_policyId];
        delete data.set;

        for (uint256 i = 0; i < data.policy.signatures.length; i++) {
            delete data.policy.functionSignatureIdMap[data.policy.signatures[i]];
            delete data.policy.signatureToRuleIds[data.policy.signatures[i]];
        }
        emit PolicyDeleted(_policyId);
    }


    /**
     * Apply the policies to the contracts.
     * @param _contractAddress address of the contract to have policies applied
     * @param _policyIds the rule to add 
     */
    function applyPolicy(address _contractAddress, uint256[] calldata _policyIds) callingContractAdminOnly(_contractAddress, msg.sender) external { 
        // Load the function signature data from storage
        PolicyAssociationS storage data = lib.getPolicyAssociationStorage();
        
        // Check policy type for each policy being applied
        for(uint256 i = 0; i < _policyIds.length; i++) {
            PolicyStorageSet storage policySet = lib.getPolicyStorage().policyStorageSets[_policyIds[i]];
            require(policySet.set, POLICY_DOES_NOT_EXIST);
            
            // If policy is cemented, no one can apply it
            if(_isCemented(_policyIds[i])) revert(POLICY_CEMENTED);

            // If policy is closed, only admin can apply it
            if(policySet.policy.policyType == PolicyType.CLOSED_POLICY) {
                require(policySet.policy.closedPolicySubscribers[msg.sender],
                    VERIFIED_SUBSCRIBER_ONLY
                );
            }
        }

        // Apply the policies
        data.contractPolicyIdMap[_contractAddress] = new uint256[](_policyIds.length);
        for(uint256 i = 0; i < _policyIds.length; i++) {
           data.contractPolicyIdMap[_contractAddress][i] = _policyIds[i];
           data.policyIdContractMap[_policyIds[i]].push(_contractAddress);
        }
        emit PolicyApplied(_policyIds, _contractAddress);
    }

    // TODO add removePolicy fn

    /**
     * Get an applied policyId from storage. 
     * @param _contractAddress contract address
     * @return policyId policyId
     */
    function getAppliedPolicyIds(address _contractAddress) external view returns (uint256[] memory) {
        // Load the policy association data from storage
        return lib.getPolicyAssociationStorage().contractPolicyIdMap[_contractAddress];
    }

    /**
     * Add a Policy to Storage and create the policy admin for the policy 
     * @param _functionSignatures corresponding signature ids in the policy. The elements in this array are one to one matches of the elements in _signatures array. They store the functionSignatureId for each of the signatures in _signatures array.
     * @param _rules two dimensional array of the rules. This array contains a simple count at first level and the second level is the array of ruleId's within the policy.
     * @param _policyType type of policy (CLOSED_POLICY or OPEN_POLICY)
     * @return policyId generated policyId
     * @dev The parameters had to be complex because nested structs are not allowed for externally facing functions
     */
    function createPolicy(
        FunctionSignatureStorageSet[] calldata _functionSignatures, 
        Rule[] calldata _rules,
        PolicyType _policyType
    ) external returns(uint256) {
        // retrieve Policy Storage 
        PolicyS storage data = lib.getPolicyStorage();
        uint256 policyId = data.policyId; 
        // If this is the first policy created increment by 1 to start id counter. 
        unchecked{
            ++data.policyId;
        }
        policyId = data.policyId;
        data.policyStorageSets[policyId].set = true; 
        data.policyStorageSets[policyId].policy.policyType = _policyType;
        //This function is called as an external call intentionally. This allows for proper gating on the generatePolicyAdminRole fn to only be callable by the RulesEngine address. 
        RulesEngineAdminRolesFacet(address(this)).generatePolicyAdminRole(policyId, address(msg.sender));
        //TODO remove this when create policy is atomic 
        // Temporarily disabling _storePolicyData
        // return _storePolicyData(policyId, _functionSignatures, _rules);
        
        _functionSignatures;
        _rules;
        emit PolicyCreated(policyId);
        return policyId;
    }

    /**
     * @dev internal helper function for create and update policy functions  
     * @param _policyId id of of the policy 
     * @param _signatures all signatures in the policy
     * @param _functionSignatureIds corresponding signature ids in the policy. The elements in this array are one to one matches of the elements in _signatures array. They store the functionSignatureId for each of the signatures in _signatures array.
     * @param _ruleIds two dimensional array of the rules. This array contains a simple count at first level and the second level is the array of ruleId's within the policy.
     * @param _policyType type of the policy(OPEN/CLOSED)
     * @return policyId updated policyId 
     * @dev The parameters had to be complex because nested structs are not allowed for externally facing functions
     */
    function _storePolicyData(uint256 _policyId, bytes4[] calldata _signatures, uint256[] calldata _functionSignatureIds, uint256[][] calldata _ruleIds, PolicyType _policyType) internal returns(uint256){   
        // Load the policy data from storage
        Policy storage data = lib.getPolicyStorage().policyStorageSets[_policyId].policy;
        // if the policy type is changing, perform all data maintenance
        _processPolicyTypeChange(_policyId, _policyType);
        // clear the iterator array
        delete data.signatures;
        if (_ruleIds.length > 0) {
            // Loop through all the passed in signatures for the policy      
            for (uint256 i = 0; i < _signatures.length; i++) {
                // make sure that all the function signatures exist
                if(!_isFunctionSignatureSet(_policyId, _functionSignatureIds[i])) revert(INVALID_SIGNATURE);
                // Load into the mapping
                data.functionSignatureIdMap[_signatures[i]] = _functionSignatureIds[i];
                // load the iterator array
                data.signatures.push(_signatures[i]);
                // make sure that all the rules attached to each function signature exist
                for (uint256 j = 0; j < _ruleIds[i].length; j++) {
                    RuleStorageSet memory ruleStore = getRule(_policyId, _ruleIds[i][j]);
                    if(!ruleStore.set) revert(INVALID_RULE);
                    for (uint256 k = 0; k < ruleStore.rule.placeHolders.length; k++) {
                        if(ruleStore.rule.placeHolders[k].foreignCall) {
                            // get the foreign call using the type specific index which will be interpreted as a foreign call index since it has foreignCall bool set
                            require(_isForeignCallSet(_policyId, ruleStore.rule.placeHolders[k].typeSpecificIndex), FOREIGN_CALL_NOT_SET);
                        } else if (ruleStore.rule.placeHolders[k].trackerValue) {
                            require(_isTrackerSet(_policyId, ruleStore.rule.placeHolders[k].typeSpecificIndex), TRACKER_NOT_SET);
                        }

                    }
                    data.signatureToRuleIds[_signatures[i]].push(_ruleIds[i][j]);
                }
                
            }
        } else {
            // Solely loop through and add signatures to the policy
            for (uint256 i = 0; i < _signatures.length; i++) {
                // make sure that all the function signatures exist
                if(!_isFunctionSignatureSet(_policyId, _functionSignatureIds[i])) revert(INVALID_SIGNATURE);
                // Load into the mapping
                data.functionSignatureIdMap[_signatures[i]] = _functionSignatureIds[i];
                // load the iterator array
                data.signatures.push(_signatures[i]);
            }
        }    
        
        return _policyId;
    }

    /**
     * @dev internal helper function to clean up data during policy type changes.
     * @param _policyId id of of the policy 
     * @param _policyType type of the policy(OPEN/CLOSED)
     * @dev The parameters had to be complex because nested structs are not allowed for externally facing functions
     */
    function _processPolicyTypeChange(uint256 _policyId, PolicyType _policyType) internal {
        // If closing, remove all applied contract associations
        Policy storage data = lib.getPolicyStorage().policyStorageSets[_policyId].policy;
        if (_policyType == PolicyType.CLOSED_POLICY){
            // Load the function signature data from storage
            PolicyAssociationS storage assocData = lib.getPolicyAssociationStorage();
            for (uint256 i = 0; i < assocData.policyIdContractMap[_policyId].length; i++) { 
                delete assocData.contractPolicyIdMap[assocData.policyIdContractMap[_policyId][i]];
            }
            delete assocData.policyIdContractMap[_policyId];
        } 
        data.policyType = _policyType;
    }

    /**
     * Get a policy from storage. Since Policy contains nested mappings, they must be broken into arrays to return the data externally. 
     * @param _policyId policyId
     * @return functionSigs function signatures within the policy(from Policy.functionSignatureIdMap)
     * @return functionSigIds function signature ids corresponding to each function sig in functionSigs(from Policy.functionSignatureIdMap)
     * @return ruleIds rule ids corresponding to each function signature in functionSigs(from Policy.signatureToRuleIds)
     */
    function getPolicy(uint256 _policyId) external view returns(bytes4[] memory functionSigs, uint256[] memory functionSigIds, uint256[][] memory ruleIds) {
        // Load the policy data from storage
        Policy storage policy = lib.getPolicyStorage().policyStorageSets[_policyId].policy;
        // Initialize the return arrays if necessary
        if(policy.signatures.length > 0){
            functionSigs = new bytes4[](policy.signatures.length);
            functionSigIds = new uint256[](policy.signatures.length);
            ruleIds = new uint256[][](policy.signatures.length);
        }
        ruleIds = new uint256[][](policy.signatures.length);
        // Loop through the function signatures and load the return arrays
        for (uint256 i = 0; i < policy.signatures.length; i++) {
            functionSigs[i] = policy.signatures[i];
            functionSigIds[i] = policy.functionSignatureIdMap[policy.signatures[i]];
            // Initialize the ruleId return array if necessary
            for (uint256 ruleIndex = 0; ruleIndex < policy.signatureToRuleIds[policy.signatures[i]].length; ruleIndex++) {
                // have to allocate the memory array here
                ruleIds[i] = new uint256[](policy.signatureToRuleIds[policy.signatures[i]].length);
                ruleIds[i][ruleIndex] = policy.signatureToRuleIds[policy.signatures[i]][ruleIndex];
            }
        }
    }

    /**
     * Function to check Policy's cemented status
     * @param _policyId policyId
     * @return _cemented cemented (true/false)
     */
     function _isCemented(uint256 _policyId) internal view returns(bool _cemented){
        return lib.getPolicyStorage().policyStorageSets[_policyId].policy.cemented;
     }

     /**
     * @dev This is the modifier used to ensure that cemented policies can't be changed.
     * @param _policyId policyId
     */
    modifier notCemented(uint256 _policyId) {
        if(_isCemented(_policyId)) revert (POLICY_CEMENTED);
        _;
    }

    /**
     * Function to cement a specified policy
     * @param _policyId policyId
     */
    function cementPolicy(uint256 _policyId) external policyAdminOnly(_policyId, msg.sender) {
        lib.getPolicyStorage().policyStorageSets[_policyId].policy.cemented = true;
        emit PolicyCemented(_policyId);
    }

    /// This section is for internal functions used for validation of components. They are here to optimize gas consumption
    /**
     * Check to see if a function signature is set for the policy.
     * @param _policyId the policyId the function signature is associated with
     * @param _functionSignatureId functionSignatureId
     * @return set true/false
     */
    function _isFunctionSignatureSet(
        uint256 _policyId,
        uint256 _functionSignatureId
    ) internal view returns (bool) {
        // Load the function signature data from storage
        return
            lib.getFunctionSignatureStorage().functionSignatureStorageSets[_policyId][_functionSignatureId].set;
    }

    /**
     * @dev Check to see if the foreign call is set for this policy
     * @param _policyId the policy Id of the foreign call to retrieve
     * @param _foreignCallId the Id of the foreign call to retrieve
     * @return set true/false
     */
    function _isForeignCallSet(
        uint256 _policyId,
        uint256 _foreignCallId
    ) internal view returns (bool) {
        // Load the Foreign Call data from storage
        return lib.getForeignCallStorage().foreignCalls[_policyId][_foreignCallId].set;
    }

    /**
     * Check to see if a tracker is set for this policy
     * @param _policyId the policyId the trackerStorage is associated with
     * @param _index postion of the tracker to return
     * @return set true/false
     */
    function _isTrackerSet(
        uint256 _policyId,
        uint256 _index
    ) public view returns (bool) {
        // return trackers for contract address at speficic index
        return lib.getTrackerStorage().trackers[_policyId][_index].set;
    }
}
