// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetCommonImports.sol";
import "src/engine/facets/RulesEngineAdminRolesFacet.sol";

/**
 * @title Rules Engine Data Facet
 * @author @ShaneDuncan602 
 * @dev This contract serves as the primary data facet for the rules engine. It is responsible for mutating and serving all the policy data.
 * @notice Data facet for the Rules Engine
 */
contract RulesEngineDataFacet is FacetCommonImports {

    /// Foreign Call Storage
    event ForeignCallCreated(uint256 indexed policyId, uint256 indexed foreignCallId);
    event ForeignCallUpdated(uint256 indexed policyId, uint256 indexed foreignCallId);
    event ForeignCallDeleted(uint256 indexed policyId, uint256 indexed foreignCallId);
    /**
     * @dev Builds a foreign call structure and adds it to the contracts storage, mapped to the contract address it is associated with
     * @param _policyId the policy Id of the policy the foreign call will be mapped to
     * @param _foreignCall The definition of the foreign call to create
     **/
    function createForeignCall(
        uint256 _policyId, 
        ForeignCall calldata _foreignCall
    ) external returns (uint256) {
        // Load the Foreign Call data from storage
        ForeignCallS storage data = lib.getForeignCallStorage();
        uint256 foreignCallIndex = data.foreignCallIdxCounter[_policyId];
        ForeignCall memory fc = _foreignCall;
        fc.foreignCallIndex = foreignCallIndex;
        storeForeignCall(_policyId, fc);
        unchecked {
            ++data.foreignCallIdxCounter[_policyId];
        }
        emit ForeignCallCreated(_policyId, foreignCallIndex);
        return foreignCallIndex;
    }

    /**
     * @dev Stores a foreign call in storage
     * @param _policyId the policyId the foreign call is associated with
     * @param _foreignCall the foreign call to store
     */
    function storeForeignCall(uint256 _policyId, ForeignCall memory _foreignCall) internal {
        assert(_foreignCall.parameterTypes.length == _foreignCall.typeSpecificIndices.length);
        _foreignCall.set = true;
        lib.getForeignCallStorage().foreignCalls[_policyId][_foreignCall.foreignCallIndex] = _foreignCall;
    }

    /**
     * @dev Deletes a foreign call from storage
     * @param _policyId the policyId the foreign call is associated with
     * @param _foreignCallId the foreign call to delete
     */
    function deleteForeignCall(uint256 _policyId, uint256 _foreignCallId) external {
        delete lib.getForeignCallStorage().foreignCalls[_policyId][_foreignCallId];
        emit ForeignCallDeleted(_policyId, _foreignCallId);
    }

    /**
     * @dev Updates a foreign call in storage
     * @param _policyId the policyId the foreign call is associated with
     * @param _foreignCallId the foreign call to update
     * @param _foreignCall the foreign call to update
     * @return fc the foreign call structure
     */
    function updateForeignCall(uint256 _policyId, uint256 _foreignCallId, ForeignCall calldata _foreignCall) external returns (ForeignCall memory fc) {
        fc = _foreignCall;
        fc.foreignCallIndex = _foreignCallId;
        storeForeignCall(_policyId, fc);
        emit ForeignCallUpdated(_policyId, _foreignCallId);
        return fc;
    }

    /**
     * @dev Retrieve Foreign Call from storage 
     * @param _policyId the policy Id of the foreign call to retrieve
     * @param _foreignCallId the Id of the foreign call to retrieve
     * @return fc the foreign call structure
     */
    function getForeignCall(
        uint256 _policyId,
        uint256 _foreignCallId
    ) public view returns (ForeignCall memory fc) {
        // Load the Foreign Call data from storage
        return lib.getForeignCallStorage().foreignCalls[_policyId][_foreignCallId];
    }

    /**
     * @dev Retrieve Foreign Call Set from storage 
     * @param _policyId the policy Id of the foreign call to retrieve
     * @return fc the foreign call set structure
     */
    function getForeignCallSet(uint256 _policyId) public view returns (ForeignCall[] memory fc) {
        // Return the Foreign Call Set data from storage
        ForeignCall[] memory foreignCalls = new ForeignCall[](30);
        for (uint256 i = 0; i < 30; i++) {
            if (lib.getForeignCallStorage().foreignCalls[_policyId][i].set) {
                foreignCalls[i] = lib.getForeignCallStorage().foreignCalls[_policyId][i];
            }
        }
        return foreignCalls;
    }

    /// Tracker Storage
    /**
     * Add a tracker to the trackerStorage mapping.
     * @param _policyId the policyId the trackerStorage is associated with
     * @param _tracker the tracker to add
     * @return trackerIndex the index of the tracker
     */
    function createTracker(
        uint256 _policyId,
        Trackers calldata _tracker
    ) public returns (uint256) {
        // Load the Tracker data from storage
        TrackerS storage data = lib.getTrackerStorage();
        Trackers memory tracker = _tracker;
        tracker.set = true;
        uint256 trackerIndex = data.trackerIndexCounter[_policyId];
        data.trackers[_policyId][trackerIndex] = tracker;
        unchecked {
            ++data.trackerIndexCounter[_policyId];
        }
        return trackerIndex;
    }

    /**
     * Function to update tracker in trackerStorage mapping.
     * @param _policyId the policyId the trackerStorage is associated with
     * @param _trackerIndex the index of the tracker to update
     * @param _tracker the tracker to update
     */
    function updateTracker(
        uint256 _policyId,
        uint256 _trackerIndex,
        Trackers calldata _tracker
    ) public {
        // Load the Tracker data from storage
        TrackerS storage data = lib.getTrackerStorage();
        data.trackers[_policyId][_trackerIndex].set = true;
        data.trackers[_policyId][_trackerIndex] = _tracker;
    }

    /**
     * Return a tracker from the trackerStorage.
     * @param _policyId the policyId the trackerStorage is associated with
     * @param index postion of the tracker to return
     * @return tracker
     */
    function getTracker(
        uint256 _policyId,
        uint256 index
    ) public view returns (Trackers memory tracker) {
        // Load the Tracker data from storage
        TrackerS storage data = lib.getTrackerStorage();
        // return trackers for contract address at speficic index
        return data.trackers[_policyId][index];
    }

    /**
     * Delete a tracker from the trackerStorage.
     * @param _policyId the policyId the trackerStorage is associated with
     * @param _trackerIndex the index of the tracker to delete
     */
    function deleteTracker(uint256 _policyId, uint256 _trackerIndex) public {
        delete lib.getTrackerStorage().trackers[_policyId][_trackerIndex];
    }

    /// Function Signature Storage
    /**
     * Add a function signature to the storage.
     * @param _functionSignatureId functionSignatureId
     * @param functionSignature the string representation of the function signature
     * @param pTypes the types of the parameters for the function in order
     * @return functionId generated function Id
     */
    function updateFunctionSignature(
        uint256 _functionSignatureId,
        bytes4 functionSignature,
        PT[] memory pTypes
    ) public returns (uint256) {
        // TODO: Add validations for function signatures

        // Load the function signature data from storage
        FunctionSignatureS storage data = lib.getFunctionSignatureStorage();
        // increment the functionSignatureId if necessary
        if (_functionSignatureId == 0) {
            unchecked {
                data.functionId++;
            }
            _functionSignatureId = data.functionId;
        }
        data.functionSignatureStorageSets[_functionSignatureId].set = true;
        data
            .functionSignatureStorageSets[_functionSignatureId]
            .signature = functionSignature;
        data
            .functionSignatureStorageSets[_functionSignatureId]
            .parameterTypes = pTypes;
        return _functionSignatureId;
    }

    /**
     * Get a function signature from storage.
     * @param _functionSignatureId functionSignatureId
     * @return functionSignatureSet function signature
     */
    function getFunctionSignature(
        uint256 _functionSignatureId
    ) public view returns (FunctionSignatureStorageSet memory) {
        // Load the function signature data from storage
        return
            lib.getFunctionSignatureStorage().functionSignatureStorageSets[
                _functionSignatureId
            ];
    }

    /**
     * Create a rule in storage.
     * @param _rule the rule to create
     * @return ruleId the generated ruleId
     */
    function createRule(Rule calldata _rule) public policyAdminOnly(_rule.policyId, msg.sender) returns (uint256) {
        RuleS storage data = lib.getRuleStorage();
        unchecked {
            data.ruleId++;
        }
        return addRule(data, data.ruleId, _rule);
    }

    /**
     * Add a rule to storage.
     * @param _ruleId the ruleId to add
     * @param _rule the rule to add
     * @return ruleId the generated ruleId
     */
    function addRule(RuleS storage data, uint256 _ruleId, Rule calldata _rule) internal returns (uint256) {
        // TODO: Add validations for rule
        
        // Validate that the policy exists
        if(!lib.getPolicyStorage().policyStorageSets[_rule.policyId].set) revert ("Invalid PolicyId");

        data.ruleStorageSets[_ruleId].set = true;
        data.ruleStorageSets[_ruleId].rule = _rule;
        return _ruleId;
    }

    /// Rule Storage
    /**
     * Update a rule in storage.
     * @param _ruleId the id of the rule
     * @param rule the rule to update
     * @return ruleId the generated ruleId
     */
    function updateRule(
        uint256 _ruleId,
        Rule calldata rule
    ) public policyAdminOnly(rule.policyId, msg.sender) returns (uint256) {
        // Load the function signature data from storage
        RuleS storage data = lib.getRuleStorage();
        addRule(data, _ruleId, rule);
        return _ruleId;
    }

    /**
     * Get a rule from storage.
     * @param _ruleId ruleId
     * @return ruleStorageSets rule
     */
    function getRule(uint256 _ruleId) public view returns (RuleStorageSet memory) {
        // Load the function signature data from storage
        return lib.getRuleStorage().ruleStorageSets[_ruleId];
    }

    /**
     * Delete a rule from storage.
     * @param _ruleId the id of the rule to delete
     */
    function deleteRule(uint256 _ruleId) public policyAdminOnly(lib.getRuleStorage().ruleStorageSets[_ruleId].rule.policyId, msg.sender) {
        delete lib.getRuleStorage().ruleStorageSets[_ruleId];
    }

    /// Policy Storage
    /**
     * Update a Policy in Storage
     * @param _policyId id of of the policy 
     * @param _signatures all signatures in the policy
     * @param functionSignatureIds corresponding signature ids in the policy. The elements in this array are one to one matches of the elements in _signatures array. They store the functionSignatureId for each of the signatures in _signatures array.
     * @param ruleIds two dimensional array of the rules. This array contains a simple count at first level and the second level is the array of ruleId's within the policy.
     * @return policyId generated policyId
     * @dev The parameters had to be complex because nested structs are not allowed for externally facing functions
     */
    function updatePolicy(uint256 _policyId, bytes4[] calldata _signatures, uint256[] calldata functionSignatureIds, uint256[][] calldata ruleIds) public policyAdminOnly(_policyId, msg.sender) returns(uint256){
        // signature length must match the signature id length
        if (_signatures.length != functionSignatureIds.length) revert("Signatures and signature id's are inconsistent"); 
        // if policy ID is zero no policy has been created and cannot be updated. 
        if (_policyId == 0) revert("Policy ID cannot be 0. Create policy before updating");
        return storePolicyData(_policyId, _signatures, functionSignatureIds, ruleIds);
    }

    /**
     * Delete a Policy from Storage
     * @param _policyId the id of the policy to delete
     */
    function deletePolicy(uint256 _policyId) public {
        PolicyStorageSet storage data = lib.getPolicyStorage().policyStorageSets[_policyId];
        delete data.set;

        for (uint256 i = 0; i < data.policy.signatures.length; i++) {
            delete data.policy.functionSignatureIdMap[data.policy.signatures[i]];
            delete data.policy.signatureToRuleIds[data.policy.signatures[i]];
        }
    }


    /**
     * Add a Policy to Storage and create the policy admin for the policy 
     * @param _signatures all signatures in the policy
     * @param functionSignatureIds corresponding signature ids in the policy. The elements in this array are one to one matches of the elements in _signatures array. They store the functionSignatureId for each of the signatures in _signatures array.
     * @param ruleIds two dimensional array of the rules. This array contains a simple count at first level and the second level is the array of ruleId's within the policy.
     * @return policyId generated policyId
     * @dev The parameters had to be complex because nested structs are not allowed for externally facing functions
     */
    function createPolicy(bytes4[] calldata _signatures, uint256[] calldata functionSignatureIds, uint256[][] calldata ruleIds) public returns(uint256) {
        // retrieve Policy Storage 
        PolicyS storage data = lib.getPolicyStorage();
        uint256 policyId; 
        // If this is the first policy created increment by 1 to start id counter. 
        unchecked{
            ++data.policyId;
        }
        policyId = data.policyId;
        data.policyStorageSets[policyId].set = true;
        //This function is called as an external call intentionally. This allows for proper gating on the generatePolicyAdminRole fn to only be callable by the RulesEngine address. 
        RulesEngineAdminRolesFacet(address(this)).generatePolicyAdminRole(policyId, address(msg.sender));

        return storePolicyData(policyId, _signatures, functionSignatureIds, ruleIds);
    }

    /**
     * @dev internal helper function for create and update policy functions  
     * @param _policyId id of of the policy 
     * @param _signatures all signatures in the policy
     * @param functionSignatureIds corresponding signature ids in the policy. The elements in this array are one to one matches of the elements in _signatures array. They store the functionSignatureId for each of the signatures in _signatures array.
     * @param ruleIds two dimensional array of the rules. This array contains a simple count at first level and the second level is the array of ruleId's within the policy.
     * @return policyId updated policyId 
     * @dev The parameters had to be complex because nested structs are not allowed for externally facing functions
     */
    function storePolicyData(uint256 _policyId, bytes4[] calldata _signatures, uint256[] calldata functionSignatureIds, uint256[][] calldata ruleIds) internal returns(uint256){   
        // Load the policy data from storage
        PolicyS storage data = lib.getPolicyStorage();
        // clear the iterator array
        delete data.policyStorageSets[_policyId].policy.signatures;
        if (ruleIds.length > 0) {
            // Loop through all the passed in signatures for the policy      
            for (uint256 i = 0; i < _signatures.length; i++) {
                // make sure that all the function signatures exist
                if(!getFunctionSignature(functionSignatureIds[i]).set) revert("Invalid Signature");
                // Load into the mapping
                data.policyStorageSets[_policyId].policy.functionSignatureIdMap[_signatures[i]] = functionSignatureIds[i];
                // load the iterator array
                data.policyStorageSets[_policyId].policy.signatures.push(_signatures[i]);
                // make sure that all the rules attached to each function signature exist
                for (uint256 j = 0; j < ruleIds[i].length; j++) {
                    RuleStorageSet memory ruleStore = getRule(ruleIds[i][j]);
                    if(!ruleStore.set) revert("Invalid Rule");
                    for (uint256 k = 0; k < ruleStore.rule.placeHolders.length; k++) {
                        if(ruleStore.rule.placeHolders[k].foreignCall) {
                            // get the foreign call using the type specific index which will be interpreted as a foreign call index since it has foreignCall bool set
                            require(getForeignCall(_policyId, ruleStore.rule.placeHolders[k].typeSpecificIndex).set, "Foreign Call referenced in rule not set");
                        } else if (ruleStore.rule.placeHolders[k].trackerValue) {
                            require(getTracker(_policyId, ruleStore.rule.placeHolders[k].typeSpecificIndex).set, "Tracker referenced in rule not set");
                        }

                    }
                    data.policyStorageSets[_policyId].policy.signatureToRuleIds[_signatures[i]].push(ruleIds[i][j]);
                }
                
            }
        } else {
            // Solely loop through and add signatures to the policy
            for (uint256 i = 0; i < _signatures.length; i++) {
                // make sure that all the function signatures exist
                if(!getFunctionSignature(functionSignatureIds[i]).set) revert("Invalid Signature");
                // Load into the mapping
                data.policyStorageSets[_policyId].policy.functionSignatureIdMap[_signatures[i]] = functionSignatureIds[i];
                // load the iterator array
                data.policyStorageSets[_policyId].policy.signatures.push(_signatures[i]);
            }
        }    
        
        return _policyId;
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
     * Apply the policies to the contracts.
     * @param _contractAddress address of the contract to have policies applied
     * @param _policyId the rule to add 
     */
    function applyPolicy(address _contractAddress, uint256[] calldata _policyId) public {
        // Load the function signature data from storage
        PolicyAssociationS storage data = lib.getPolicyAssociationStorage();
        // TODO: atomic setting function plus an addToAppliedPolicies?
        data.contractPolicyIdMap[_contractAddress] = new uint256[](_policyId.length);
        for(uint256 i = 0; i < _policyId.length; i++) {
           data.contractPolicyIdMap[_contractAddress][i] = _policyId[i];
        }
    }

    /**
     * Get an applied policyId from storage. 
     * @param _contractAddress contract address
     * @return policyId policyId
     */
    function getAppliedPolicyIds(address _contractAddress) public view returns (uint256[] memory) {
        // Load the policy association data from storage
        return lib.getPolicyAssociationStorage().contractPolicyIdMap[_contractAddress];
    }
}
