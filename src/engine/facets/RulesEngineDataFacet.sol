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
    ) external policyAdminOnly(_policyId, msg.sender) returns (uint256) {
        // Load the Foreign Call data from storage
        ForeignCallS storage data = lib.getForeignCallStorage();
        uint256 foreignCallIndex = ++data.foreignCallIdxCounter[_policyId];
        ForeignCall memory fc = _foreignCall;
        fc.foreignCallIndex = foreignCallIndex;
        _storeForeignCall(_policyId, fc);
        data.foreignCallIdxCounter[_policyId] = foreignCallIndex;
        emit ForeignCallCreated(_policyId, foreignCallIndex);
        return foreignCallIndex;
    }

    /**
     * @dev Stores a foreign call in storage
     * @param _policyId the policyId the foreign call is associated with
     * @param _foreignCall the foreign call to store
     */
    function _storeForeignCall(uint256 _policyId, ForeignCall memory _foreignCall) internal {
        assert(_foreignCall.parameterTypes.length == _foreignCall.typeSpecificIndices.length);
        _foreignCall.set = true;
        lib.getForeignCallStorage().foreignCalls[_policyId][_foreignCall.foreignCallIndex] = _foreignCall;
    }

    /**
     * @dev Deletes a foreign call from storage
     * @param _policyId the policyId the foreign call is associated with
     * @param _foreignCallId the foreign call to delete
     */
    function deleteForeignCall(uint256 _policyId, uint256 _foreignCallId) external policyAdminOnly(_policyId, msg.sender) {
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
    function updateForeignCall(uint256 _policyId, uint256 _foreignCallId, ForeignCall calldata _foreignCall) external policyAdminOnly(_policyId, msg.sender) returns (ForeignCall memory fc) {
        fc = _foreignCall;
        fc.foreignCallIndex = _foreignCallId;
        _storeForeignCall(_policyId, fc);
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
    function getAllForeignCalls(uint256 _policyId) public view returns (ForeignCall[] memory fc) {
        // Return the Foreign Call Set data from storage
        uint256 foreignCallCount = lib.getForeignCallStorage().foreignCallIdxCounter[_policyId];
        ForeignCall[] memory foreignCalls = new ForeignCall[](foreignCallCount);
        uint256 j = 0;
        for (uint256 i = 1; i <= foreignCallCount; i++) {
            if (lib.getForeignCallStorage().foreignCalls[_policyId][i].set) {
                foreignCalls[j] = lib.getForeignCallStorage().foreignCalls[_policyId][i];
                j++;
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
    ) public policyAdminOnly(_policyId, msg.sender) returns (uint256) {
        // Load the Tracker data from storage
        TrackerS storage data = lib.getTrackerStorage();
        uint256 trackerIndex = ++data.trackerIndexCounter[_policyId];
        _storeTracker(data, _policyId, trackerIndex, _tracker);
        data.trackerIndexCounter[_policyId] = trackerIndex;
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
    ) public policyAdminOnly(_policyId, msg.sender){
        // Load the Tracker data from storage
        TrackerS storage data = lib.getTrackerStorage();
        _storeTracker(data, _policyId, _trackerIndex, _tracker);
    }

    /**
     * Store a tracker in the trackerStorage.
     * @param _data the trackerStorage
     * @param _policyId the policyId the tracker is associated with
     * @param _trackerIndex the index of the tracker to store
     * @param _tracker the tracker to store
     */
    function _storeTracker(TrackerS storage _data, uint256 _policyId, uint256 _trackerIndex, Trackers memory _tracker) internal {
        _tracker.set = true;
        _data.trackers[_policyId][_trackerIndex] = _tracker;
    }

    /**
     * Return a tracker from the trackerStorage.
     * @param _policyId the policyId the trackerStorage is associated with
     * @param _index postion of the tracker to return
     * @return tracker
     */
    function getTracker(
        uint256 _policyId,
        uint256 _index
    ) public view returns (Trackers memory tracker) {
        // Load the Tracker data from storage
        TrackerS storage data = lib.getTrackerStorage();
        // return trackers for contract address at speficic index
        return data.trackers[_policyId][_index];
    }

    /**
     * Get all trackers from storage.
     * @param _policyId the policyId the trackers are associated with
     * @return trackers the trackers in the policy
     */
    function getAllTrackers(uint256 _policyId) public view returns (Trackers[] memory) {
        // Load the Tracker data from storage
        TrackerS storage data = lib.getTrackerStorage();
        // return trackers for contract address at speficic index
        uint256 trackerCount = data.trackerIndexCounter[_policyId];
        Trackers[] memory trackers = new Trackers[](trackerCount);
        uint256 j = 0;
        for (uint256 i = 1; i <= trackerCount; i++) {
            if (data.trackers[_policyId][i].set) {
                trackers[j] = data.trackers[_policyId][i];
                j++;
            }
        }
        return trackers;
    }

    /**
     * Delete a tracker from the trackerStorage.
     * @param _policyId the policyId the trackerStorage is associated with
     * @param _trackerIndex the index of the tracker to delete
     */
    function deleteTracker(uint256 _policyId, uint256 _trackerIndex) public policyAdminOnly(_policyId, msg.sender) {
        delete lib.getTrackerStorage().trackers[_policyId][_trackerIndex];
    }

    /// Function Signature Storage
    
    function createFunctionSignature(
        uint256 _policyId,
        bytes4 _functionSignature,
        PT[] memory _pTypes
    ) public policyAdminOnly(_policyId, msg.sender) returns (uint256) {
        FunctionSignatureS storage data = lib.getFunctionSignatureStorage();
        uint256 functionId = ++data.functionIdCounter[_policyId];
        data.functionSignatureStorageSets[_policyId][functionId].set = true;
        data.functionSignatureStorageSets[_policyId][functionId].signature = _functionSignature;
        data.functionSignatureStorageSets[_policyId][functionId].parameterTypes = _pTypes;      
        data.functionIdCounter[_policyId] = functionId;
        return functionId;
    }
    
    /**
     * Appends PTypes to an already existing function signature
     * @param _policyId the policyId the function signature is associated with
     * @param _functionSignatureId functionSignatureId
     * @param _functionSignature the string representation of the function signature
     * @param _pTypes the types of the parameters for the function in order
     * @return functionId generated function Id
     */
    function updateFunctionSignature(
        uint256 _policyId,
        uint256 _functionSignatureId,
        bytes4 _functionSignature,
        PT[] memory _pTypes
    ) public policyAdminOnly(_policyId, msg.sender) returns (uint256) {
        // Load the function signature data from storage
        FunctionSignatureS storage data = lib.getFunctionSignatureStorage();
        // increment the functionSignatureId if necessary
        FunctionSignatureStorageSet storage functionSignature = data.functionSignatureStorageSets[_policyId][_functionSignatureId];
        require(functionSignature.signature == _functionSignature, "Delete function signature before updating to a new one");
        require(functionSignature.parameterTypes.length <= _pTypes.length, "New parameter types must be of greater or equal length to the original");
        for (uint256 i = 0; i < functionSignature.parameterTypes.length; i++) {
            require(_pTypes[i] == functionSignature.parameterTypes[i], "New parameter types must be of the same type as the original");
        }
        if (functionSignature.parameterTypes.length < _pTypes.length) {
            for (uint256 i = functionSignature.parameterTypes.length; i < _pTypes.length; i++) {
                functionSignature.parameterTypes.push(_pTypes[i]);
            }
        }

        return _functionSignatureId;
    }

    /**
     * Delete a function signature from storage.
     * @param _policyId the policyId the functionSignatureId belongs to
     * @param _functionSignatureId the index of the functionSignature to delete
     */
    function deleteFunctionSignature(uint256 _policyId, uint256 _functionSignatureId) public policyAdminOnly(_policyId, msg.sender) {
        // retrieve policy from storage 
        PolicyStorageSet storage data = lib.getPolicyStorage().policyStorageSets[_policyId];
        // retrieve function signature to delete  
        bytes4 signature = lib.getFunctionSignatureStorage().functionSignatureStorageSets[_policyId][_functionSignatureId].signature;  

        // delete the function signature storage set struct 
        delete lib.getFunctionSignatureStorage().functionSignatureStorageSets[_policyId][_functionSignatureId];
        // delete signatures array from policy 
        delete data.policy.signatures;
        // delete function signature to id map 
        delete data.policy.functionSignatureIdMap[signature];
        // delete rule structures associated to function signature 
        for(uint256 i; i < data.policy.signatureToRuleIds[signature].length; i++) {
            // delete rules from storage 
            delete lib.getRuleStorage().ruleStorageSets[_policyId][i];
        }
        // delete function signature to rule Ids mapping  
        delete data.policy.signatureToRuleIds[signature];

        // retrieve remaining function signature structs from storage that were not removed   
        FunctionSignatureStorageSet[] memory functionSignatureStructs = getAllFunctionSignatures(_policyId);
        // reset signature array for policy
        for(uint256 j; j < functionSignatureStructs.length; j++) {
            if(functionSignatureStructs[j].set) {
                data.policy.signatures.push(functionSignatureStructs[j].signature);
            }
        }
    }

    /**
     * Get a function signature from storage.
     * @param _policyId the policyId the function signature is associated with
     * @param _functionSignatureId functionSignatureId
     * @return functionSignatureSet function signature
     */
    function getFunctionSignature(
        uint256 _policyId,
        uint256 _functionSignatureId
    ) public view returns (FunctionSignatureStorageSet memory) {
        // Load the function signature data from storage
        return
            lib.getFunctionSignatureStorage().functionSignatureStorageSets[_policyId][_functionSignatureId];
    }


    /**
     * Get all function signatures from storage.
     * @param _policyId the policyId the function signatures are associated with
     * @return functionSignatureStorageSets function signatures
     */
    function getAllFunctionSignatures(uint256 _policyId) public view returns (FunctionSignatureStorageSet[] memory) {
        // Load the function signature data from storage
        FunctionSignatureS storage data = lib.getFunctionSignatureStorage();
        uint256 functionIdCount = data.functionIdCounter[_policyId];
        FunctionSignatureStorageSet[] memory functionSignatureStorageSets = new FunctionSignatureStorageSet[](functionIdCount);
        uint256 j = 0;
        for (uint256 i = 1; i <= functionIdCount; i++) {
            if (data.functionSignatureStorageSets[_policyId][i].set) {
                functionSignatureStorageSets[j] = data.functionSignatureStorageSets[_policyId][i];
                j++;
            }
        }
        return functionSignatureStorageSets;
    }

    /**
     * Create a rule in storage.
     * @param _rule the rule to create
     * @return ruleId the generated ruleId
     */
    function createRule(uint256 _policyId, Rule calldata _rule) public policyAdminOnly(_policyId, msg.sender) returns (uint256) {
        RuleS storage data = lib.getRuleStorage();
        uint256 ruleId = ++data.ruleIdCounter[_policyId];
        _storeRule(data, _policyId, ruleId, _rule);
        data.ruleIdCounter[_policyId] = ruleId;
        return ruleId;
    }

    /**
     * Add a rule to storage.
     * @param _data the rule storage
     * @param _policyId the policyId the rule is associated with
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
     * @param _ruleId the id of the rule
     * @param _rule the rule to update
     * @return ruleId the generated ruleId
     */
    function updateRule(
        uint256 _policyId,
        uint256 _ruleId,
        Rule calldata _rule
    ) public policyAdminOnly(_policyId, msg.sender) returns (uint256) {
        // Load the function signature data from storage
        RuleS storage data = lib.getRuleStorage();

        _storeRule(data, _policyId, _ruleId, _rule);
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
    function getAllRules(uint256 _policyId) public view returns (Rule[][] memory) {
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

    /**
     * Delete a rule from storage.
     * @param _ruleId the id of the rule to delete
     */
    function deleteRule(uint256 _policyId, uint256 _ruleId) public policyAdminOnly(_policyId, msg.sender) {
        delete lib.getRuleStorage().ruleStorageSets[_policyId][_ruleId];
    }

    /// Policy Storage
    /**
     * Update a Policy in Storage
     * @param _policyId id of of the policy 
     * @param _signatures all signatures in the policy
     * @param _functionSignatureIds corresponding signature ids in the policy. The elements in this array are one to one matches of the elements in _signatures array. They store the functionSignatureId for each of the signatures in _signatures array.
     * @param _ruleIds two dimensional array of the rules. This array contains a simple count at first level and the second level is the array of ruleId's within the policy.
     * @return policyId generated policyId
     * @dev The parameters had to be complex because nested structs are not allowed for externally facing functions
     */
    function updatePolicy(uint256 _policyId, bytes4[] calldata _signatures, uint256[] calldata _functionSignatureIds, uint256[][] calldata _ruleIds) public policyAdminOnly(_policyId, msg.sender) returns(uint256){
        // signature length must match the signature id length
        if (_signatures.length != _functionSignatureIds.length) revert("Signatures and signature id's are inconsistent"); 
        // if policy ID is zero no policy has been created and cannot be updated. 
        if (_policyId == 0) revert("Policy ID cannot be 0. Create policy before updating");
        return _storePolicyData(_policyId, _signatures, _functionSignatureIds, _ruleIds);
    }

    /**
     * Delete a Policy from Storage
     * @param _policyId the id of the policy to delete
     */
    function deletePolicy(uint256 _policyId) public policyAdminOnly(_policyId, msg.sender) {
        PolicyStorageSet storage data = lib.getPolicyStorage().policyStorageSets[_policyId];
        delete data.set;

        for (uint256 i = 0; i < data.policy.signatures.length; i++) {
            delete data.policy.functionSignatureIdMap[data.policy.signatures[i]];
            delete data.policy.signatureToRuleIds[data.policy.signatures[i]];
        }
    }


    /**
     * Add a Policy to Storage and create the policy admin for the policy 
     * @param _functionSignatures corresponding signature ids in the policy. The elements in this array are one to one matches of the elements in _signatures array. They store the functionSignatureId for each of the signatures in _signatures array.
     * @param _rules two dimensional array of the rules. This array contains a simple count at first level and the second level is the array of ruleId's within the policy.
     * @return policyId generated policyId
     * @dev The parameters had to be complex because nested structs are not allowed for externally facing functions
     */
    function createPolicy(FunctionSignatureStorageSet[] calldata _functionSignatures, Rule[] calldata _rules) public returns(uint256) {
        // retrieve Policy Storage 
        PolicyS storage data = lib.getPolicyStorage();
        uint256 policyId = data.policyId; 
        // If this is the first policy created increment by 1 to start id counter. 
        unchecked{
            ++data.policyId;
        }
        policyId = data.policyId;
        data.policyStorageSets[policyId].set = true;
        //This function is called as an external call intentionally. This allows for proper gating on the generatePolicyAdminRole fn to only be callable by the RulesEngine address. 
        RulesEngineAdminRolesFacet(address(this)).generatePolicyAdminRole(policyId, address(msg.sender));
        //TODO remove this when create policy is atomic 
        // Temporarily disabling _storePolicyData
        // return _storePolicyData(policyId, _functionSignatures, _rules);
        _functionSignatures;
        _rules;
        return policyId;
    }

    /**
     * @dev internal helper function for create and update policy functions  
     * @param _policyId id of of the policy 
     * @param _signatures all signatures in the policy
     * @param _functionSignatureIds corresponding signature ids in the policy. The elements in this array are one to one matches of the elements in _signatures array. They store the functionSignatureId for each of the signatures in _signatures array.
     * @param _ruleIds two dimensional array of the rules. This array contains a simple count at first level and the second level is the array of ruleId's within the policy.
     * @return policyId updated policyId 
     * @dev The parameters had to be complex because nested structs are not allowed for externally facing functions
     */
    function _storePolicyData(uint256 _policyId, bytes4[] calldata _signatures, uint256[] calldata _functionSignatureIds, uint256[][] calldata _ruleIds) internal returns(uint256){   
        // Load the policy data from storage
        PolicyS storage data = lib.getPolicyStorage();
        // clear the iterator array
        delete data.policyStorageSets[_policyId].policy.signatures;
        if (_ruleIds.length > 0) {
            // Loop through all the passed in signatures for the policy      
            for (uint256 i = 0; i < _signatures.length; i++) {
                // make sure that all the function signatures exist
                if(!getFunctionSignature(_policyId, _functionSignatureIds[i]).set) revert("Invalid Signature");
                // Load into the mapping
                data.policyStorageSets[_policyId].policy.functionSignatureIdMap[_signatures[i]] = _functionSignatureIds[i];
                // load the iterator array
                data.policyStorageSets[_policyId].policy.signatures.push(_signatures[i]);
                // make sure that all the rules attached to each function signature exist
                for (uint256 j = 0; j < _ruleIds[i].length; j++) {
                    RuleStorageSet memory ruleStore = getRule(_policyId, _ruleIds[i][j]);
                    if(!ruleStore.set) revert("Invalid Rule");
                    for (uint256 k = 0; k < ruleStore.rule.placeHolders.length; k++) {
                        if(ruleStore.rule.placeHolders[k].foreignCall) {
                            // get the foreign call using the type specific index which will be interpreted as a foreign call index since it has foreignCall bool set
                            require(getForeignCall(_policyId, ruleStore.rule.placeHolders[k].typeSpecificIndex).set, "Foreign Call referenced in rule not set");
                        } else if (ruleStore.rule.placeHolders[k].trackerValue) {
                            require(getTracker(_policyId, ruleStore.rule.placeHolders[k].typeSpecificIndex).set, "Tracker referenced in rule not set");
                        }

                    }
                    data.policyStorageSets[_policyId].policy.signatureToRuleIds[_signatures[i]].push(_ruleIds[i][j]);
                }
                
            }
        } else {
            // Solely loop through and add signatures to the policy
            for (uint256 i = 0; i < _signatures.length; i++) {
                // make sure that all the function signatures exist
                if(!getFunctionSignature(_policyId, _functionSignatureIds[i]).set) revert("Invalid Signature");
                // Load into the mapping
                data.policyStorageSets[_policyId].policy.functionSignatureIdMap[_signatures[i]] = _functionSignatureIds[i];
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
    function applyPolicy(address _contractAddress, uint256[] calldata _policyId) public policyAdminOnly(_policyId[0], msg.sender) {
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
