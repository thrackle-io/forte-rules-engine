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

    /**
     * @dev Builds a foreign call structure and adds it to the contracts storage, mapped to the contract address it is associated with
     * @param _policyId the policy Id of the policy the foreign call will be mapped to
     * @param foreignContractAddress the address of the contract where the foreign call exists
     * @param functionSignature the string representation of the function signature of the foreign call
     * @param returnType the parameter type of the foreign calls return value
     * @param arguments the parameter types of the foreign calls arguments in order
     * @return fc the foreign call structure
     */
    function updateForeignCall(
        uint256 _policyId,
        address foreignContractAddress,
        string memory functionSignature,
        PT returnType,
        PT[] memory arguments,
        uint8[] memory typeSpecificIndices
    ) public returns (ForeignCall memory fc) {
        // Load the Foreign Call data from storage
        ForeignCallS storage data = lib.getForeignCallStorage();
        fc.foreignCallAddress = foreignContractAddress;
        // Convert the string representation of the function signature to a selector
        fc.signature = bytes4(keccak256(bytes(functionSignature)));
        fc.foreignCallIndex = data.foreignCallIndex;
        data.foreignCallIndex++;
        fc.returnType = returnType;
        assert(arguments.length == typeSpecificIndices.length);
        fc.parameterTypes = new PT[](arguments.length);
        fc.typeSpecificIndices = new uint8[](arguments.length);
        for (uint256 i = 0; i < arguments.length; i++) {
            fc.parameterTypes[i] = arguments[i];
            fc.typeSpecificIndices[i] = typeSpecificIndices[i];
        }

        // If the foreign call structure already exists in the mapping update it, otherwise add it
        data.foreignCallSets[_policyId].foreignCalls.push(fc);
        data.foreignCallSets[_policyId].set = true;
    }

    /**
     * @dev Builds a foreign call structure and adds it to the contracts storage, mapped to the contract address it is associated with
     * @param _policyId the policy Id of the foreign call to retrieve
     * @param _foreignCallId the Id of the foreign call to retrieve
     * @return fc the foreign call structure
     */
    function getForeignCall(
        uint256 _policyId,
        uint256 _foreignCallId
    ) public view returns (ForeignCall memory fc) {
        // Load the Foreign Call data from storage
        ForeignCallS storage data = lib.getForeignCallStorage();
        ForeignCall[] memory foreignCalls = data
            .foreignCallSets[_policyId]
            .foreignCalls;
        for (uint256 i = 0; i < foreignCalls.length; i++) {
            if (foreignCalls[i].foreignCallIndex == _foreignCallId)
                return foreignCalls[i];
        }
    }

    /**
     * @dev Builds a foreign call structure and adds it to the contracts storage, mapped to the contract address it is associated with
     * @param _policyId the policy Id of the foreign call to retrieve
     * @return fc the foreign call set structure
     */
    function getForeignCall(uint256 _policyId) public view returns (ForeignCallSet memory fc) {
        // Return the Foreign Call Set data from storage
        return lib.getForeignCallStorage().foreignCallSets[_policyId];
    }

    /// Tracker Storage
    /**
     * Add a tracker to the trackerStorage mapping.
     * @param _policyId the policyId the trackerStorage is associated with
     * @param tracker the tracker to add
     * @return trackerIndex the index of the tracker
     */
    function addTracker(
        uint256 _policyId,
        Trackers calldata tracker
    ) public returns (uint256) {
        // Load the Tracker data from storage
        TrackerS storage data = lib.getTrackerStorage();
        data.trackerValueSets[_policyId].set = true;
        data.trackerValueSets[_policyId].trackers.push(tracker);
        return data.trackerValueSets[_policyId].trackers.length;
    }

    /**
     * Function to update tracker in trackerStorage mapping.
     * @param _policyId the policyId the trackerStorage is associated with
     * @param updatedUintTracker uint256 tracker update
     * @param updatedAddressTracker address tracker update
     * @param updatedStringTracker string tracker update
     * @param updatedBoolTracker bool tracker update
     * @param updatedBytesTracker bytes tracker update
     */
    function updateTracker(
        uint256 _policyId,
        uint256 updatedUintTracker,
        address updatedAddressTracker,
        string memory updatedStringTracker,
        bool updatedBoolTracker,
        bytes memory updatedBytesTracker
    ) public {
        // Load the Tracker data from storage
        TrackerS storage data = lib.getTrackerStorage();
        data.trackerValueSets[_policyId].set = true;
        for (
            uint256 i = 0;
            i < data.trackerValueSets[_policyId].trackers.length;
            i++
        ) {
            if (data.trackerValueSets[_policyId].trackers[i].pType == PT.UINT)
                data.trackerValueSets[_policyId].trackers[i].trackerValue = abi
                    .encode(updatedUintTracker);
            else if (
                data.trackerValueSets[_policyId].trackers[i].pType == PT.ADDR
            )
                data.trackerValueSets[_policyId].trackers[i].trackerValue = abi
                    .encode(updatedAddressTracker);
            else if (
                data.trackerValueSets[_policyId].trackers[i].pType == PT.STR
            )
                data.trackerValueSets[_policyId].trackers[i].trackerValue = abi
                    .encode(updatedStringTracker);
            else if (
                data.trackerValueSets[_policyId].trackers[i].pType == PT.BOOL
            )
                data.trackerValueSets[_policyId].trackers[i].trackerValue = abi
                    .encode(updatedBoolTracker);
            else if (
                data.trackerValueSets[_policyId].trackers[i].pType == PT.BYTES
            )
                data.trackerValueSets[_policyId].trackers[i].trackerValue = abi
                    .encode(updatedBytesTracker);
        }
    }

    /**
     * Return a tracker from the trackerStorage.
     * @param _policyId the policyId the trackerStorage is associated with
     * @param index postion of the tracker to return
     * @return trackers
     */
    function getTracker(
        uint256 _policyId,
        uint256 index
    ) public returns (Trackers memory trackers) {
        // Load the Tracker data from storage
        TrackerS storage data = lib.getTrackerStorage();
        data.trackerValueSets[_policyId].set = true;
        // return trackers for contract address at speficic index
        return data.trackerValueSets[_policyId].trackers[index - 1];
    }

    /**
     * Return a TrackerValuesSet from the trackerStorage.
     * @param _policyId the policyId the trackerStorage is associated with
     * @return trackerValuesSet
     */
    function getTracker(uint256 _policyId) public view returns (TrackerValuesSet memory trackerValuesSet) {
        // return the TrackerValuesSet data from storage
        return lib.getTrackerStorage().trackerValueSets[_policyId];
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

    /// Rule Storage
    /**
     * Add a rule to the ruleStorage mapping.
     * @param _ruleId the id of the rule
     * @param rule the rule to add
     * @return ruleId the generated ruleId
     */
    function updateRule(
        uint256 _ruleId,
        Rule calldata rule
    ) public returns (uint256) {
        // TODO: Add validations for rule
        // Load the function signature data from storage
        RuleS storage data = lib.getRuleStorage();
        // increment the ruleId if necessary
        if (_ruleId == 0) {
            unchecked {
                ++data.ruleId;
            }
            _ruleId = data.ruleId;
        }
        data.ruleStorageSets[_ruleId].set = true;
        data.ruleStorageSets[_ruleId].rule = rule;
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

    /// Policy Storage
    /**
     * Add a Policy to Storage
     * @param _policyId id of of the policy 
     * @param _signatures all signatures in the policy
     * @param functionSignatureIds corresponding signature ids in the policy. The elements in this array are one to one matches of the elements in _signatures array. They store the functionSignatureId for each of the signatures in _signatures array.
     * @param ruleIds two dimensional array of the rules. This array contains a simple count at first level and the second level is the array of ruleId's within the policy.
     * @return policyId generated policyId
     * @dev The parameters had to be complex because nested structs are not allowed for externally facing functions
     */
    function updatePolicy(uint256 _policyId, bytes4[] calldata _signatures, uint256[] calldata functionSignatureIds, uint256[][] calldata ruleIds) public returns(uint256){
        // Load the policy data from storage
        PolicyS storage data = lib.getPolicyStorage();
        // signature length must match the signature id length
        if (_signatures.length != functionSignatureIds.length) revert("Signatures and signature id's are inconsistent"); 
        // increment the policyId if necessary
        if (_policyId == 0) {
            unchecked{
                ++data.policyId;
            }
            _policyId = data.policyId;
            data.policyStorageSets[_policyId].set = true;
        }
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
                            require(getForeignCall(_policyId).set, "Foreign Call referenced in rule not set");
                        } else if (ruleStore.rule.placeHolders[k].trackerValue) {
                            require(getTracker(_policyId).set, "Tracker referenced in rule not set");
                        }
                    }
                }
                data.policyStorageSets[_policyId].policy.signatureToRuleIds[_signatures[i]] = ruleIds[i];
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
     * Add a Policy to Storage and create the policy admin for the policy 
     * @param _policyId id of of the policy 
     * @param _signatures all signatures in the policy
     * @param functionSignatureIds corresponding signature ids in the policy. The elements in this array are one to one matches of the elements in _signatures array. They store the functionSignatureId for each of the signatures in _signatures array.
     * @param ruleIds two dimensional array of the rules. This array contains a simple count at first level and the second level is the array of ruleId's within the policy.
     * @return policyId generated policyId
     * @dev The parameters had to be complex because nested structs are not allowed for externally facing functions
     */
    function createPolicy(uint256 _policyId, bytes4[] calldata _signatures, uint256[] calldata functionSignatureIds, uint256[][] calldata ruleIds) public returns(uint256) {
        uint256 policyId = updatePolicy(_policyId, _signatures, functionSignatureIds, ruleIds);
        //This function is called as an external call intentionally. This allows for proper gating on the generatePolicyAdminRole fn to only be callable by the RulesEngine address. 
        RulesEngineAdminRolesFacet(address(this)).generatePolicyAdminRole(policyId, address(msg.sender));

        return policyId; 
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
        // Loop through the function signatures and load the return arrays
        for (uint256 i = 0; i < policy.signatures.length; i++) {
            functionSigs[i] = policy.signatures[i];
            functionSigIds[i] = policy.functionSignatureIdMap[policy.signatures[i]];
            // Initialize the ruleId return array if necessary
            if(policy.signatureToRuleIds[policy.signatures[i]].length >0 && policy.signatureToRuleIds[policy.signatures[i]][0]> 0){
                ruleIds[i] = new uint256[](policy.signatureToRuleIds[policy.signatures[i]].length);
            } 
            for (uint256 ruleIndex; ruleIndex < policy.signatureToRuleIds[policy.signatures[i]].length; ruleIndex++) {
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
