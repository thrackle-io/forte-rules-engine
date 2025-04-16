// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetCommonImports.sol";
import "src/engine/facets/RulesEngineAdminRolesFacet.sol";

/**
 * @title Rules Engine Component Facet
 * @author @ShaneDuncan602 
 * @dev This contract serves as the data facet for the rules engine subcomponents. 
 * @notice Data facet for the Rules Engine
 */
contract RulesEngineComponentFacet is FacetCommonImports {

    
    /**
     * @dev Builds a foreign call structure and adds it to the contracts storage, mapped to the contract address it is associated with
     * @param _policyId the policy Id of the policy the foreign call will be mapped to
     * @param _foreignCall The definition of the foreign call to create
     **/
    function createForeignCall(
        uint256 _policyId, 
        ForeignCall calldata _foreignCall
    ) external policyAdminOnly(_policyId, msg.sender) notCemented(_policyId) returns (uint256) {
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
        require(_foreignCall.foreignCallIndex < MAX_LOOP, "Max foreign calls reached.");
        require(_foreignCall.parameterTypes.length < MAX_LOOP, "Max foreign parameter types reached.");
        _foreignCall.set = true;
        lib.getForeignCallStorage().foreignCalls[_policyId][_foreignCall.foreignCallIndex] = _foreignCall;
    }

    /**
     * @dev Deletes a foreign call from storage
     * @param _policyId the policyId the foreign call is associated with
     * @param _foreignCallId the foreign call to delete
     */
    function deleteForeignCall(uint256 _policyId, uint256 _foreignCallId) external policyAdminOnly(_policyId, msg.sender) notCemented(_policyId){
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
    function updateForeignCall(uint256 _policyId, uint256 _foreignCallId, ForeignCall calldata _foreignCall) external policyAdminOnly(_policyId, msg.sender) notCemented(_policyId) returns (ForeignCall memory fc) {
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
    function getAllForeignCalls(uint256 _policyId) external view returns (ForeignCall[] memory fc) {
        // Return the Foreign Call Set data from storage
        uint256 foreignCallCount = lib.getForeignCallStorage().foreignCallIdxCounter[_policyId];
        ForeignCall[] memory foreignCalls = new ForeignCall[](foreignCallCount);
        uint256 j = 0;
        for (uint256 i = 0; i <= foreignCallCount; i++) {
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
    ) external policyAdminOnly(_policyId, msg.sender) notCemented(_policyId) returns (uint256) {
        // Load the Tracker data from storage
        TrackerS storage data = lib.getTrackerStorage();
        uint256 trackerIndex = ++data.trackerIndexCounter[_policyId];
        _storeTracker(data, _policyId, trackerIndex, _tracker);
        data.trackerIndexCounter[_policyId] = trackerIndex;
        emit TrackerCreated(_policyId, trackerIndex); 
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
    ) external policyAdminOnly(_policyId, msg.sender) {
        // Load the Tracker data from storage
        TrackerS storage data = lib.getTrackerStorage();
        _storeTracker(data, _policyId, _trackerIndex, _tracker);
        emit TrackerUpdated(_policyId, _trackerIndex); 
    }

    /**
     * Store a tracker in the trackerStorage.
     * @param _data the trackerStorage
     * @param _policyId the policyId the tracker is associated with
     * @param _trackerIndex the index of the tracker to store
     * @param _tracker the tracker to store
     */
    function _storeTracker(TrackerS storage _data, uint256 _policyId, uint256 _trackerIndex, Trackers memory _tracker) internal {
        require(_trackerIndex < MAX_LOOP, "Max trackers reached.");
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
    function getAllTrackers(uint256 _policyId) external view returns (Trackers[] memory) {
        // Load the Tracker data from storage
        TrackerS storage data = lib.getTrackerStorage();
        // return trackers for contract address at speficic index
        uint256 trackerCount = data.trackerIndexCounter[_policyId];
        Trackers[] memory trackers = new Trackers[](trackerCount);
        uint256 j = 0;
        // Loop through all the tracker and load for return. Data entry validation will never let trackerCount be > MAX_LOOP
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
    function deleteTracker(uint256 _policyId, uint256 _trackerIndex) external policyAdminOnly(_policyId, msg.sender) notCemented(_policyId){
        delete lib.getTrackerStorage().trackers[_policyId][_trackerIndex];
        emit TrackerDeleted(_policyId, _trackerIndex); 
    }

    /// Function Signature Storage
    
    function createFunctionSignature(
        uint256 _policyId,
        bytes4 _functionSignature,
        PT[] memory _pTypes
    ) external policyAdminOnly(_policyId, msg.sender) notCemented(_policyId) returns (uint256) {
        FunctionSignatureS storage data = lib.getFunctionSignatureStorage();
        uint256 functionId = ++data.functionIdCounter[_policyId];
        require(functionId < MAX_LOOP, "Max function signatures reached.");
        data.functionSignatureStorageSets[_policyId][functionId].set = true;
        data.functionSignatureStorageSets[_policyId][functionId].signature = _functionSignature;
        data.functionSignatureStorageSets[_policyId][functionId].parameterTypes = _pTypes;      
        data.functionIdCounter[_policyId] = functionId;
        emit FunctionSignatureCreated(_policyId, functionId);
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
    ) external policyAdminOnly(_policyId, msg.sender) notCemented(_policyId) returns (uint256) {
        // Load the function signature data from storage
        FunctionSignatureS storage data = lib.getFunctionSignatureStorage();
        // increment the functionSignatureId if necessary
        FunctionSignatureStorageSet storage functionSignature = data.functionSignatureStorageSets[_policyId][_functionSignatureId];
        require(functionSignature.signature == _functionSignature, "Delete function signature before updating to a new one");
        require(functionSignature.parameterTypes.length <= _pTypes.length, "New parameter types must be of greater or equal length to the original");
        // Data entry validation will never let functionSignature.parameterTypes.length be > MAX_LOOP
        for (uint256 i = 0; i < functionSignature.parameterTypes.length; i++) {
            require(_pTypes[i] == functionSignature.parameterTypes[i], "New parameter types must be of the same type as the original");
        }
        require(_pTypes.length < MAX_LOOP, "Max function signatures reached.");
        if (functionSignature.parameterTypes.length < _pTypes.length) {
            for (uint256 i = functionSignature.parameterTypes.length; i < _pTypes.length; i++) {
                functionSignature.parameterTypes.push(_pTypes[i]);
            }
        }
        emit FunctionSignatureUpdated(_policyId, _functionSignatureId);
        return _functionSignatureId;
    }

    /**
     * Delete a function signature from storage.
     * @param _policyId the policyId the functionSignatureId belongs to
     * @param _functionSignatureId the index of the functionSignature to delete
     */
    function deleteFunctionSignature(uint256 _policyId, uint256 _functionSignatureId) external policyAdminOnly(_policyId, msg.sender) notCemented(_policyId){
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
            emit AssociatedRuleDeleted(_policyId, _functionSignatureId);
        }
        // delete function signature to rule Ids mapping  
        delete data.policy.signatureToRuleIds[signature];
        // retrieve remaining function signature structs from storage that were not removed   
        FunctionSignatureStorageSet[] memory functionSignatureStructs = getAllFunctionSignatures(_policyId);
        // reset signature array for policy. FunctionSignatureStructs length will always be 0 or less than MAX_LOOP 
        for(uint256 j; j < functionSignatureStructs.length; j++) {
            if(functionSignatureStructs[j].set) {
                data.policy.signatures.push(functionSignatureStructs[j].signature);
            }
        }
        emit FunctionSignatureDeleted(_policyId, _functionSignatureId);
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
        // Data validation will alway ensure functionIdCount will be less than MAX_LOOP
        for (uint256 i = 1; i <= functionIdCount; i++) {
            if (data.functionSignatureStorageSets[_policyId][i].set) {
                functionSignatureStorageSets[j] = data.functionSignatureStorageSets[_policyId][i];
                j++;
            }
        }
        return functionSignatureStorageSets;
    }

    /**
     * Function to add an address to subscriber list to specified policy
     * @param _policyId policyId
     * @param _subscriber address to add to policy subscription 
     */
    function addClosedPolicySubscriber(uint256 _policyId, address _subscriber) external policyAdminOnly(_policyId, msg.sender) notCemented(_policyId){
        lib.getPolicyStorage().policyStorageSets[_policyId].policy.closedPolicySubscribers[_subscriber] = true;
        emit PolicySubsciberAdded(_policyId, _subscriber);
    }

    /**
     * Function to check if an address is a subscriber of the specified policy
     * @param _policyId policyId
     * @param _subscriber address to check policy subscription 
     */
    function isClosedPolicySubscriber(uint256 _policyId, address _subscriber) external view returns (bool) {
        return lib.getPolicyStorage().policyStorageSets[_policyId].policy.closedPolicySubscribers[_subscriber];
    }

    /**
     * Function to remove an address from subscriber list of specified policy
     * @param _policyId policyId
     * @param _subscriber address to remove from policy subscription 
     */
    function removeClosedPolicySubscriber(uint256 _policyId, address _subscriber) external policyAdminOnly(_policyId, msg.sender) notCemented(_policyId){
        delete lib.getPolicyStorage().policyStorageSets[_policyId].policy.closedPolicySubscribers[_subscriber];
        emit PolicySubsciberRemoved(_policyId, _subscriber);
    }


    function isCemented(uint256 _policyId) public view returns(bool _cemented){
        return lib.getPolicyStorage().policyStorageSets[_policyId].policy.cemented;
     }

     /**
     * @dev This is the modifier used to ensure that cemented policies can't be changed.
     * @param _policyId policyId
     */
    modifier notCemented(uint256 _policyId) {
        if(isCemented(_policyId)) revert ("Not allowed for cemented policy");
        _;
    }
    
}
