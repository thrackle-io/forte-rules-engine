// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetCommonImports.sol";
import "src/engine/facets/RulesEngineAdminRolesFacet.sol";

/**
 * @title Rules Engine Component Facet
 * @dev This contract serves as the data facet for the Rules Engine subcomponents. It provides functionality for managing
 *      foreign calls, trackers, calling functions, and policy subscriptions. It enforces role-based access control
 *      and ensures that only authorized users can modify or retrieve data. The contract also supports policy cementing
 *      to prevent further modifications.
 * @notice This contract is a critical component of the Rules Engine, enabling secure and flexible data management.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract RulesEngineComponentFacet is FacetCommonImports {
    
    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Foreign Call Management
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Creates a foreign call and stores it in the contract's storage.
     * @dev Builds a foreign call structure and maps it to the associated policy ID.
     * @param _policyId The policy ID the foreign call will be mapped to.
     * @param _foreignCall The definition of the foreign call to create.
     * @return The index of the created foreign call.
     */
    function createForeignCall(
        uint256 _policyId, 
        ForeignCall calldata _foreignCall, string calldata foreignCallName
    ) external policyAdminOnly(_policyId, msg.sender) returns (uint256) {
        _notCemented(_policyId);
        if (_foreignCall.foreignCallAddress == address(0)) revert(ZERO_ADDRESS);

        // Step 1: Generate the foreign call index
        uint256 foreignCallIndex = _incrementForeignCallIndex(_policyId);

        // Step 2: Store the foreign call
        _storeForeignCallData(_policyId, _foreignCall, foreignCallIndex);

        // Step 3: Store metadata
        _storeForeignCallMetadata(_policyId, foreignCallIndex, foreignCallName);

        emit ForeignCallCreated(_policyId, foreignCallIndex);
        return foreignCallIndex;
    }

    /**
     * @notice Updates a foreign call in the contract's storage.
     * @param policyId The policy ID the foreign call is associated with.
     * @param foreignCallId The ID of the foreign call to update.
     * @param foreignCall The updated foreign call structure.
     * @return fc The updated foreign call structure.
     */
    function updateForeignCall(uint256 policyId, uint256 foreignCallId, ForeignCall calldata foreignCall) external policyAdminOnly(policyId, msg.sender) returns (ForeignCall memory fc) {
        _notCemented(policyId);
        fc = foreignCall;
        if (fc.foreignCallAddress == address(0)) revert(ZERO_ADDRESS);
        fc.foreignCallIndex = foreignCallId;
        _storeForeignCallData(policyId, foreignCall, foreignCallId);
        emit ForeignCallUpdated(policyId, foreignCallId);
        return fc;
    }

    /**
     * @notice Deletes a foreign call from the contract's storage.
     * @param policyId The policy ID the foreign call is associated with.
     * @param foreignCallId The ID of the foreign call to delete.
     */
    function deleteForeignCall(uint256 policyId, uint256 foreignCallId) external policyAdminOnly(policyId, msg.sender) {
        _notCemented(policyId);
        delete lib.getForeignCallStorage().foreignCalls[policyId][foreignCallId];
        emit ForeignCallDeleted(policyId, foreignCallId);
    }

    /**
     * @dev Retrieve Foreign Call Set from storage 
     * @param policyId the policy Id of the foreign call to retrieve
     * @return fc the foreign call set structure
     */
    function getAllForeignCalls(uint256 policyId) external view returns (ForeignCall[] memory fc) {
        // Return the Foreign Call Set data from storage
        uint256 foreignCallCount = lib.getForeignCallStorage().foreignCallIdxCounter[policyId];
        ForeignCall[] memory foreignCalls = new ForeignCall[](foreignCallCount);
        uint256 j = 0;
        for (uint256 i = 0; i <= foreignCallCount; i++) {
            if (lib.getForeignCallStorage().foreignCalls[policyId][i].set) {
                foreignCalls[j] = lib.getForeignCallStorage().foreignCalls[policyId][i];
                j++;
            }
        }
        return foreignCalls;
    }

    /**
     * @notice Retrieves a foreign call from the contract's storage.
     * @param policyId The policy ID of the foreign call to retrieve.
     * @param foreignCallId The ID of the foreign call to retrieve.
     * @return fc The foreign call structure.
     */
    function getForeignCall(
        uint256 policyId,
        uint256 foreignCallId
    ) public view returns (ForeignCall memory fc) {
        // Load the Foreign Call data from storage
        return lib.getForeignCallStorage().foreignCalls[policyId][foreignCallId];
    }

    /**
     * @notice retrieves the foreign call metadata
     * @param policyId The policy ID the foreign call is associated with.
     * @param foreignCallId The identifier for the foreign call
     * @return fcMeta the metadata for the foreign call
     */
    function getForeignCallMetadata(
        uint256 policyId,
        uint256 foreignCallId
    ) public view returns (string memory fcMeta) {
        return lib.getForeignCallMetadataStorage().foreignCallMetadata[policyId][foreignCallId];
    }

    /**
     * @notice Stores a foreign call in the contract's storage.
     * @dev Ensures the foreign call is properly set before storing it.
     * @param _policyId The policy ID the foreign call is associated with.
     * @param _foreignCall The foreign call to store.
     */
    function _storeForeignCall(uint256 _policyId, ForeignCall memory _foreignCall) internal {
        assert(_foreignCall.parameterTypes.length == _foreignCall.typeSpecificIndices.length);
        _foreignCall.set = true;
        lib.getForeignCallStorage().foreignCalls[_policyId][_foreignCall.foreignCallIndex] = _foreignCall;
    }

    /** 
     * @dev Helper function to increment the foreign call index
     * @dev Ensures the foreign call is properly set before storing it.
     * @param _policyId The policy ID the foreign call is associated with.
     */
    function _incrementForeignCallIndex(uint256 _policyId) private returns (uint256) {
        ForeignCallStorage storage data = lib.getForeignCallStorage();
        return ++data.foreignCallIdxCounter[_policyId];
    }

    /** 
     * @dev Helper function to store the foreign call data
     * @dev Ensures the foreign call is properly set before storing it.
     * @param _policyId The policy ID the foreign call is associated with.
     * @param _foreignCall The foreign call to store.
     * @param _foreignCallIndex The index of the foreign call.
     */
    function _storeForeignCallData(
        uint256 _policyId,
        ForeignCall calldata _foreignCall,
        uint256 _foreignCallIndex
    ) private {
        ForeignCallStorage storage data = lib.getForeignCallStorage();
        ForeignCall memory fc = _foreignCall;
        fc.foreignCallIndex = _foreignCallIndex;
        _storeForeignCall(_policyId, fc);
        data.foreignCallIdxCounter[_policyId] = _foreignCallIndex;
    }

    /**
     * @dev Helper function to store the foreign call metadata
     * @param _policyId The policy ID the foreign call is associated with.
     * @param _foreignCallIndex The index of the foreign call.
     * @param _foreignCallName The name of the foreign call.
     */
    function _storeForeignCallMetadata(
        uint256 _policyId,
        uint256 _foreignCallIndex,
        string calldata _foreignCallName
    ) private {
        lib.getForeignCallMetadataStorage().foreignCallMetadata[_policyId][_foreignCallIndex] = _foreignCallName;
    }

    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Tracker Management
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Adds a tracker to the tracker storage mapping.
     * @dev Creates a new tracker and associates it with the specified policy ID.
     * @param policyId The policy ID the tracker is associated with.
     * @param tracker The tracker to add.
     * @return trackerIndex The index of the created tracker.
     */
    function createTracker(
        uint256 policyId,
        Trackers calldata tracker,
        string calldata trackerName
    ) external policyAdminOnly(policyId, msg.sender) returns (uint256) {
        _notCemented(policyId);
        // Step 1: Increment tracker index
        uint256 trackerIndex = _incrementTrackerIndex(policyId);
        // Step 2: Store tracker data
        _storeTrackerData(policyId, trackerIndex, tracker);
        // Step 3: Store tracker metadata
        _storeTrackerMetadata(policyId, trackerIndex, trackerName);
        // Emit event
        emit TrackerCreated(policyId, trackerIndex);

        return trackerIndex;
    }

    /**
     * @notice Updates an existing tracker in the tracker storage mapping.
     * @dev Modifies the tracker associated with the specified policy ID and tracker index.
     * @param policyId The policy ID the tracker is associated with.
     * @param trackerIndex The index of the tracker to update.
     * @param tracker The updated tracker data.
     */
    function updateTracker(
        uint256 policyId,
        uint256 trackerIndex,
        Trackers calldata tracker
    ) external policyAdminOnly(policyId, msg.sender) {
        // Load the Tracker data from storage
        TrackerStorage storage data = lib.getTrackerStorage();
        _storeTracker(data, policyId, trackerIndex, tracker);
        emit TrackerUpdated(policyId, trackerIndex); 
    }

    /**
     * @notice Deletes a tracker from the tracker storage mapping.
     * @param policyId The policy ID the tracker is associated with.
     * @param trackerIndex The index of the tracker to delete.
     */
    function deleteTracker(uint256 policyId, uint256 trackerIndex) external policyAdminOnly(policyId, msg.sender) {
        _notCemented(policyId);
        delete lib.getTrackerStorage().trackers[policyId][trackerIndex];
        emit TrackerDeleted(policyId, trackerIndex); 
    }

    /**
     * @notice Retrieves all trackers associated with a specific policy ID.
     * @param policyId The policy ID the trackers are associated with.
     * @return trackers An array of tracker data.
     */
    function getAllTrackers(uint256 policyId) external view returns (Trackers[] memory) {
        // Load the Tracker data from storage
        TrackerStorage storage data = lib.getTrackerStorage();
        // return trackers for contract address at speficic index
        uint256 trackerCount = data.trackerIndexCounter[policyId];
        Trackers[] memory trackers = new Trackers[](trackerCount);
        uint256 j = 0;
        for (uint256 i = 1; i <= trackerCount; i++) {
            if (data.trackers[policyId][i].set) {
                trackers[j] = data.trackers[policyId][i];
                j++;
            }
        }
        return trackers;
    }

    /**
     * @notice retrieves the tracker metadata
     * @param policyId The policy ID the tracker is associated with.
     * @param trackerId The identifier for the tracker
     * @return trMeta the metadata for the tracker
     */
    function getTrackerMetadata(
        uint256 policyId,
        uint256 trackerId
    ) public view returns (string memory trMeta) {
        return lib.getTrackerMetadataStorage().trackerMetadata[policyId][trackerId];
    }

    /**
     * @notice Retrieves a tracker from the tracker storage mapping.
     * @param policyId The policy ID the tracker is associated with.
     * @param index The index of the tracker to retrieve.
     * @return tracker The tracker data.
     */
    function getTracker(
        uint256 policyId,
        uint256 index
    ) public view returns (Trackers memory tracker) {
        // Load the Tracker data from storage
        TrackerStorage storage data = lib.getTrackerStorage();
        // return trackers for contract address at speficic index
        return data.trackers[policyId][index];
    }

    /**
     * @notice Stores a tracker in the tracker storage mapping.
     * @dev Sets the tracker data and marks it as active.
     * @param _data The tracker storage structure.
     * @param _policyId The policy ID the tracker is associated with.
     * @param _trackerIndex The index of the tracker to store.
     * @param _tracker The tracker data to store.
     */
    function _storeTracker(TrackerStorage storage _data, uint256 _policyId, uint256 _trackerIndex, Trackers memory _tracker) internal {
        _tracker.set = true;
        _tracker.trackerIndex = _trackerIndex;
        _data.trackers[_policyId][_trackerIndex] = _tracker;
    }

    /**
     * @dev Helper function to increment tracker index
     * @param _policyId The policy ID the tracker is associated with.
     */
    function _incrementTrackerIndex(uint256 _policyId) private returns (uint256) {
        TrackerStorage storage data = lib.getTrackerStorage();
        return ++data.trackerIndexCounter[_policyId];
    }

    /**
     * @dev Helper function to store tracker data
     * @param _policyId The policy ID the tracker is associated with.
     * @param _trackerIndex The index of the tracker to store 
     */
    function _storeTrackerData(
        uint256 _policyId,
        uint256 _trackerIndex,
        Trackers calldata _tracker
    ) private {
        TrackerStorage storage data = lib.getTrackerStorage();
        _storeTracker(data, _policyId, _trackerIndex, _tracker);
    }

    /**
     * @dev Helper function to store tracker metadata
     * @param _policyId The policy ID the tracker is associated with.
     * @param _trackerIndex The index of the tracker
     * @param _trackerName Name of the tracker 
     */
    function _storeTrackerMetadata(
        uint256 _policyId,
        uint256 _trackerIndex,
        string calldata _trackerName
    ) private {
        lib.getTrackerMetadataStorage().trackerMetadata[_policyId][_trackerIndex] = _trackerName;
    }

    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Calling Function Management
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Creates a new calling function and stores it in the calling function storage mapping.
     * @dev Associates the calling function with the specified policy ID and parameter types.
     * @param policyId The policy ID the calling function is associated with.
     * @param functionSignature The function signature of the calling function.
     * @param pTypes The parameter types for the calling function.
     * @param callingFunctionName the name of the calling function (to be stored in metadata)
     * @param encodedValues the string representation of the values encoded with the calling function (to be stored in metadata)
     * @return functionId The index of the created calling function.
     */    
    function createCallingFunction(
        uint256 policyId,
        bytes4 functionSignature,
        PT[] memory pTypes,
        string memory callingFunctionName,
        string memory encodedValues
    ) external policyAdminOnly(policyId, msg.sender) returns (uint256) {
        _notCemented(policyId);
        // Step 1: Increment function ID
        uint256 functionId = _incrementFunctionId(policyId);

        // Step 2: Store calling function data
        _storeCallingFunctionData(policyId, functionId, functionSignature, pTypes);

        // Step 3: Store calling function metadata
        _storeCallingFunctionMetadata(policyId, functionId, functionSignature, callingFunctionName, encodedValues);

        // Emit event
        emit CallingFunctionCreated(policyId, functionId);

        return functionId;
    }

    /**
     * @notice Updates an existing calling function by appending new parameter types.
     * @dev Ensures that the new parameter types are compatible with the existing ones.
     * @param policyId The policy ID the calling function is associated with.
     * @param callingFunctionID The ID of the calling function to update.
     * @param functionSignature The function signature of the calling function.
     * @param pTypes The new parameter types to append.
     * @return functionId The updated calling function ID.
     */
    function updateCallingFunction(
        uint256 policyId,
        uint256 callingFunctionID,
        bytes4 functionSignature,
        PT[] memory pTypes
    ) external policyAdminOnly(policyId, msg.sender) returns (uint256) {
        _notCemented(policyId);
        // Load the calling function data from storage
        CallingFunctionStruct storage data = lib.getCallingFunctionStorage();
        // increment the callingFunctionId if necessary
        CallingFunctionStorageSet storage callingFunction = data.callingFunctionStorageSets[policyId][callingFunctionID];
        require(callingFunction.signature == functionSignature, "Delete calling function before updating to a new one");
        require(callingFunction.parameterTypes.length <= pTypes.length, "New parameter types must be of greater or equal length to the original");
        for (uint256 i = 0; i < callingFunction.parameterTypes.length; i++) {
            require(pTypes[i] == callingFunction.parameterTypes[i], "New parameter types must be of the same type as the original");
        }
        if (callingFunction.parameterTypes.length < pTypes.length) {
            for (uint256 i = callingFunction.parameterTypes.length; i < pTypes.length; i++) {
                callingFunction.parameterTypes.push(pTypes[i]);
            }
        }
        emit CallingFunctionUpdated(policyId, callingFunctionID);
        return callingFunctionID;
    }

    /**
     * @notice Deletes a calling function from storage.
     * @dev Removes the calling function and its associated rules and mappings.
     * @param policyId The policy ID the calling function is associated with.
     * @param callingFunctionId The ID of the calling function to delete.
     */
    function deleteCallingFunction(uint256 policyId, uint256 callingFunctionId) external policyAdminOnly(policyId, msg.sender) {
        _notCemented(policyId);
        // retrieve policy from storage 
        PolicyStorageSet storage data = lib.getPolicyStorage().policyStorageSets[policyId];
        // retrieve calling function to delete  
        bytes4 signature = lib.getCallingFunctionStorage().callingFunctionStorageSets[policyId][callingFunctionId].signature;  
        // delete the calling function storage set struct 
        delete lib.getCallingFunctionStorage().callingFunctionStorageSets[policyId][callingFunctionId];
        // delete calling function array from policy 
        delete data.policy.callingFunctions;
        // delete calling function to id map 
        delete data.policy.callingFunctionIdMap[signature];
        // delete rule structures associated to calling function 
        for(uint256 i; i < data.policy.callingFunctionsToRuleIds[signature].length; i++) {
            // delete rules from storage 
            delete lib.getRuleStorage().ruleStorageSets[policyId][i];
            emit AssociatedRuleDeleted(policyId, callingFunctionId);
        }
        // delete calling function to rule Ids mapping  
        delete data.policy.callingFunctionsToRuleIds[signature];
        // retrieve remaining calling function structs from storage that were not removed   
        CallingFunctionStorageSet[] memory callingFunctionStructs = getAllCallingFunctions(policyId);
        // reset calling function array for policy
        for(uint256 j; j < callingFunctionStructs.length; j++) {
            if(callingFunctionStructs[j].set) {
                data.policy.callingFunctions.push(callingFunctionStructs[j].signature);
            }
        }
        emit CallingFunctionDeleted(policyId, callingFunctionId);
    }

    /**
     * @notice Retrieves a calling function from storage.
     * @param policyId The policy ID the calling function is associated with.
     * @param callingFunctionId The ID of the calling function to retrieve.
     * @return CallngFunctionStorageSet The calling function data.
     */
    function getCallingFunction(
        uint256 policyId,
        uint256 callingFunctionId
    ) public view returns (CallingFunctionStorageSet memory) {
        // Load the calling function data from storage
        return
            lib.getCallingFunctionStorage().callingFunctionStorageSets[policyId][callingFunctionId];
    }

    /**
     * @notice retrieves the calling function metadata
     * @param policyId The policy ID the calling function is associated with.
     * @param callingFunctionId The identifier for the calling function
     * @return the metadata for the calling function
     */
    function getCallingFunctionMetadata(
        uint256 policyId,
        uint256 callingFunctionId
    ) public view returns (CallingFunctionHashMapping memory) {
        return lib.getCallingFunctioneMetadataStorage().callingFunctionMetadata[policyId][callingFunctionId];
    }

    /**
     * @notice Retrieves all calling functions associated with a specific policy ID.
     * @param _policyId The policy ID the calling functions are associated with.
     * @return CallingFunctionStorageSet An array of calling function data.
     */
    function getAllCallingFunctions(uint256 _policyId) public view returns (CallingFunctionStorageSet[] memory) {
        // Load the calling function data from storage
        CallingFunctionStruct storage data = lib.getCallingFunctionStorage();
        uint256 functionIdCount = data.functionIdCounter[_policyId];
        CallingFunctionStorageSet[] memory callingFunctionStorageSets = new CallingFunctionStorageSet[](functionIdCount);
        uint256 j = 0;
        for (uint256 i = 1; i <= functionIdCount; i++) {
            if (data.callingFunctionStorageSets[_policyId][i].set) {
                callingFunctionStorageSets[j] = data.callingFunctionStorageSets[_policyId][i];
                j++;
            }
        }
        return callingFunctionStorageSets;
    }

    /**
     * @dev Helper function to increment function ID 
     * @param _policyId The policy ID the calling function is associated with.
     */
    function _incrementFunctionId(uint256 _policyId) private returns (uint256) {
        CallingFunctionStruct storage data = lib.getCallingFunctionStorage();
        return ++data.functionIdCounter[_policyId];
    }

    /**
     * @dev Helper function to store calling function data 
     * @param _policyId The policy ID the calling function is associated with.
     * @param _functionId The ID of the function 
     * @param _functionSignature The function signature of the calling function
     * @param _pTypes The parameter types for the calling function.
     */
    function _storeCallingFunctionData(
        uint256 _policyId,
        uint256 _functionId,
        bytes4 _functionSignature,
        PT[] memory _pTypes
    ) private {
        CallingFunctionStruct storage data = lib.getCallingFunctionStorage();
        data.callingFunctionStorageSets[_policyId][_functionId].set = true;
        data.callingFunctionStorageSets[_policyId][_functionId].signature = _functionSignature;
        data.callingFunctionStorageSets[_policyId][_functionId].parameterTypes = _pTypes;
    }

    /** 
     * @dev Helper function to store calling function metadata
     * @param _policyId The policy ID the calling function is associated with.
     * @param _functionId The ID of the function 
     * @param _functionSignature The function signature of the calling function 
     * @param _callingFunctionName Name of the calling function
     * @param _encodedValues Arguments to be encoded 
     */
    function _storeCallingFunctionMetadata(
        uint256 _policyId,
        uint256 _functionId,
        bytes4 _functionSignature,
        string memory _callingFunctionName,
        string memory _encodedValues
    ) private {
        CallingFunctionMetadataStruct storage metaData = lib.getCallingFunctioneMetadataStorage();
        metaData.callingFunctionMetadata[_policyId][_functionId].callingFunction = _callingFunctionName;
        metaData.callingFunctionMetadata[_policyId][_functionId].signature = _functionSignature;
        metaData.callingFunctionMetadata[_policyId][_functionId].encodedValues = _encodedValues;
    }

    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Policy Subscription Management
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Adds an address to the subscriber list of a specified policy.
     * @dev Only callable by a policy admin. The policy must not be cemented.
     * @param policyId The ID of the policy.
     * @param subscriber The address to add to the policy subscription.
     */
    function addClosedPolicySubscriber(uint256 policyId, address subscriber) external policyAdminOnly(policyId, msg.sender) {
        _notCemented(policyId);
        if (subscriber == address(0)) revert(ZERO_ADDRESS); 
        lib.getPolicyStorage().policyStorageSets[policyId].policy.closedPolicySubscribers[subscriber] = true;
        emit PolicySubsciberAdded(policyId, subscriber);
    }

    /**
     * @notice Removes an address from the subscriber list of a specified policy.
     * @dev Only callable by a policy admin. The policy must not be cemented.
     * @param policyId The ID of the policy.
     * @param subscriber The address to remove from the policy subscription.
     */
    function removeClosedPolicySubscriber(uint256 policyId, address subscriber) external policyAdminOnly(policyId, msg.sender) {
        _notCemented(policyId);
        if (subscriber == address(0)) revert(ZERO_ADDRESS);
        delete lib.getPolicyStorage().policyStorageSets[policyId].policy.closedPolicySubscribers[subscriber];
        emit PolicySubsciberRemoved(policyId, subscriber);
    }

   /**
     * @notice Checks if an address is a subscriber of the specified policy.
     * @param policyId The ID of the policy.
     * @param subscriber The address to check for policy subscription.
     * @return bool True if the address is a subscriber, false otherwise.
     */
    function isClosedPolicySubscriber(uint256 policyId, address subscriber) external view returns (bool) {
        return lib.getPolicyStorage().policyStorageSets[policyId].policy.closedPolicySubscribers[subscriber];
    }

    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Policy Cementing
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Checks that a policy is not cemented.
     * @param _policyId The ID of the policy.
     */
    function _notCemented(uint256 _policyId) internal view {
        if(lib.getPolicyStorage().policyStorageSets[_policyId].policy.cemented) revert ("Not allowed for cemented policy");
    }
    
}
