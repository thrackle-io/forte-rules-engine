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

//     /**
//      * @notice Creates a foreign call and stores it in the contract's storage.
//      * @dev Builds a foreign call structure and maps it to the associated policy ID.
//      * @param _policyId The policy ID the foreign call will be mapped to.
//      * @param _foreignCall The definition of the foreign call to create.
//      * @return The index of the created foreign call.
//      */
//     function createForeignCall(
//         uint256 _policyId, 
//         ForeignCall calldata _foreignCall, string calldata foreignCallName
//     ) external policyAdminOnly(_policyId, msg.sender) returns (uint256) {
//         notCemented(_policyId);
//         if (_foreignCall.foreignCallAddress == address(0)) revert(ZERO_ADDRESS);

//         // Step 1: Generate the foreign call index
//         uint256 foreignCallIndex = _incrementForeignCallIndex(_policyId);

//         // Step 2: Store the foreign call
//         _storeForeignCallData(_policyId, _foreignCall, foreignCallIndex);

//         // Step 3: Store metadata
//         _storeForeignCallMetadata(_policyId, foreignCallIndex, foreignCallName);

//         emit ForeignCallCreated(_policyId, foreignCallIndex);
//         return foreignCallIndex;
//     }

//     /** 
//      * @dev Helper function to increment the foreign call index
//      * @dev Ensures the foreign call is properly set before storing it.
//      * @param _policyId The policy ID the foreign call is associated with.
//      */
//     function _incrementForeignCallIndex(uint256 _policyId) private returns (uint256) {
//         ForeignCallS storage data = lib.getForeignCallStorage();
//         return ++data.foreignCallIdxCounter[_policyId];
//     }

//     /** 
//      * @dev Helper function to store the foreign call data
//      * @dev Ensures the foreign call is properly set before storing it.
//      * @param _policyId The policy ID the foreign call is associated with.
//      * @param _foreignCall The foreign call to store.
//      * @param foreignCallIndex The index of the foreign call.
//      */
//     function _storeForeignCallData(
//         uint256 _policyId,
//         ForeignCall calldata _foreignCall,
//         uint256 foreignCallIndex
//     ) private {
//         ForeignCallS storage data = lib.getForeignCallStorage();
//         ForeignCall memory fc = _foreignCall;
//         fc.foreignCallIndex = foreignCallIndex;
//         _storeForeignCall(_policyId, fc);
//         data.foreignCallIdxCounter[_policyId] = foreignCallIndex;
//     }

//     /**
//      * @dev Helper function to store the foreign call metadata
//      * @param _policyId The policy ID the foreign call is associated with.
//      * @param foreignCallIndex The index of the foreign call.
//      * @param foreignCallName The name of the foreign call.
//      */
//     function _storeForeignCallMetadata(
//         uint256 _policyId,
//         uint256 foreignCallIndex,
//         string calldata foreignCallName
//     ) private {
//         lib.getForeignCallMetadataStorage().foreignCallMetadata[_policyId][foreignCallIndex] = foreignCallName;
//     }

//     /**
//      * @notice Stores a foreign call in the contract's storage.
//      * @dev Ensures the foreign call is properly set before storing it.
//      * @param _policyId The policy ID the foreign call is associated with.
//      * @param _foreignCall The foreign call to store.
//      */
//     function _storeForeignCall(uint256 _policyId, ForeignCall memory _foreignCall) internal {
//         assert(_foreignCall.parameterTypes.length == _foreignCall.typeSpecificIndices.length);
//         _foreignCall.set = true;
//         lib.getForeignCallStorage().foreignCalls[_policyId][_foreignCall.foreignCallIndex] = _foreignCall;
//     }

//     /**
//      * @notice Deletes a foreign call from the contract's storage.
//      * @param _policyId The policy ID the foreign call is associated with.
//      * @param _foreignCallId The ID of the foreign call to delete.
//      */
//     function deleteForeignCall(uint256 _policyId, uint256 _foreignCallId) external policyAdminOnly(_policyId, msg.sender) {
//         notCemented(_policyId);
//         delete lib.getForeignCallStorage().foreignCalls[_policyId][_foreignCallId];
//         emit ForeignCallDeleted(_policyId, _foreignCallId);
//     }

//     /**
//      * @notice Updates a foreign call in the contract's storage.
//      * @param _policyId The policy ID the foreign call is associated with.
//      * @param _foreignCallId The ID of the foreign call to update.
//      * @param _foreignCall The updated foreign call structure.
//      * @return fc The updated foreign call structure.
//      */
//     function updateForeignCall(uint256 _policyId, uint256 _foreignCallId, ForeignCall calldata _foreignCall) external policyAdminOnly(_policyId, msg.sender) returns (ForeignCall memory fc) {
//         notCemented(_policyId);
//         fc = _foreignCall;
//         if (fc.foreignCallAddress == address(0)) revert(ZERO_ADDRESS);
//         fc.foreignCallIndex = _foreignCallId;
//         _storeForeignCallData(_policyId, _foreignCall, _foreignCallId);
//         emit ForeignCallUpdated(_policyId, _foreignCallId);
//         return fc;
//     }

//     /**
//      * @notice Retrieves a foreign call from the contract's storage.
//      * @param _policyId The policy ID of the foreign call to retrieve.
//      * @param _foreignCallId The ID of the foreign call to retrieve.
//      * @return fc The foreign call structure.
//      */
//     function getForeignCall(
//         uint256 _policyId,
//         uint256 _foreignCallId
//     ) public view returns (ForeignCall memory fc) {
//         // Load the Foreign Call data from storage
//         return lib.getForeignCallStorage().foreignCalls[_policyId][_foreignCallId];
//     }

//     /**
//      * @notice retrieves the foreign call metadata
//      * @param _policyId The policy ID the foreign call is associated with.
//      * @param _foreignCallId The identifier for the foreign call
//      * @return fcMeta the metadata for the foreign call
//      */
//     function getForeignCallMetadata(
//         uint256 _policyId,
//         uint256 _foreignCallId
//     ) public view returns (string memory fcMeta) {
//         return lib.getForeignCallMetadataStorage().foreignCallMetadata[_policyId][_foreignCallId];
//     }

//     /**
//      * @dev Retrieve Foreign Call Set from storage 
//      * @param _policyId the policy Id of the foreign call to retrieve
//      * @return fc the foreign call set structure
//      */
//     function getAllForeignCalls(uint256 _policyId) external view returns (ForeignCall[] memory fc) {
//         // Return the Foreign Call Set data from storage
//         uint256 foreignCallCount = lib.getForeignCallStorage().foreignCallIdxCounter[_policyId];
//         ForeignCall[] memory foreignCalls = new ForeignCall[](foreignCallCount);
//         uint256 j = 0;
//         for (uint256 i = 0; i <= foreignCallCount; i++) {
//             if (lib.getForeignCallStorage().foreignCalls[_policyId][i].set) {
//                 foreignCalls[j] = lib.getForeignCallStorage().foreignCalls[_policyId][i];
//                 j++;
//             }
//         }
//         return foreignCalls;
//     }

//     //-------------------------------------------------------------------------------------------------------------------------------------------------------
//     // Tracker Management
//     //-------------------------------------------------------------------------------------------------------------------------------------------------------

//     /**
//      * @notice Adds a tracker to the tracker storage mapping.
//      * @dev Creates a new tracker and associates it with the specified policy ID.
//      * @param _policyId The policy ID the tracker is associated with.
//      * @param _tracker The tracker to add.
//      * @return trackerIndex The index of the created tracker.
//      */
//     function createTracker(
//         uint256 _policyId,
//         Trackers calldata _tracker,
//         string calldata trackerName
//     ) external policyAdminOnly(_policyId, msg.sender) returns (uint256) {
//         notCemented(_policyId);
//         // Step 1: Increment tracker index
//         uint256 trackerIndex = _incrementTrackerIndex(_policyId);
//         // Step 2: Store tracker data
//         _storeTrackerData(_policyId, trackerIndex, _tracker);
//         // Step 3: Store tracker metadata
//         _storeTrackerMetadata(_policyId, trackerIndex, trackerName);
//         // Emit event
//         emit TrackerCreated(_policyId, trackerIndex);

//         return trackerIndex;
//     }

//     /**
//      * @dev Helper function to increment tracker index
//      * @param _policyId The policy ID the tracker is associated with.
//      */
//     function _incrementTrackerIndex(uint256 _policyId) private returns (uint256) {
//         TrackerS storage data = lib.getTrackerStorage();
//         return ++data.trackerIndexCounter[_policyId];
//     }

//     /**
//      * @dev Helper function to store tracker data
//      * @param _policyId The policy ID the tracker is associated with.
//      * @param _trackerIndex The index of the tracker to store 
//      */
//     function _storeTrackerData(
//         uint256 _policyId,
//         uint256 _trackerIndex,
//         Trackers calldata _tracker
//     ) private {
//         TrackerS storage data = lib.getTrackerStorage();
//         _storeTracker(data, _policyId, _trackerIndex, _tracker);
//     }

//     /**
//      * @dev Helper function to store tracker metadata
//      * @param _policyId The policy ID the tracker is associated with.
//      * @param _trackerIndex The index of the tracker
//      * @param trackerName Name of the tracker 
//      */
//     function _storeTrackerMetadata(
//         uint256 _policyId,
//         uint256 _trackerIndex,
//         string calldata trackerName
//     ) private {
//         lib.getTrackerMetadataStorage().trackerMetadata[_policyId][_trackerIndex] = trackerName;
//     }

//     /**
//      * @notice retrieves the tracker metadata
//      * @param _policyId The policy ID the tracker is associated with.
//      * @param _trackerId The identifier for the tracker
//      * @return trMeta the metadata for the tracker
//      */
//     function getTrackerMetadata(
//         uint256 _policyId,
//         uint256 _trackerId
//     ) public view returns (string memory trMeta) {
//         return lib.getTrackerMetadataStorage().trackerMetadata[_policyId][_trackerId];
//     }

//     /**
//      * @notice Updates an existing tracker in the tracker storage mapping.
//      * @dev Modifies the tracker associated with the specified policy ID and tracker index.
//      * @param _policyId The policy ID the tracker is associated with.
//      * @param _trackerIndex The index of the tracker to update.
//      * @param _tracker The updated tracker data.
//      */
//     function updateTracker(
//         uint256 _policyId,
//         uint256 _trackerIndex,
//         Trackers calldata _tracker
//     ) external policyAdminOnly(_policyId, msg.sender) {
//         // Load the Tracker data from storage
//         TrackerS storage data = lib.getTrackerStorage();
//         _storeTracker(data, _policyId, _trackerIndex, _tracker);
//         emit TrackerUpdated(_policyId, _trackerIndex); 
//     }

//     /**
//      * @notice Stores a tracker in the tracker storage mapping.
//      * @dev Sets the tracker data and marks it as active.
//      * @param _data The tracker storage structure.
//      * @param _policyId The policy ID the tracker is associated with.
//      * @param _trackerIndex The index of the tracker to store.
//      * @param _tracker The tracker data to store.
//      */
//     function _storeTracker(TrackerS storage _data, uint256 _policyId, uint256 _trackerIndex, Trackers memory _tracker) internal {
//         _tracker.set = true;
//         _tracker.trackerIndex = _trackerIndex;
//         _data.trackers[_policyId][_trackerIndex] = _tracker;
//     }

//     /**
//      * @notice Retrieves a tracker from the tracker storage mapping.
//      * @param _policyId The policy ID the tracker is associated with.
//      * @param _index The index of the tracker to retrieve.
//      * @return tracker The tracker data.
//      */
//     function getTracker(
//         uint256 _policyId,
//         uint256 _index
//     ) public view returns (Trackers memory tracker) {
//         // Load the Tracker data from storage
//         TrackerS storage data = lib.getTrackerStorage();
//         // return trackers for contract address at speficic index
//         return data.trackers[_policyId][_index];
//     }

//    /**
//      * @notice Retrieves all trackers associated with a specific policy ID.
//      * @param _policyId The policy ID the trackers are associated with.
//      * @return trackers An array of tracker data.
//      */
//     function getAllTrackers(uint256 _policyId) external view returns (Trackers[] memory) {
//         // Load the Tracker data from storage
//         TrackerS storage data = lib.getTrackerStorage();
//         // return trackers for contract address at speficic index
//         uint256 trackerCount = data.trackerIndexCounter[_policyId];
//         Trackers[] memory trackers = new Trackers[](trackerCount);
//         uint256 j = 0;
//         for (uint256 i = 1; i <= trackerCount; i++) {
//             if (data.trackers[_policyId][i].set) {
//                 trackers[j] = data.trackers[_policyId][i];
//                 j++;
//             }
//         }
//         return trackers;
//     }

//    /**
//      * @notice Deletes a tracker from the tracker storage mapping.
//      * @param _policyId The policy ID the tracker is associated with.
//      * @param _trackerIndex The index of the tracker to delete.
//      */
//     function deleteTracker(uint256 _policyId, uint256 _trackerIndex) external policyAdminOnly(_policyId, msg.sender) {
//         notCemented(_policyId);
//         delete lib.getTrackerStorage().trackers[_policyId][_trackerIndex];
//         emit TrackerDeleted(_policyId, _trackerIndex); 
//     }

//     //-------------------------------------------------------------------------------------------------------------------------------------------------------
//     // Calling Function Management
//     //-------------------------------------------------------------------------------------------------------------------------------------------------------

//     /**
//      * @notice Creates a new calling function and stores it in the calling function storage mapping.
//      * @dev Associates the calling function with the specified policy ID and parameter types.
//      * @param _policyId The policy ID the calling function is associated with.
//      * @param _functionSignature The function signature of the calling function.
//      * @param _pTypes The parameter types for the calling function.
//      * @param _callingFunctionName the name of the calling function (to be stored in metadata)
//      * @param _encodedValues the string representation of the values encoded with the calling function (to be stored in metadata)
//      * @return functionId The index of the created calling function.
//      */    
//     function createCallingFunction(
//         uint256 _policyId,
//         bytes4 _functionSignature,
//         PT[] memory _pTypes,
//         string memory _callingFunctionName,
//         string memory _encodedValues
//     ) external policyAdminOnly(_policyId, msg.sender) returns (uint256) {
//         notCemented(_policyId);
//         // Step 1: Increment function ID
//         uint256 functionId = _incrementFunctionId(_policyId);

//         // Step 2: Store calling function data
//         _storeCallingFunctionData(_policyId, functionId, _functionSignature, _pTypes);

//         // Step 3: Store calling function metadata
//         _storeCallingFunctionMetadata(_policyId, functionId, _functionSignature, _callingFunctionName, _encodedValues);

//         // Emit event
//         emit CallingFunctionCreated(_policyId, functionId);

//         return functionId;
//     }

//     /**
//      * @dev Helper function to increment function ID 
//      * @param _policyId The policy ID the calling function is associated with.
//      */
//     function _incrementFunctionId(uint256 _policyId) private returns (uint256) {
//         CallingFunctionStruct storage data = lib.getCallingFunctionStorage();
//         return ++data.functionIdCounter[_policyId];
//     }

//     /**
//      * @dev Helper function to store calling function data 
//      * @param _policyId The policy ID the calling function is associated with.
//      * @param _functionId The ID of the function 
//      * @param _functionSignature The function signature of the calling function
//      * @param _pTypes The parameter types for the calling function.
//      */
//     function _storeCallingFunctionData(
//         uint256 _policyId,
//         uint256 _functionId,
//         bytes4 _functionSignature,
//         PT[] memory _pTypes
//     ) private {
//         CallingFunctionStruct storage data = lib.getCallingFunctionStorage();
//         data.callingFunctionStorageSets[_policyId][_functionId].set = true;
//         data.callingFunctionStorageSets[_policyId][_functionId].signature = _functionSignature;
//         data.callingFunctionStorageSets[_policyId][_functionId].parameterTypes = _pTypes;
//     }

//     /** 
//      * @dev Helper function to store calling function metadata
//      * @param _policyId The policy ID the calling function is associated with.
//      * @param _functionId The ID of the function 
//      * @param _functionSignature The function signature of the calling function 
//      * @param _callingFunctionName Name of the calling function
//      * @param _encodedValues Arguments to be encoded 
//      */
//     function _storeCallingFunctionMetadata(
//         uint256 _policyId,
//         uint256 _functionId,
//         bytes4 _functionSignature,
//         string memory _callingFunctionName,
//         string memory _encodedValues
//     ) private {
//         CallingFunctionMetadataStruct storage metaData = lib.getCallingFunctioneMetadataStorage();
//         metaData.callingFunctionMetadata[_policyId][_functionId].callingFunction = _callingFunctionName;
//         metaData.callingFunctionMetadata[_policyId][_functionId].signature = _functionSignature;
//         metaData.callingFunctionMetadata[_policyId][_functionId].encodedValues = _encodedValues;
//     }
    
//     /**
//      * @notice Updates an existing calling function by appending new parameter types.
//      * @dev Ensures that the new parameter types are compatible with the existing ones.
//      * @param _policyId The policy ID the calling function is associated with.
//      * @param _callingFunctionID The ID of the calling function to update.
//      * @param _functionSignature The function signature of the calling function.
//      * @param _pTypes The new parameter types to append.
//      * @return functionId The updated calling function ID.
//      */
//     function updateCallingFunction(
//         uint256 _policyId,
//         uint256 _callingFunctionID,
//         bytes4 _functionSignature,
//         PT[] memory _pTypes
//     ) external policyAdminOnly(_policyId, msg.sender) returns (uint256) {
//         notCemented(_policyId);
//         // Load the calling function data from storage
//         CallingFunctionStruct storage data = lib.getCallingFunctionStorage();
//         // increment the callingFunctionId if necessary
//         CallingFunctionStorageSet storage callingFunction = data.callingFunctionStorageSets[_policyId][_callingFunctionID];
//         require(callingFunction.signature == _functionSignature, "Delete calling function before updating to a new one");
//         require(callingFunction.parameterTypes.length <= _pTypes.length, "New parameter types must be of greater or equal length to the original");
//         for (uint256 i = 0; i < callingFunction.parameterTypes.length; i++) {
//             require(_pTypes[i] == callingFunction.parameterTypes[i], "New parameter types must be of the same type as the original");
//         }
//         if (callingFunction.parameterTypes.length < _pTypes.length) {
//             for (uint256 i = callingFunction.parameterTypes.length; i < _pTypes.length; i++) {
//                 callingFunction.parameterTypes.push(_pTypes[i]);
//             }
//         }
//         emit CallingFunctionUpdated(_policyId, _callingFunctionID);
//         return _callingFunctionID;
//     }

//     /**
//      * @notice Deletes a calling function from storage.
//      * @dev Removes the calling function and its associated rules and mappings.
//      * @param _policyId The policy ID the calling function is associated with.
//      * @param _callingFunctionId The ID of the calling function to delete.
//      */
//     function deleteCallingFunction(uint256 _policyId, uint256 _callingFunctionId) external policyAdminOnly(_policyId, msg.sender) {
//         notCemented(_policyId);
//         // retrieve policy from storage 
//         PolicyStorageSet storage data = lib.getPolicyStorage().policyStorageSets[_policyId];
//         // retrieve calling function to delete  
//         bytes4 signature = lib.getCallingFunctionStorage().callingFunctionStorageSets[_policyId][_callingFunctionId].signature;  
//         // delete the calling function storage set struct 
//         delete lib.getCallingFunctionStorage().callingFunctionStorageSets[_policyId][_callingFunctionId];
//         // delete calling function array from policy 
//         delete data.policy.callingFunctions;
//         // delete calling function to id map 
//         delete data.policy.callingFunctionIdMap[signature];
//         // delete rule structures associated to calling function 
//         for(uint256 i; i < data.policy.callingFunctionsToRuleIds[signature].length; i++) {
//             // delete rules from storage 
//             delete lib.getRuleStorage().ruleStorageSets[_policyId][i];
//             emit AssociatedRuleDeleted(_policyId, _callingFunctionId);
//         }
//         // delete calling function to rule Ids mapping  
//         delete data.policy.callingFunctionsToRuleIds[signature];
//         // retrieve remaining calling function structs from storage that were not removed   
//         CallingFunctionStorageSet[] memory callingFunctionStructs = getAllCallingFunctions(_policyId);
//         // reset calling function array for policy
//         for(uint256 j; j < callingFunctionStructs.length; j++) {
//             if(callingFunctionStructs[j].set) {
//                 data.policy.callingFunctions.push(callingFunctionStructs[j].signature);
//             }
//         }
//         emit CallingFunctionDeleted(_policyId, _callingFunctionId);
//     }

//     /**
//      * @notice Retrieves a calling function from storage.
//      * @param _policyId The policy ID the calling function is associated with.
//      * @param _callingFunctionId The ID of the calling function to retrieve.
//      * @return CallngFunctionStorageSet The calling function data.
//      */
//     function getCallingFunction(
//         uint256 _policyId,
//         uint256 _callingFunctionId
//     ) public view returns (CallingFunctionStorageSet memory) {
//         // Load the calling function data from storage
//         return
//             lib.getCallingFunctionStorage().callingFunctionStorageSets[_policyId][_callingFunctionId];
//     }

//     /**
//      * @notice retrieves the calling function metadata
//      * @param _policyId The policy ID the calling function is associated with.
//      * @param _callingFunctionId The identifier for the calling function
//      * @return the metadata for the calling function
//      */
//     function getCallingFunctionMetadata(
//                 uint256 _policyId,
//         uint256 _callingFunctionId
//     ) public view returns (CallingFunctionHashMapping memory) {
//         return lib.getCallingFunctioneMetadataStorage().callingFunctionMetadata[_policyId][_callingFunctionId];
//     }

//     /**
//      * @notice Retrieves all calling functions associated with a specific policy ID.
//      * @param _policyId The policy ID the calling functions are associated with.
//      * @return CallingFunctionStorageSet An array of calling function data.
//      */
//     function getAllCallingFunctions(uint256 _policyId) public view returns (CallingFunctionStorageSet[] memory) {
//         // Load the calling function data from storage
//         CallingFunctionStruct storage data = lib.getCallingFunctionStorage();
//         uint256 functionIdCount = data.functionIdCounter[_policyId];
//         CallingFunctionStorageSet[] memory callingFunctionStorageSets = new CallingFunctionStorageSet[](functionIdCount);
//         uint256 j = 0;
//         for (uint256 i = 1; i <= functionIdCount; i++) {
//             if (data.callingFunctionStorageSets[_policyId][i].set) {
//                 callingFunctionStorageSets[j] = data.callingFunctionStorageSets[_policyId][i];
//                 j++;
//             }
//         }
//         return callingFunctionStorageSets;
//     }

//     //-------------------------------------------------------------------------------------------------------------------------------------------------------
//     // Policy Subscription Management
//     //-------------------------------------------------------------------------------------------------------------------------------------------------------

//     /**
//      * @notice Adds an address to the subscriber list of a specified policy.
//      * @dev Only callable by a policy admin. The policy must not be cemented.
//      * @param _policyId The ID of the policy.
//      * @param _subscriber The address to add to the policy subscription.
//      */
//     function addClosedPolicySubscriber(uint256 _policyId, address _subscriber) external policyAdminOnly(_policyId, msg.sender) {
//         notCemented(_policyId);
//         if (_subscriber == address(0)) revert(ZERO_ADDRESS); 
//         lib.getPolicyStorage().policyStorageSets[_policyId].policy.closedPolicySubscribers[_subscriber] = true;
//         emit PolicySubsciberAdded(_policyId, _subscriber);
//     }

//    /**
//      * @notice Checks if an address is a subscriber of the specified policy.
//      * @param _policyId The ID of the policy.
//      * @param _subscriber The address to check for policy subscription.
//      * @return bool True if the address is a subscriber, false otherwise.
//      */
//     function isClosedPolicySubscriber(uint256 _policyId, address _subscriber) external view returns (bool) {
//         return lib.getPolicyStorage().policyStorageSets[_policyId].policy.closedPolicySubscribers[_subscriber];
//     }

//     /**
//      * @notice Removes an address from the subscriber list of a specified policy.
//      * @dev Only callable by a policy admin. The policy must not be cemented.
//      * @param _policyId The ID of the policy.
//      * @param _subscriber The address to remove from the policy subscription.
//      */
//     function removeClosedPolicySubscriber(uint256 _policyId, address _subscriber) external policyAdminOnly(_policyId, msg.sender) {
//         notCemented(_policyId);
//         if (_subscriber == address(0)) revert(ZERO_ADDRESS);
//         delete lib.getPolicyStorage().policyStorageSets[_policyId].policy.closedPolicySubscribers[_subscriber];
//         emit PolicySubsciberRemoved(_policyId, _subscriber);
//     }

//     //-------------------------------------------------------------------------------------------------------------------------------------------------------
//     // Policy Cementing
//     //-------------------------------------------------------------------------------------------------------------------------------------------------------

//     /**
//      * @notice Checks that a policy is not cemented.
//      * @param _policyId The ID of the policy.
//      */
//     function notCemented(uint256 _policyId) internal view {
//         if(lib.getPolicyStorage().policyStorageSets[_policyId].policy.cemented) revert ("Not allowed for cemented policy");
//     }
    
}
