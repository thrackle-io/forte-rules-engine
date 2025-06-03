// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetCommonImports.sol";
import "src/engine/facets/RulesEngineAdminRolesFacet.sol";
import "src/engine/facets/RulesEngineComponentFacet.sol";
import {RulesEngineStorageLib as StorageLib} from "src/engine/facets/RulesEngineStorageLib.sol";

/**
 * @title Rules Engine Policy Facet
 * @dev This contract serves as the primary data facet for the Rules Engine. It is responsible for creating, updating, 
 *      retrieving, and managing policies and rules. It enforces role-based access control and ensures that only authorized 
 *      users can modify or retrieve data. The contract also supports policy cementing to prevent further modifications.
 * @notice This contract is a critical component of the Rules Engine, enabling secure and flexible policy management.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract RulesEnginePolicyFacet is FacetCommonImports {


    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Policy Management
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Updates a policy in storage.
     * @dev Updates the policy type, calling functions, and associated rules.
     * @param policyId The ID of the policy to update.
     * @param callingFunctions The function signatures of the calling functions in the policy.
     * @param callingFunctionIds The IDs of the calling functions.
     * @param ruleIds A two-dimensional array of rule IDs associated with the policy.
     * @param policyType The type of the policy (CLOSED_POLICY or OPEN_POLICY).
     * @return policyId The updated policy ID.
     */
    function updatePolicy(
        uint256 policyId, 
        bytes4[] calldata callingFunctions, 
        uint256[] calldata callingFunctionIds, 
        uint256[][] calldata ruleIds,
        PolicyType policyType
    ) external policyAdminOnly(policyId, msg.sender) returns(uint256) {
        StorageLib.notCemented(policyId);
        // calling functions length must match the calling function ids length
        if (callingFunctions.length != callingFunctionIds.length) revert(SIGNATURES_INCONSISTENT); 
        // if policy ID is zero no policy has been created and cannot be updated. 
        if (policyId == 0) revert(POLICY_ID_0);
        emit PolicyUpdated(policyId);
        // Update the policy type
        return _storePolicyData(policyId, callingFunctions, callingFunctionIds, ruleIds, policyType);
    }

    /**
     * @notice Closes a policy by changing its type to CLOSED_POLICY.
     * @dev This function ensures that only policy admins can close a policy and that the policy is not cemented.
     * @param policyId The ID of the policy to close.
     */
    function closePolicy(uint256 policyId) external policyAdminOnly(policyId, msg.sender) {
        StorageLib.notCemented(policyId);
        _processPolicyTypeChange(policyId, PolicyType.CLOSED_POLICY);        
        emit PolicyClosed(policyId);
    }

    /**
     * @notice Opens a policy by changing its type to OPEN_POLICY.
     * @dev This function ensures that only policy admins can open a policy and that the policy is not cemented.
     * @param policyId The ID of the policy to open.
     */
    function openPolicy(uint256 policyId) external policyAdminOnly(policyId, msg.sender) {
        StorageLib.notCemented(policyId);
        _processPolicyTypeChange(policyId, PolicyType.OPEN_POLICY);        
        emit PolicyOpened(policyId);
    }

    /**
     * @notice Marks a policy as cemented, preventing further modifications.
     * @param policyId The ID of the policy to cement.
     */
    function cementPolicy(uint256 policyId) external policyAdminOnly(policyId, msg.sender) {
        lib.getPolicyStorage().policyStorageSets[policyId].policy.cemented = true;
        emit PolicyCemented(policyId);
    }

    /**
     * @notice Deletes a policy from storage.
     * @dev Removes the policy and all associated rules, trackers, and foreign calls. Ensures the policy is not cemented.
     * @param policyId The ID of the policy to delete.
     */
    function deletePolicy(uint256 policyId) external policyAdminOnly(policyId, msg.sender) {
        StorageLib.notCemented(policyId);
        PolicyStorageSet storage data = lib.getPolicyStorage().policyStorageSets[policyId];
        delete data.set;

        Policy storage policy = data.policy;
        bytes4[] memory callingFunctions = policy.callingFunctions;
        for (uint256 i = 0; i < callingFunctions.length; i++) {
            uint256[] memory ruleIds = policy.callingFunctionsToRuleIds[callingFunctions[i]];
            for (uint256 j = 0; j < ruleIds.length; j++) {
                callAnotherFacet(0xa31c8ebb, abi.encodeWithSignature("deleteRule(uint256,uint256)", policyId, ruleIds[j]));
            }
        }

        uint256 foreignCallCount = lib.getForeignCallStorage().foreignCallIdxCounter[policyId];
        for (uint256 i = 0; i <= foreignCallCount; i++) {
            if (lib.getForeignCallStorage().foreignCalls[policyId][i].set) {
                delete lib.getForeignCallStorage().foreignCalls[policyId][i];
                emit ForeignCallDeleted(policyId, i);
            }
        }

        TrackerStorage storage trackerData = lib.getTrackerStorage();
        uint256 trackerCount = trackerData.trackerIndexCounter[policyId];
        for (uint256 i = 1; i <= trackerCount; i++) {
            if (trackerData.trackers[policyId][i].set) {
                delete lib.getTrackerStorage().trackers[policyId][i];
                emit TrackerDeleted(policyId, i); 
            }
        }

        for (uint256 i = 0; i < data.policy.callingFunctions.length; i++) {
            delete data.policy.callingFunctionIdMap[data.policy.callingFunctions[i]];
            delete data.policy.callingFunctionsToRuleIds[data.policy.callingFunctions[i]];
        }
        emit PolicyDeleted(policyId);
    }

    /**
     * @notice Applies policies to a specified contract.
     * @dev Ensures that only calling contract admins can apply policies and validates policy types.
     * @param contractAddress The address of the contract to apply policies to.
     * @param policyIds The IDs of the policies to apply.
     */
    function applyPolicy(address contractAddress, uint256[] calldata policyIds) callingContractAdminOnly(contractAddress, msg.sender) external { 
        if (contractAddress == address(0)) revert(ZERO_ADDRESS);
        // Load the policy data from storage
        PolicyAssociationStorage storage data = lib.getPolicyAssociationStorage();
        
        // Check policy type for each policy being applied
        for(uint256 i = 0; i < policyIds.length; i++) {
            PolicyStorageSet storage policySet = lib.getPolicyStorage().policyStorageSets[policyIds[i]];
            require(policySet.set, POLICY_DOES_NOT_EXIST);
            
            // If policy is cemented, no one can apply it
            StorageLib.notCemented(policyIds[i]);

            // If policy is closed, only admin can apply it
            if(policySet.policy.policyType == PolicyType.CLOSED_POLICY) {
                require(policySet.policy.closedPolicySubscribers[msg.sender],
                    VERIFIED_SUBSCRIBER_ONLY
                );
            }
        }

        // Apply the policies
        data.contractPolicyIdMap[contractAddress] = new uint256[](policyIds.length);
        for(uint256 i = 0; i < policyIds.length; i++) {
           data.contractPolicyIdMap[contractAddress][i] = policyIds[i];
           data.policyIdContractMap[policyIds[i]].push(contractAddress);
        }
        emit PolicyApplied(_policyIds, _contractAddress);
    }

    /**
     * @notice Unapplies policies from a specified contract.
     * @dev Ensures that only calling contract admins can unapply policies. Removes associations between the contract and the specified policies.
     * @param _contractAddress The address of the contract from which policies will be unapplied.
     * @param _policyIds The IDs of the policies to unapply.
     */
    function unapplyPolicy(address _contractAddress, uint256[] calldata _policyIds) callingContractAdminOnly(_contractAddress, msg.sender) external { 
        if (_contractAddress == address(0)) revert(ZERO_ADDRESS);
        // Load the policy association data from storage
        PolicyAssociationS storage data = lib.getPolicyAssociationStorage();
        // Get the currently applied policyIds
        uint256[] memory allPolicyIds = data.contractPolicyIdMap[_contractAddress];
        // Blow away the contract to policyId association data in order to keep the associated id's array length in line with the amount of policies associated.
        delete data.contractPolicyIdMap[_contractAddress];
        bool found;
        for(uint256 i = 0; i < allPolicyIds.length; i++) {
            found = false;
            for(uint256 j = 0; j < _policyIds.length; j++) {
                // if the id exists in the unapply list, don't carry it forward
                if (allPolicyIds[i] == _policyIds[j]) found = true;
            }
            if (!found) data.contractPolicyIdMap[_contractAddress].push(allPolicyIds[i]);
        } 

        // Get the currently applied policyIds
        address[] memory allContracts = data.policyIdContractMap[_policyIds[0]];
        // Loop through the policyId to contract arrays, clear them and add back only the correct addresses
        for(uint256 i = 0; i < _policyIds.length; i++) {
            // Blow away the policyId to contract association data in order to keep the associated id's array length in line with the amount of contracts associated.
            delete data.policyIdContractMap[_policyIds[i]];
            for(uint256 j = 0; j < allContracts.length; j++) {
                // if the address is not the current address, add it back to the array.
                if (allContracts[j] != _contractAddress) data.policyIdContractMap[_policyIds[i]].push(allContracts[j]);
            } 
        }
        emit PolicyUnapplied(_policyIds, _contractAddress);
    }

    /**
     * @notice Retrieves the IDs of policies applied to a specific contract.
     * @param _contractAddress The address of the contract.
     * @return uint256[] An array of applied policy IDs.
     */
    function getAppliedPolicyIds(address _contractAddress) external view returns (uint256[] memory) {
        // Load the policy association data from storage
        return lib.getPolicyAssociationStorage().contractPolicyIdMap[_contractAddress];
    }

    /**
     * @notice Creates a new policy and assigns a policy admin.
     * @dev Generates a policy ID and initializes the policy with the specified type.
     * @param callingFunctions The calling functions associated with the policy.
     * @param rules The rules associated with the policy.
     * @param policyType The type of the policy (CLOSED_POLICY or OPEN_POLICY).
     * @return uint256 The generated policy ID.
     */
    function createPolicy(
        CallingFunctionStorageSet[] calldata callingFunctions, 
        Rule[] calldata rules,
        PolicyType policyType
    ) external returns(uint256) {
        // retrieve Policy Storage 
        PolicyStorage storage data = lib.getPolicyStorage();
        uint256 policyId = data.policyId; 
        // If this is the first policy created increment by 1 to start id counter. 
        unchecked{
            ++data.policyId;
        }
        policyId = data.policyId;
        data.policyStorageSets[policyId].set = true; 
        data.policyStorageSets[policyId].policy.policyType = policyType;
        //This function is called as an external call intentionally. This allows for proper gating on the generatePolicyAdminRole fn to only be callable by the RulesEngine address. 
        RulesEngineAdminRolesFacet(address(this)).generatePolicyAdminRole(policyId, address(msg.sender));
        //TODO remove this when create policy is atomic 
        // Temporarily disabling _storePolicyData
        // return _storePolicyData(policyId, _callingFunctions, _rules);
        
        callingFunctions;
        rules;
        emit PolicyCreated(policyId);
        return policyId;
    }

    // TODO add removePolicy fn

    /**
     * @notice Retrieves the IDs of policies applied to a specific contract.
     * @param contractAddress The address of the contract.
     * @return uint256[] An array of applied policy IDs.
     */
    function getAppliedPolicyIds(address contractAddress) external view returns (uint256[] memory) {
        // Load the policy association data from storage
        return lib.getPolicyAssociationStorage().contractPolicyIdMap[contractAddress];
    }

    /**
     * @notice Checks if a policy is closed.
     * @param policyId The ID of the policy to check.
     * @return bool True if the policy is closed, false otherwise.
     */
    function isClosedPolicy(uint256 policyId) external view returns (bool) {
        return (lib.getPolicyStorage().policyStorageSets[policyId].policy.policyType == PolicyType.CLOSED_POLICY);
    }

    /**
     * @notice Retrieves a policy from storage.
     * @dev Since `Policy` contains nested mappings, the data is broken into arrays for external return.
     * @param policyId The ID of the policy.
     * @return callingFunctions The calling functions within the policy.
     * @return callingFunctionIds The calling function IDs corresponding to each calling function.
     * @return ruleIds The rule IDs corresponding to each calling function.
     */
    function getPolicy(uint256 policyId) external view returns(bytes4[] memory callingFunctions, uint256[] memory callingFunctionIds, uint256[][] memory ruleIds) {
        // Load the policy data from storage
        Policy storage policy = lib.getPolicyStorage().policyStorageSets[policyId].policy;
        // Initialize the return arrays if necessary
        if(policy.callingFunctions.length > 0){
            callingFunctions = new bytes4[](policy.callingFunctions.length);
            callingFunctionIds = new uint256[](policy.callingFunctions.length);
            ruleIds = new uint256[][](policy.callingFunctions.length);
        }
        ruleIds = new uint256[][](policy.callingFunctions.length);
        // Loop through the callng functions and load the return arrays
        for (uint256 i = 0; i < policy.callingFunctions.length; i++) {
            callingFunctions[i] = policy.callingFunctions[i];
            callingFunctionIds[i] = policy.callingFunctionIdMap[policy.callingFunctions[i]];
            // Initialize the ruleId return array if necessary
            for (uint256 ruleIndex = 0; ruleIndex < policy.callingFunctionsToRuleIds[policy.callingFunctions[i]].length; ruleIndex++) {
                // have to allocate the memory array here
                ruleIds[i] = new uint256[](policy.callingFunctionsToRuleIds[policy.callingFunctions[i]].length);
                ruleIds[i][ruleIndex] = policy.callingFunctionsToRuleIds[policy.callingFunctions[i]][ruleIndex];
            }
        }
    }

    /**
     * @notice Internal helper function for creating and updating policy data.
     * @dev This function processes and stores policy data, including calling functions, rules, and policy type.
     * @param _policyId The ID of the policy.
     * @param _callingFunctions All callingFunctions in the policy.
     * @param _callingFunctionIds Corresponding Calling Function IDs in the policy. Each element matches one-to-one with the elements in `_callingFunctions`.
     * @param _ruleIds A two-dimensional array of rule IDs. The first level represents calling functions, and the second level contains rule IDs for each calling function.
     * @param _policyType The type of the policy (OPEN or CLOSED).
     * @return policyId The updated policy ID.
     * @dev The parameters are complex because nested structs are not allowed for externally facing functions.
     */
    function _storePolicyData(uint256 _policyId, bytes4[] calldata _callingFunctions, uint256[] calldata _callingFunctionIds, uint256[][] calldata _ruleIds, PolicyType _policyType) internal returns(uint256){   
        // Load the policy data from storage
        Policy storage data = lib.getPolicyStorage().policyStorageSets[_policyId].policy;
        // if the policy type is changing, perform all data maintenance
        _processPolicyTypeChange(_policyId, _policyType);
        // clear the iterator array
        delete data.callingFunctions;
        if (_ruleIds.length > 0) {
            // Loop through all the passed in calling functions for the policy      
            for (uint256 i = 0; i < _callingFunctions.length; i++) {
                // make sure that all the calling functions exist
                if(!StorageLib._isCallingFunctionSet(_policyId, _callingFunctionIds[i])) revert(INVALID_SIGNATURE);
                // Load into the mapping
                data.callingFunctionIdMap[_callingFunctions[i]] = _callingFunctionIds[i];
                // load the iterator array
                data.callingFunctions.push(_callingFunctions[i]);
                // make sure that all the rules attached to each calling function exist
                for (uint256 j = 0; j < _ruleIds[i].length; j++) {
                    RuleStorageSet memory ruleStore = lib.getRuleStorage().ruleStorageSets[_policyId][_ruleIds[i][j]];
                    if(!ruleStore.set) revert(INVALID_RULE);
                    for (uint256 k = 0; k < ruleStore.rule.placeHolders.length; k++) {
                        if(ruleStore.rule.placeHolders[k].foreignCall) {
                            // get the foreign call using the type specific index which will be interpreted as a foreign call index since it has foreignCall bool set
                            require(StorageLib._isForeignCallSet(_policyId, ruleStore.rule.placeHolders[k].typeSpecificIndex), FOREIGN_CALL_NOT_SET);
                        } else if (ruleStore.rule.placeHolders[k].trackerValue) {
                            require(StorageLib._isTrackerSet(_policyId, ruleStore.rule.placeHolders[k].typeSpecificIndex), TRACKER_NOT_SET);
                        }

                    }
                    data.callingFunctionsToRuleIds[_callingFunctions[i]].push(_ruleIds[i][j]);
                }
                
            }
        } else {
            // Solely loop through and add calling functions to the policy
            for (uint256 i = 0; i < _callingFunctions.length; i++) {
                // make sure that all the calling functions exist
                if(!StorageLib._isCallingFunctionSet(_policyId, _callingFunctionIds[i])) revert(INVALID_SIGNATURE);
                // Load into the mapping
                data.callingFunctionIdMap[_callingFunctions[i]] = _callingFunctionIds[i];
                // load the iterator array
                data.callingFunctions.push(_callingFunctions[i]);
            }
        }    
        
        return _policyId;
    }

    /**
     * @notice Internal helper function to handle data cleanup during policy type changes.
     * @dev This function removes applied contract associations when transitioning to a CLOSED policy.
     * @param _policyId The ID of the policy.
     * @param _policyType The new type of the policy (OPEN or CLOSED).
     */
    function _processPolicyTypeChange(uint256 _policyId, PolicyType _policyType) internal {
        // If closing, remove all applied contract associations
        Policy storage data = lib.getPolicyStorage().policyStorageSets[_policyId].policy;
        if (_policyType == PolicyType.CLOSED_POLICY){
            // Load the calling function data from storage
            PolicyAssociationStorage storage assocData = lib.getPolicyAssociationStorage();
            for (uint256 i = 0; i < assocData.policyIdContractMap[_policyId].length; i++) { 
                delete assocData.contractPolicyIdMap[assocData.policyIdContractMap[_policyId][i]];
            }
            delete assocData.policyIdContractMap[_policyId];
        } 
        data.policyType = _policyType;
    }
}
