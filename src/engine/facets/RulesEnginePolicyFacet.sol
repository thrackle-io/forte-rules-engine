// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetCommonImports.sol";
import "src/engine/facets/RulesEngineAdminRolesFacet.sol";
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
        PolicyType policyType,
        string calldata policyName,
        string calldata policyDescription
    ) external returns (uint256) {
        _policyAdminOnly(policyId, msg.sender);
        StorageLib._notCemented(policyId);
        // calling functions length must match the calling function ids length
        if (callingFunctions.length != callingFunctionIds.length) revert(SIGNATURES_INCONSISTENT);
        // if policy ID is zero no policy has been created and cannot be updated.
        if (policyId == 0) revert(POLICY_ID_0);

        // Update the policy type
        return _storePolicyData(policyId, callingFunctions, callingFunctionIds, ruleIds, policyType, policyName, policyDescription);
    }

    /**
     * @notice Closes a policy by changing its type to CLOSED_POLICY.
     * @dev This function ensures that only policy admins can close a policy and that the policy is not cemented.
     * @param policyId The ID of the policy to close.
     */
    function closePolicy(uint256 policyId) external policyAdminOnly(policyId, msg.sender) {
        StorageLib._notCemented(policyId);
        _processPolicyTypeChange(policyId, PolicyType.CLOSED_POLICY);
        emit PolicyClosed(policyId);
    }

    /**
     * @notice Opens a policy by changing its type to OPEN_POLICY.
     * @dev This function ensures that only policy admins can open a policy and that the policy is not cemented.
     * @param policyId The ID of the policy to open.
     */
    function openPolicy(uint256 policyId) external policyAdminOnly(policyId, msg.sender) {
        StorageLib._notCemented(policyId);
        _processPolicyTypeChange(policyId, PolicyType.OPEN_POLICY);
        emit PolicyOpened(policyId);
    }

    /**
     * @notice Marks a policy as cemented, preventing further modifications.
     * @param policyId The ID of the policy to cement.
     */
    function cementPolicy(uint256 policyId) external policyAdminOnly(policyId, msg.sender) {
        StorageLib._notCemented(policyId);
        lib._getPolicyStorage().policyStorageSets[policyId].policy.cemented = true;
        emit PolicyCemented(policyId);
    }

    /**
     * @notice Marks a policy as disabled.
     * @dev A policy will not be checked against if it is in a disabled state.
     * @param policyId The ID of the policy to disable.
     */
    function disablePolicy(uint256 policyId) external policyAdminOnly(policyId, msg.sender) {
        StorageLib._notCemented(policyId);
        _processPolicyTypeChange(policyId, PolicyType.DISABLED_POLICY);
        emit PolicyDisabled(policyId);
    }

    /**
     * @notice Deletes a policy from storage.
     * @dev Removes the policy and all associated rules, trackers, and foreign calls. Ensures the policy is not cemented.
     * @param policyId The ID of the policy to delete.
     */
    function deletePolicy(uint256 policyId) external policyAdminOnly(policyId, msg.sender) {
        StorageLib._notCemented(policyId);
        PolicyStorageSet storage data = lib._getPolicyStorage().policyStorageSets[policyId];
        delete data.set;

        Policy storage policy = data.policy;
        bytes4[] memory callingFunctions = policy.callingFunctions;
        for (uint256 i = 0; i < callingFunctions.length; i++) {
            uint256[] memory ruleIds = policy.callingFunctionsToRuleIds[callingFunctions[i]];
            for (uint256 j = 0; j < ruleIds.length; j++) {
                _callAnotherFacet(0xa31c8ebb, abi.encodeWithSignature("deleteRule(uint256,uint256)", policyId, ruleIds[j]));
            }
        }

        uint256 foreignCallCount = lib._getForeignCallStorage().foreignCallIdxCounter[policyId];
        for (uint256 i = 0; i <= foreignCallCount; i++) {
            if (lib._getForeignCallStorage().foreignCalls[policyId][i].set) {
                delete lib._getForeignCallStorage().foreignCalls[policyId][i];
                emit ForeignCallDeleted(policyId, i);
            }
        }

        TrackerStorage storage trackerData = lib._getTrackerStorage();
        uint256 trackerCount = trackerData.trackerIndexCounter[policyId];
        for (uint256 i = 1; i <= trackerCount; i++) {
            if (trackerData.trackers[policyId][i].set) {
                delete lib._getTrackerStorage().trackers[policyId][i];
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
    function applyPolicy(
        address contractAddress,
        uint256[] calldata policyIds
    ) external callingContractAdminOnly(contractAddress, msg.sender) {
        if (contractAddress == address(0)) revert(ZERO_ADDRESS);
        // Load the policy data from storage
        PolicyAssociationStorage storage data = lib._getPolicyAssociationStorage();

        require(policyIds.length < MAX_LOOP, MAX_POLICIES_PER_ADDR);
        for (uint256 i = 0; i < policyIds.length; i++) {
            PolicyStorageSet storage policySet = lib._getPolicyStorage().policyStorageSets[policyIds[i]];
            require(policySet.set, POLICY_DOES_NOT_EXIST);

            // If policy is cemented, no one can apply it
            StorageLib._notCemented(policyIds[i]);

            // If policy is closed, only admin can apply it
            if (policySet.policy.policyType == PolicyType.CLOSED_POLICY) {
                require(policySet.policy.closedPolicySubscribers[msg.sender], VERIFIED_SUBSCRIBER_ONLY);
            }
        }

        // Apply the policies
        data.contractPolicyIdMap[contractAddress] = new uint256[](policyIds.length);
        // Data validation will alway ensure _policyIds.length will be less than MAX_LOOP
        for (uint256 i = 0; i < policyIds.length; i++) {
            data.contractPolicyIdMap[contractAddress][i] = policyIds[i];
            data.policyIdContractMap[policyIds[i]].push(contractAddress);
        }
        emit PolicyApplied(policyIds, contractAddress);
    }

    /**
     * @notice Unapplies policies from a specified contract.
     * @dev Ensures that only calling contract admins can unapply policies. Removes associations between the contract and the specified policies.
     * @param _contractAddress The address of the contract from which policies will be unapplied.
     * @param _policyIds The IDs of the policies to unapply.
     */
    function unapplyPolicy(
        address _contractAddress,
        uint256[] calldata _policyIds
    ) external callingContractAdminOnly(_contractAddress, msg.sender) {
        if (_contractAddress == address(0)) revert(ZERO_ADDRESS);
        // Load the policy association data from storage
        PolicyAssociationStorage storage data = lib._getPolicyAssociationStorage();
        // Get the currently applied policyIds
        uint256[] memory allPolicyIds = data.contractPolicyIdMap[_contractAddress];
        // Blow away the contract to policyId association data in order to keep the associated id's array length in line with the amount of policies associated.
        delete data.contractPolicyIdMap[_contractAddress];
        bool found;
        for (uint256 i = 0; i < allPolicyIds.length; i++) {
            found = false;
            for (uint256 j = 0; j < _policyIds.length; j++) {
                // if the id exists in the unapply list, don't carry it forward
                if (allPolicyIds[i] == _policyIds[j]) found = true;
            }
            if (!found) data.contractPolicyIdMap[_contractAddress].push(allPolicyIds[i]);
        }

        // Get the currently applied policyIds
        address[] memory allContracts = data.policyIdContractMap[_policyIds[0]];
        // Loop through the policyId to contract arrays, clear them and add back only the correct addresses
        for (uint256 i = 0; i < _policyIds.length; i++) {
            // Blow away the policyId to contract association data in order to keep the associated id's array length in line with the amount of contracts associated.
            delete data.policyIdContractMap[_policyIds[i]];
            for (uint256 j = 0; j < allContracts.length; j++) {
                // if the address is not the current address, add it back to the array.
                if (allContracts[j] != _contractAddress) data.policyIdContractMap[_policyIds[i]].push(allContracts[j]);
            }
        }
        emit PolicyUnapplied(_policyIds, _contractAddress);
    }

    /**
     * @notice Creates a new policy and assigns a policy admin.
     * @dev Generates a policy ID and initializes the policy with the specified type.
     * @param policyType The type of the policy (CLOSED_POLICY or OPEN_POLICY).
     * @param policyName The name of the policy.
     * @param policyDescription A description of the policy.
     * @return uint256 The generated policy ID.
     */
    function createPolicy(PolicyType policyType, string calldata policyName, string calldata policyDescription) external returns (uint256) {
        require(uint8(policyType) < 3, POLICY_TYPE_INV);
        // retrieve Policy Storage
        PolicyStorage storage data = lib._getPolicyStorage();
        uint256 policyId = data.policyId;
        // If this is the first policy created increment by 1 to start id counter.
        unchecked {
            ++data.policyId;
        }
        policyId = data.policyId;
        data.policyStorageSets[policyId].set = true;
        data.policyStorageSets[policyId].policy.policyType = policyType;
        //This function is called as an external call intentionally. This allows for proper gating on the generatePolicyAdminRole fn to only be callable by the RulesEngine address.
        RulesEngineAdminRolesFacet(address(this)).generatePolicyAdminRole(policyId, address(msg.sender));
        _storePolicyMetadata(policyId, policyName, policyDescription);
        emit PolicyCreated(policyId);
        return policyId;
    }

    /**
     * @notice Internal function to store policy metadata.
     * @dev This function is a placeholder for storing policy metadata such as name and description.
     * @param _policyId The ID of the policy.
     * @param _policyName The name of the policy.
     * @param _policyDescription A description of the policy.
     */
    function _storePolicyMetadata(uint256 _policyId, string calldata _policyName, string calldata _policyDescription) internal {
        PolicyMetadataStruct storage metadata = lib._getPolicyMetadataStorage();
        metadata.policyMetadata[_policyId].policyName = _policyName;
        metadata.policyMetadata[_policyId].policyDescription = _policyDescription;
    }

    /**
     * @notice Retrieves the metadata of a policy.
     * @param _policyId The ID of the policy to retrieve metadata for.
     * @return PolicyMetadata The metadata of the policy.
     */
    function getPolicyMetadata(uint256 _policyId) external view returns (PolicyMetadata memory) {
        return (lib._getPolicyMetadataStorage().policyMetadata[_policyId]);
    }

    /**
     * @notice Retrieves the IDs of policies applied to a specific contract.
     * @param contractAddress The address of the contract.
     * @return uint256[] An array of applied policy IDs.
     */
    function getAppliedPolicyIds(address contractAddress) external view returns (uint256[] memory) {
        // Load the policy association data from storage
        return lib._getPolicyAssociationStorage().contractPolicyIdMap[contractAddress];
    }

    /**
     * @notice Checks if a policy is closed.
     * @param policyId The ID of the policy to check.
     * @return bool True if the policy is closed, false otherwise.
     */
    function isClosedPolicy(uint256 policyId) external view returns (bool) {
        return (lib._getPolicyStorage().policyStorageSets[policyId].policy.policyType == PolicyType.CLOSED_POLICY);
    }

    /**
     * @notice Checks if a policy is disabled.
     * @param policyId The ID of the policy to check.
     * @return bool True if the policy is disabled, false otherwise.
     */
    function isDisabledPolicy(uint256 policyId) external view returns (bool) {
        return (lib._getPolicyStorage().policyStorageSets[policyId].policy.policyType == PolicyType.DISABLED_POLICY);
    }

    /**
     * @notice Retrieves a policy from storage.
     * @dev Since `Policy` contains nested mappings, the data is broken into arrays for external return.
     * @param policyId The ID of the policy.
     * @return callingFunctions The calling functions within the policy.
     * @return callingFunctionIds The calling function IDs corresponding to each calling function.
     * @return ruleIds The rule IDs corresponding to each calling function.
     */
    function getPolicy(
        uint256 policyId
    ) external view returns (bytes4[] memory callingFunctions, uint256[] memory callingFunctionIds, uint256[][] memory ruleIds) {
        // Load the policy data from storage
        Policy storage policy = lib._getPolicyStorage().policyStorageSets[policyId].policy;
        // Initialize the return arrays if necessary
        if (policy.callingFunctions.length > 0) {
            callingFunctions = new bytes4[](policy.callingFunctions.length);
            callingFunctionIds = new uint256[](policy.callingFunctions.length);
            ruleIds = new uint256[][](policy.callingFunctions.length);
        }
        ruleIds = new uint256[][](policy.callingFunctions.length);
        // Loop through the callng functions and load the return arrays
        // Data validation will alway ensure policy.signatures.length will be less than MAX_LOOP
        for (uint256 i = 0; i < policy.callingFunctions.length; i++) {
            callingFunctions[i] = policy.callingFunctions[i];
            callingFunctionIds[i] = policy.callingFunctionIdMap[policy.callingFunctions[i]];
            // Initialize the ruleId return array if necessary
            // Data validation will alway ensure policy.signatureToRuleIds[policy.callingFunctions[i]].length will be less than MAX_LOOP
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
    function _storePolicyData(
        uint256 _policyId,
        bytes4[] calldata _callingFunctions,
        uint256[] calldata _callingFunctionIds,
        uint256[][] calldata _ruleIds,
        PolicyType _policyType,
        string calldata _policyName,
        string calldata _policyDescription
    ) internal returns (uint256) {
        require(uint8(_policyType) < 3, POLICY_TYPE_INV);
        require(_policyId > 0, POLICY_ID_INV);
        // Load the policy data from storage
        Policy storage data = lib._getPolicyStorage().policyStorageSets[_policyId].policy;

        // Process policy type change and update metadata
        _processPolicyTypeChange(_policyId, _policyType);
        _storePolicyMetadata(_policyId, _policyName, _policyDescription);

        // Clear the iterator array
        delete data.callingFunctions;

        // Validate input lengths
        require(_ruleIds.length < MAX_LOOP, MAX_RULES);
        require(_callingFunctions.length < MAX_LOOP, MAX_CF);

        if (_ruleIds.length > 0) {
            _processCallingFunctionsWithRules(_policyId, _callingFunctions, _callingFunctionIds, _ruleIds, data);
        } else {
            _processCallingFunctionsWithoutRules(_policyId, _callingFunctions, _callingFunctionIds, data);
        }

        emit PolicyUpdated(_policyId);
        return _policyId;
    }

    /**
     * @notice Internal helper function to process calling functions with associated rules.
     * @dev This function validates calling functions, maps them to their IDs, and processes rules for each calling function.
     * @param _policyId The ID of the policy.
     * @param _callingFunctions The function signatures of the calling functions in the policy.
     * @param _callingFunctionIds The IDs of the calling functions.
     * @param _ruleIds A two-dimensional array of rule IDs associated with the policy.
     * @param data The policy data storage structure.
     */
    function _processCallingFunctionsWithRules(
        uint256 _policyId,
        bytes4[] calldata _callingFunctions,
        uint256[] calldata _callingFunctionIds,
        uint256[][] calldata _ruleIds,
        Policy storage data
    ) private {
        for (uint256 i = 0; i < _callingFunctions.length; i++) {
            // Validate calling function
            if (!StorageLib._isCallingFunctionSet(_policyId, _callingFunctionIds[i])) revert(INVALID_SIGNATURE);

            // Map calling function to its ID and add to iterator array
            data.callingFunctionIdMap[_callingFunctions[i]] = _callingFunctionIds[i];
            data.callingFunctions.push(_callingFunctions[i]);

            // Process rules for the calling function
            _processRulesForCallingFunction(_policyId, _callingFunctions[i], _ruleIds[i], data);
        }
    }

    /**
     * @notice Internal helper function to process calling functions without associated rules.
     * @dev This function validates calling functions and maps them to their IDs.
     * @param _policyId The ID of the policy.
     * @param _callingFunctions The function signatures of the calling functions in the policy.
     * @param _callingFunctionIds The IDs of the calling functions.
     * @param data The policy data storage structure.
     */
    function _processCallingFunctionsWithoutRules(
        uint256 _policyId,
        bytes4[] calldata _callingFunctions,
        uint256[] calldata _callingFunctionIds,
        Policy storage data
    ) private {
        for (uint256 i = 0; i < _callingFunctions.length; i++) {
            // Validate calling function
            if (!StorageLib._isCallingFunctionSet(_policyId, _callingFunctionIds[i])) revert(INVALID_SIGNATURE);

            // Map calling function to its ID and add to iterator array
            data.callingFunctionIdMap[_callingFunctions[i]] = _callingFunctionIds[i];
            data.callingFunctions.push(_callingFunctions[i]);
        }
    }

    /**
     * @notice Internal helper function to process rules for a calling function.
     * @dev This function validates placeholders in the rule and maps rules to the calling function.
     * @param _policyId The ID of the policy.
     * @param _callingFunction The function signature of the calling function.
     * @param _ruleIds The IDs of the rules associated with the calling function.
     * @param data The policy data storage structure.
     */
    function _processRulesForCallingFunction(
        uint256 _policyId,
        bytes4 _callingFunction,
        uint256[] calldata _ruleIds,
        Policy storage data
    ) private {
        for (uint256 j = 0; j < _ruleIds.length; j++) {
            RuleStorageSet memory ruleStore = lib._getRuleStorage().ruleStorageSets[_policyId][_ruleIds[j]];
            if (!ruleStore.set) revert(INVALID_RULE);

            // Validate placeholders in the rule
            _validatePlaceholders(_policyId, ruleStore.rule.placeHolders);

            // Map rules to the calling function
            data.callingFunctionsToRuleIds[_callingFunction].push(_ruleIds[j]);
        }
    }

    /**
     * @notice Internal helper function to validate placeholders in a policy.
     * @dev This function checks if the placeholders are set correctly and if foreign calls or trackers are valid.
     * @param _policyId The ID of the policy.
     * @param placeholders The array of placeholders to validate.
     */
    function _validatePlaceholders(uint256 _policyId, Placeholder[] memory placeholders) private view {
        require(placeholders.length < MAX_LOOP, MAX_PLC_HLD);
        for (uint256 k = 0; k < placeholders.length; k++) {
            if (FacetUtils._isForeignCall(placeholders[k])) {
                require(StorageLib._isForeignCallSet(_policyId, placeholders[k].typeSpecificIndex), FOREIGN_CALL_NOT_SET);
            } else if (FacetUtils._isTrackerValue(placeholders[k])) {
                require(StorageLib._isTrackerSet(_policyId, placeholders[k].typeSpecificIndex), TRACKER_NOT_SET);
            }
        }
    }

    /**
     * @notice Internal helper function to handle data cleanup during policy type changes.
     * @dev This function removes applied contract associations when transitioning to a CLOSED policy.
     * @param _policyId The ID of the policy.
     * @param _policyType The new type of the policy (OPEN or CLOSED).
     */
    function _processPolicyTypeChange(uint256 _policyId, PolicyType _policyType) internal {
        // If closing, remove all applied contract associations
        Policy storage data = lib._getPolicyStorage().policyStorageSets[_policyId].policy;
        if (_policyType == PolicyType.CLOSED_POLICY) {
            // Load the calling function data from storage
            PolicyAssociationStorage storage assocData = lib._getPolicyAssociationStorage();
            // Data validation will alway ensure assocData.policyIdContractMap[_policyId].length will be less than MAX_LOOP
            for (uint256 i = 0; i < assocData.policyIdContractMap[_policyId].length; i++) {
                delete assocData.contractPolicyIdMap[assocData.policyIdContractMap[_policyId][i]];
            }
            delete assocData.policyIdContractMap[_policyId];
        }
        data.policyType = _policyType;
    }

    /**
     * @notice Checks if a policy is cemented.
     * @param _policyId The ID of the policy to check.
     * @return bool True if the policy is cemented, false otherwise.
     */
    function isCementedPolicy(uint256 _policyId) external view returns (bool) {
        return lib._getPolicyStorage().policyStorageSets[_policyId].policy.cemented;
    }

    /**
     * @notice Checks that the caller is a policy admin
     * @param _policyId The ID of the policy.
     * @param _address The address to check for policy admin status.
     */
    function _policyAdminOnly(uint256 _policyId, address _address) internal {
        // 0x901cee11 = isPolicyAdmin(uint256,address)
        (bool success, bytes memory res) = _callAnotherFacet(
            0x901cee11,
            abi.encodeWithSignature("isPolicyAdmin(uint256,address)", _policyId, _address)
        );
        bool returnBool;
        if (success) {
            if (res.length >= 4) {
                assembly {
                    returnBool := mload(add(res, 32))
                }
            }
            // returned false so revert with error
            if (!returnBool) revert(NOT_AUTH_POLICY);
        }
    }
}
