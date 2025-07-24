// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetCommonImports.sol";

library RulesEngineStorageLib {
    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Internal Validation Functions
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /// This section is for internal functions used for validation of components. They are here to optimize gas consumption.

    /**
     * @notice Checks if a calling function is set for the specified policy.
     * @dev Validates whether the calling function exists in the policy's storage.
     * @param _policyId The ID of the policy the calling function is associated with.
     * @param _callingFunctionId The ID of the calling function to check.
     * @return set True if the calling funciton is set, false otherwise.
     */
    function _isCallingFunctionSet(uint256 _policyId, uint256 _callingFunctionId) internal view returns (bool) {
        // Load the calling function data from storage
        return lib._getCallingFunctionStorage().callingFunctionStorageSets[_policyId][_callingFunctionId].set;
    }

    /**
     * @notice Checks if a foreign call is set for the specified policy.
     * @dev Validates whether the foreign call exists in the policy's storage.
     * @param _policyId The ID of the policy the foreign call is associated with.
     * @param _foreignCallId The ID of the foreign call to check.
     * @return set True if the foreign call is set, false otherwise.
     */
    function _isForeignCallSet(uint256 _policyId, uint256 _foreignCallId) internal view returns (bool) {
        // Load the Foreign Call data from storage
        return lib._getForeignCallStorage().foreignCalls[_policyId][_foreignCallId].set;
    }

    /**
     * @notice Checks if a tracker is set for the specified policy.
     * @dev Validates whether the tracker exists in the policy's storage.
     * @param _policyId The ID of the policy the tracker is associated with.
     * @param _index The index of the tracker to check.
     * @return set True if the tracker is set, false otherwise.
     */
    function _isTrackerSet(uint256 _policyId, uint256 _index) internal view returns (bool) {
        // return trackers for contract address at speficic index
        return lib._getTrackerStorage().trackers[_policyId][_index].set;
    }

    /**
     * @notice Checks that a policy is not cemented.
     * @param _policyId The ID of the policy.
     */
    function _notCemented(uint256 _policyId) internal view {
        if (lib._getPolicyStorage().policyStorageSets[_policyId].policy.cemented) revert(NOT_ALLOWED_CEMENTED_POLICY);
    }
}
