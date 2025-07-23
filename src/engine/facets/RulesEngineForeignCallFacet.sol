// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetCommonImports.sol";
import {console2 as console} from "forge-std/src/console2.sol";

/**
 * @title Rules Engine Foreign Call Facet
 * @dev This contract serves as the data facet for the Rules Engine Foreign Call Components. It provides functionality for managing
 *      foreign calls. It enforces role-based access control
 *      and ensures that only authorized users can modify or retrieve data. The contract also supports policy cementing
 *      to prevent further modifications.
 * @notice This contract is a critical component of the Rules Engine, enabling secure and flexible data management.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract RulesEngineForeignCallFacet is FacetCommonImports {
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
        ForeignCall calldata _foreignCall,
        string calldata foreignCallName
    ) external returns (uint256) {
        _policyAdminOnly(_policyId, msg.sender);
        _notCemented(_policyId);
        _isForeignCallPermissioned(_foreignCall.foreignCallAddress, _foreignCall.signature);
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
    function updateForeignCall(
        uint256 policyId,
        uint256 foreignCallId,
        ForeignCall calldata foreignCall
    ) external returns (ForeignCall memory fc) {
        _policyAdminOnly(policyId, msg.sender);
        _notCemented(policyId);
        _isForeignCallPermissioned(foreignCall.foreignCallAddress, foreignCall.signature);
        fc = foreignCall;
        if (fc.foreignCallAddress == address(0)) revert(ZERO_ADDRESS);
        fc.foreignCallIndex = foreignCallId;
        _storeForeignCallData(policyId, foreignCall, foreignCallId);
        emit ForeignCallUpdated(policyId, foreignCallId);
    }

    /**
     * @notice Deletes a foreign call from the contract's storage.
     * @param policyId The policy ID the foreign call is associated with.
     * @param foreignCallId The ID of the foreign call to delete.
     */
    function deleteForeignCall(uint256 policyId, uint256 foreignCallId) external {
        _policyAdminOnly(policyId, msg.sender);
        _notCemented(policyId);
        delete lib._getForeignCallStorage().foreignCalls[policyId][foreignCallId];
        emit ForeignCallDeleted(policyId, foreignCallId);
    }

    /**
     * @dev Retrieve Foreign Call Set from storage
     * @param policyId the policy Id of the foreign call to retrieve
     * @return the foreign call set structure
     */
    function getAllForeignCalls(uint256 policyId) external view returns (ForeignCall[] memory) {
        // Return the Foreign Call Set data from storage
        uint256 foreignCallCount = lib._getForeignCallStorage().foreignCallIdxCounter[policyId];
        ForeignCall[] memory foreignCalls = new ForeignCall[](foreignCallCount);
        uint256 j = 0;
        for (uint256 i = 0; i <= foreignCallCount; i++) {
            if (lib._getForeignCallStorage().foreignCalls[policyId][i].set) {
                foreignCalls[j] = lib._getForeignCallStorage().foreignCalls[policyId][i];
                j++;
            }
        }
        return foreignCalls;
    }

    /**
     * @notice Retrieves a foreign call from the contract's storage.
     * @param policyId The policy ID of the foreign call to retrieve.
     * @param foreignCallId The ID of the foreign call to retrieve.
     * @return The foreign call structure.
     */
    function getForeignCall(uint256 policyId, uint256 foreignCallId) public view returns (ForeignCall memory) {
        // Load the Foreign Call data from storage
        return lib._getForeignCallStorage().foreignCalls[policyId][foreignCallId];
    }

    /**
     * @notice retrieves the foreign call metadata
     * @param policyId The policy ID the foreign call is associated with.
     * @param foreignCallId The identifier for the foreign call
     * @return the metadata for the foreign call
     */
    function getForeignCallMetadata(uint256 policyId, uint256 foreignCallId) public view returns (string memory) {
        return lib._getForeignCallMetadataStorage().foreignCallMetadata[policyId][foreignCallId];
    }

    /**
     * @notice Stores a foreign call in the contract's storage.
     * @dev Ensures the foreign call is properly set before storing it.
     * @param _policyId The policy ID the foreign call is associated with.
     * @param _foreignCall The foreign call to store.
     */
    function _storeForeignCall(uint256 _policyId, ForeignCall calldata _foreignCall, uint256 _foreignCallIndex) internal {
        assert(_foreignCall.parameterTypes.length == _foreignCall.encodedIndices.length);
        require(_foreignCall.foreignCallIndex < MAX_LOOP, "Max foreign calls reached.");
        require(_foreignCall.parameterTypes.length < MAX_LOOP, "Max foreign parameter types reached.");
        uint mappedTrackerKeyIndexCounter = 0;
        console.log("encodedIndices length", _foreignCall.encodedIndices.length);
        console.log("mappedTrackerKeyIndices length", _foreignCall.mappedTrackerKeyIndices.length);
        console.log("mappedTrackerKeyIndexCounter", mappedTrackerKeyIndexCounter);
        for (uint256 i = 0; i < _foreignCall.encodedIndices.length; i++) {
            if (_foreignCall.encodedIndices[i].eType == EncodedIndexType.MAPPED_TRACKER_KEY) {
                require(mappedTrackerKeyIndexCounter < _foreignCall.mappedTrackerKeyIndices.length, "Mapped tracker key indices length mismatch.");
                require(_foreignCall.mappedTrackerKeyIndices[mappedTrackerKeyIndexCounter].eType != EncodedIndexType.MAPPED_TRACKER_KEY, "Mapped tracker key cannot be double nested");
                mappedTrackerKeyIndexCounter++;
            }
        }
        require(mappedTrackerKeyIndexCounter == _foreignCall.mappedTrackerKeyIndices.length, "Mapped tracker key indices length mismatch.");
        lib._getForeignCallStorage().foreignCalls[_policyId][_foreignCallIndex] = _foreignCall;
        lib._getForeignCallStorage().foreignCalls[_policyId][_foreignCallIndex].set = true;
        lib._getForeignCallStorage().foreignCalls[_policyId][_foreignCallIndex].foreignCallIndex = _foreignCallIndex;
    }

    /**
     * @dev Helper function to increment the foreign call index
     * @dev Ensures the foreign call is properly set before storing it.
     * @param _policyId The policy ID the foreign call is associated with.
     */
    function _incrementForeignCallIndex(uint256 _policyId) private returns (uint256) {
        ForeignCallStorage storage data = lib._getForeignCallStorage();
        return ++data.foreignCallIdxCounter[_policyId];
    }

    /**
     * @dev Helper function to store the foreign call data
     * @dev Ensures the foreign call is properly set before storing it.
     * @param _policyId The policy ID the foreign call is associated with.
     * @param _foreignCall The foreign call to store.
     * @param _foreignCallIndex The index of the foreign call.
     */
    function _storeForeignCallData(uint256 _policyId, ForeignCall calldata _foreignCall, uint256 _foreignCallIndex) private {
        ForeignCallStorage storage data = lib._getForeignCallStorage();
        _storeForeignCall(_policyId, _foreignCall, _foreignCallIndex);
        data.foreignCallIdxCounter[_policyId] = _foreignCallIndex;
    }

    /**
     * @dev Helper function to store the foreign call metadata
     * @param _policyId The policy ID the foreign call is associated with.
     * @param _foreignCallIndex The index of the foreign call.
     * @param _foreignCallName The name of the foreign call.
     */
    function _storeForeignCallMetadata(uint256 _policyId, uint256 _foreignCallIndex, string calldata _foreignCallName) private {
        lib._getForeignCallMetadataStorage().foreignCallMetadata[_policyId][_foreignCallIndex] = _foreignCallName;
    }

    /**
     * @notice Checks if the foreign call is permissioned and if the caller is authorized.
     * @param _foriegnCallAddress The address of the foreign call contract.
     * @param _functionSignature The function signature of the foreign call.
     */
    function _isForeignCallPermissioned(address _foriegnCallAddress, bytes4 _functionSignature) internal view {
        // look up the foreign call in the permissioned foreign call storage to see if it is permissioned
        if (
            lib._getForeignCallStorage().isPermissionedForeignCall[_foriegnCallAddress][_functionSignature] &&
            !lib._getForeignCallStorage().permissionedForeignCallAdmins[_foriegnCallAddress][_functionSignature][msg.sender]
        ) revert(NOT_PERMISSIONED_FOR_FOREIGN_CALL);
    }

    /**
     * @notice Adds an admin to the permission list for a foreign call.
     * @dev This function can only be called by an existing foreign call admin.
     * @param foriegnCallAddress The address of the foreign call contract.
     * @param policyAdminsToAdd The address of the admin to add to the permission list.
     * @param selector The function selector of the foreign call to add the admin to.
     */
    function addAdminToPermissionList(address foriegnCallAddress, address policyAdminsToAdd, bytes4 selector) external {
        _foreignCallAdminOnly(foriegnCallAddress, msg.sender, selector);
        // add single address to the permission list for the foreign call
        lib._getForeignCallStorage().permissionedForeignCallAdminsList[foriegnCallAddress][selector].push(policyAdminsToAdd);
        // add single address to the permission mapping
        lib._getForeignCallStorage().permissionedForeignCallAdmins[foriegnCallAddress][selector][policyAdminsToAdd] = true;
        // emit event
        emit AdminAddedToForeignCallPermissions(foriegnCallAddress, selector, policyAdminsToAdd);
    }

    /**
     * @notice Updates the permission list for a foreign call.
     * @dev This function can only be called by an existing foreign call admin.
     * @param foriegnCallAddress The address of the foreign call contract.
     * @param selector The function selector of the foreign call to update the permission list for.
     * @param policyAdminsToAdd The addresses of the admins to add to the permission list.
     */
    function updatePermissionList(address foriegnCallAddress, bytes4 selector, address[] memory policyAdminsToAdd) external {
        _foreignCallAdminOnly(foriegnCallAddress, msg.sender, selector);
        // reset mappings and arrays to empty
        delete lib._getForeignCallStorage().permissionedForeignCallAdminsList[foriegnCallAddress][selector];
        // retreive current list and set all addresses in the current list to false (remove them from the permission list)
        address[] memory oldAdminList = getForeignCallPermissionList(foriegnCallAddress, selector);
        for (uint256 i = 0; i < oldAdminList.length; i++) {
            lib._getForeignCallStorage().permissionedForeignCallAdmins[foriegnCallAddress][selector][oldAdminList[i]] = false;
        }

        // add all addresses to the permission list for the foreign call
        for (uint256 i = 0; i < policyAdminsToAdd.length; i++) {
            lib._getForeignCallStorage().permissionedForeignCallAdminsList[foriegnCallAddress][selector].push(policyAdminsToAdd[i]);
            lib._getForeignCallStorage().permissionedForeignCallAdmins[foriegnCallAddress][selector][policyAdminsToAdd[i]] = true;
            // emit event
            emit AdminAddedToForeignCallPermissions(foriegnCallAddress, selector, policyAdminsToAdd[i]);
        }
        // emit list of addresses added to the permission list
        emit ForeignCallPermissionsListUpdate(foriegnCallAddress, selector, policyAdminsToAdd);
    }

    /**
     * @notice Retrieves the permission list for a foreign call.
     * @param foriegnCallAddress The address of the foreign call contract.
     * @param selector The function selector of the foreign call to retrieve the permission list for.
     * @return An array of addresses that are permissioned for the foreign call.
     */
    function getForeignCallPermissionList(address foriegnCallAddress, bytes4 selector) public view returns (address[] memory) {
        // return the permissioned foreign call admins for the foreign call address and selector
        return lib._getForeignCallStorage().permissionedForeignCallAdminsList[foriegnCallAddress][selector];
    }

    /**
     * @notice Removes all addresses from the permission list for a foreign call.
     * @notice This function resets the permission list to only include the foreign call admin.
     * @dev This function can only be called by an existing foreign call admin.
     * @param foriegnCallAddress The address of the foreign call contract.
     * @param selector The function selector of the foreign call to remove all permissions from.
     */
    function removeAllFromPermissionList(address foriegnCallAddress, bytes4 selector) external {
        _foreignCallAdminOnly(foriegnCallAddress, msg.sender, selector);
        // reset mappings and arrays to empty
        delete lib._getForeignCallStorage().permissionedForeignCallAdminsList[foriegnCallAddress][selector];
        address[] memory oldAdminList = getForeignCallPermissionList(foriegnCallAddress, selector);
        for (uint256 i = 1; i < oldAdminList.length; i++) {
            // index starts at one to skip the foreign call admin address
            lib._getForeignCallStorage().permissionedForeignCallAdmins[foriegnCallAddress][selector][oldAdminList[i]] = false;
        }
        // re create the Foreign Call admin list with the first admin
        lib._getForeignCallStorage().permissionedForeignCallAdminsList[foriegnCallAddress][selector].push(msg.sender);
        // emit event
        emit ForeignCallPermissionsListReset(foriegnCallAddress, selector);
    }

    /**
     * @notice Removes a specific address from the permission list for a foreign call.
     * @dev This function can only be called by an existing foreign call admin.
     * @param _foriegnCallAddress The address of the foreign call contract.
     * @param _selector The function selector of the foreign call to remove the address from.
     * @param policyAdminToRemove The address of the admin to remove from the permission list.
     */
    function removeFromPermissionList(address _foriegnCallAddress, bytes4 _selector, address policyAdminToRemove) external {
        _foreignCallAdminOnly(_foriegnCallAddress, msg.sender, _selector);
        // remove the address from the permission list for the foreign call
        lib._getForeignCallStorage().permissionedForeignCallAdmins[_foriegnCallAddress][_selector][policyAdminToRemove] = false;
        // remove the address from the permissioned foreign call admins list
        address[] storage adminList = lib._getForeignCallStorage().permissionedForeignCallAdminsList[_foriegnCallAddress][_selector];
        for (uint256 i = 0; i < adminList.length; i++) {
            if (adminList[i] == policyAdminToRemove) {
                adminList[i] = adminList[adminList.length - 1]; // Move last element to current position
                adminList.pop(); // Remove last element
                break;
            }
        }
        // emit event
        emit ForeignCallPermissionsListUpdate(_foriegnCallAddress, _selector, adminList);
    }

    /**
     * @notice Removes foreign call permissions from the contract address and selector pair.
     * @dev This function can only be called by an existing foreign call admin.
     * @param _foriegnCallAddress The address of the foreign call contract.
     * @param _selector The function selector of the foreign call to remove permissions for.
     */
    function removeForeignCallPermissions(address _foriegnCallAddress, bytes4 _selector) external {
        _foreignCallAdminOnly(_foriegnCallAddress, msg.sender, _selector);
        // reset mappings and arrays to empty
        delete lib._getForeignCallStorage().permissionedForeignCallAdminsList[_foriegnCallAddress][_selector];
        // retreive current list and set all addresses in the current list to false (remove them from the permission list)
        address[] memory oldAdminList = getForeignCallPermissionList(_foriegnCallAddress, _selector);
        for (uint256 i = 0; i < oldAdminList.length; i++) {
            lib._getForeignCallStorage().permissionedForeignCallAdmins[_foriegnCallAddress][_selector][oldAdminList[i]] = false;
        }

        // remove from permissioned foreign call master list and map
        lib._getForeignCallStorage().isPermissionedForeignCall[_foriegnCallAddress][_selector] = false;
        address[] storage pfcAddressList = lib._getPermissionedForeignCallStorage().permissionedForeignCallAddresses;
        bytes4[] storage pfcSelectorsList = lib._getPermissionedForeignCallStorage().permissionedForeignCallSignatures;
        for (uint256 i = 0; i < pfcAddressList.length; i++) {
            if (pfcAddressList[i] == _foriegnCallAddress && pfcSelectorsList[i] == _selector) {
                // Move last element to current position
                pfcAddressList[i] = pfcAddressList[pfcAddressList.length - 1];
                pfcSelectorsList[i] = pfcSelectorsList[pfcSelectorsList.length - 1];
                // Remove last element
                pfcAddressList.pop();
                pfcSelectorsList.pop();
                break;
            }
        }

        // emit event
        emit ForeignCallPermissionsRemoved(_foriegnCallAddress, _selector);
    }

    /**
     * @notice Retrieves all permissioned foreign calls.
     * @return The PermissionedForeignCallStorage structure containing all permissioned foreign calls.
     */
    function getAllPermissionedFCs() external pure returns (PermissionedForeignCallStorage memory) {
        return lib._getPermissionedForeignCallStorage();
    }

    /**
     * @notice Checks that a policy is not cemented.
     * @param _policyId The ID of the policy.
     */
    function _notCemented(uint256 _policyId) internal view {
        if (lib._getPolicyStorage().policyStorageSets[_policyId].policy.cemented) revert("Not allowed for cemented policy");
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
            } else {
                returnBool = false;
            }
            // returned false so revert with error
            if (!returnBool) revert("Not Authorized To Policy");
        }
    }

    /**
     * @notice Checks that the caller is a policy admin
     * @param _foreignCallAddr The ID of the foreign call.
     * @param _address The address to check for policy admin status.
     * @param _functionSelector The function selector to check for policy admin status.
     */
    function _foreignCallAdminOnly(address _foreignCallAddr, address _address, bytes4 _functionSelector) internal {
        // 0x41a2b7ae = isForeignCallAdmin(address,address,bytes4)
        (bool success, bytes memory res) = _callAnotherFacet(
            0x41a2b7ae,
            abi.encodeWithSignature("isForeignCallAdmin(address,address,bytes4)", _foreignCallAddr, _address, _functionSelector)
        );
        bool returnBool;
        if (success) {
            if (res.length >= 4) {
                assembly {
                    returnBool := mload(add(res, 32))
                }
            } else {
                returnBool = false;
            }
            // returned false so revert with error
            if (!returnBool) revert("Not An Authorized Foreign Call Admin");
        }
    }
}
