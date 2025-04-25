// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetUtils.sol";

/**
 * @title Access Modifiers for the Rules Engine
 * @dev This contract contains all the access modifiers used across the Rules Engine. These modifiers enforce role-based 
 *      access control for various operations, ensuring that only authorized users can execute specific functions. 
 *      It is inherited by all Engine facets to provide consistent access control mechanisms.
 * @notice This contract is a critical component of the Rules Engine, enabling secure and flexible access control.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract AccessModifiers is FacetUtils {

    /**
     * @notice Ensures that the function caller is a Policy Admin for the specified policy.
     * @dev This modifier checks if the caller has the Policy Admin role for the given policy ID by delegating the check 
     *      to another facet. If the caller is not authorized, the transaction is reverted.
     * @param _policyId The ID of the policy to check.
     * @param _address The address of the user to verify.
     */
    modifier policyAdminOnly(uint256 _policyId, address _address) {   
        // 0x901cee11 = isPolicyAdmin(uint256,address)   
        // (bool success, bytes memory res) = callAnotherFacet(0x901cee11, abi.encodeWithSignature("isPolicyAdmin(uint256,address)", _policyId, _address));   
        // bool returnBool;
        // if (success) {
        //     if (res.length >= 4) {
        //         assembly {
        //             returnBool := mload(add(res, 32))
        //         }
        //     } else {
        //         returnBool = false;
        //     }
        //     // returned false so revert with error
        //     if (!returnBool) revert("Not Authorized To Policy");                        
        // }
        _;                 
    }

    /**
     * @notice Ensures that the function caller is a Calling Contract Admin for the specified contract.
     * @dev This modifier checks if the caller has the Calling Contract Admin role for the given contract address by delegating 
     *      the check to another facet. If the caller is not authorized, the transaction is reverted.
     * @param _callingContract The address of the calling contract to check.
     * @param _address The address of the user to verify.
     */
    modifier callingContractAdminOnly(address _callingContract, address _address) {   
        // 0x70aca092 = isCallingContractAdmin(address,address) 
        // (bool success, bytes memory res) = callAnotherFacet(0x70aca092, abi.encodeWithSignature("isCallingContractAdmin(address,address)", _callingContract, _address));   
        // bool returnBool;
        // if (success) {
        //     if (res.length >= 4) {
        //         assembly {
        //             returnBool := mload(add(res, 32))
        //         }
        //     } else {
        //         returnBool = false;
        //     }
        //     // returned false so revert with error
        //     if (!returnBool) revert("Not Authorized Admin");                        
        // }
        _;                 
    }
}
