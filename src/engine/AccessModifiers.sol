// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetUtils.sol";

/**
 * @title Access modifiers for the Rules Engine
 * @author @ShaneDuncan602 
 * @dev This contains all the access modifiers for the Rules Engine. It is inherited by all Engine facets.
 */
contract AccessModifiers is FacetUtils {

    /**
     * @dev Modifier ensures function caller is a Policy Admin for the specific policy
     * @param _policyId Address of App Manager
     * @param _address user address
     */
    modifier policyAdminOnly(uint256 _policyId, address _address) {   
        // // 0x901cee11 = isPolicyAdmin(uint256,address)   
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
     * @dev Modifier ensures function caller is a Calling Contract Admin for the specific policy
     * @param _callingContract Address of App Manager
     * @param _address user address
     */
    modifier callingContractAdminOnly(address _callingContract, address _address) {   
    //     // 0x70aca092 = isCallingContractAdmin(address,address) 
    //     (bool success, bytes memory res) = callAnotherFacet(0x70aca092, abi.encodeWithSignature("isCallingContractAdmin(address,address)", _callingContract, _address));   
    //     bool returnBool;
    //     if (success) {
    //         if (res.length >= 4) {
    //             assembly {
    //                 returnBool := mload(add(res, 32))
    //             }
    //         } else {
    //             returnBool = false;
    //         }
    //         // returned false so revert with error
    //         if (!returnBool) revert("Not Authorized Admin");                        
    //     }
    //     _;                 
    // }
        _;
    }
}
