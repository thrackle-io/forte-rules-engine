// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./IRulesEngine.sol";

/**
 * @title Rules Engine Client
 * @dev Abstract contract that provides functionality to connect and interact with the Rules Engine.
 *      This contract includes methods to set the Rules Engine address, invoke the Rules Engine, 
 *      and manage calling contract admin roles.
 * @notice This contract is intended to be inherited by other contracts that require Rules Engine integration.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
abstract contract RulesEngineClient {

    /// @notice Address of the Rules Engine contract
    address public rulesEngineAddress;

    /**
     * @notice Sets the address of the Rules Engine contract.
     * @dev This function should be overridden in inheriting contracts to implement role-based access control.
     * @param rulesEngine The address of the Rules Engine contract.
     */
    function setRulesEngineAddress(address rulesEngine) public virtual {
        rulesEngineAddress = rulesEngine;
    }

    /**
     * @notice Invokes the Rules Engine to evaluate policies.
     * @dev This function calls the `checkPolicies` function of the Rules Engine. 
     *      The `encoded` parameter must be properly encoded using `abi.encodeWithSelector`.
     *      Example: `bytes memory encoded = abi.encodeWithSelector(msg.sig, to, value, msg.sender);`
     * @param encoded The encoded data to be passed to the Rules Engine.
     * @return retval The return value from the Rules Engine, representing the result of the policy evaluation.
     */
    function _invokeRulesEngine(bytes memory encoded) internal returns (uint256 retval) {
        if (rulesEngineAddress != address(0)) {
            return IRulesEngine(rulesEngineAddress).checkPolicies(address(this), encoded);
        }
    }

    /**
     * @notice Sets the admin role for the calling contract in the Rules Engine.
     * @dev This function assigns the admin role for the calling contract to the specified address.
     * @param callingContractAdmin The address to be assigned as the admin for the calling contract.
     */
    function setCallingContractAdmin(address callingContractAdmin) external {
        IRulesEngine(rulesEngineAddress).grantCallingContractRole(address(this), callingContractAdmin);
    }
}