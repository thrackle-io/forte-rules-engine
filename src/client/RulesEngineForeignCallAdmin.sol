/// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "./IRulesEngine.sol";

/**
 * @title Rules Engine Foriegn Call Admin
 * @dev Abstract contract that provides functionality to connect and interact with the Rules Engine.
 *      This contract includes methods to set the Rules Engine address and set the foreign call admin role.
 * @notice This contract is intended to be inherited by other contracts that serve as permissioned foreign call contracts for policies.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220, @Palmerg4
 */

abstract contract RulesEngineForeignCallAdmin {
    /// @notice Address of the Rules Engine contract
    address public rulesEngineAddress;

    /**
     * @notice Sets the admin role for the calling contract in the Rules Engine.
     * @notice This function must be called per function signature. The admin role will be granted for the contract address and signature pair.
     * @dev This function is intended to be overridden by the contract that implements the foreign call and used in conjuction with role based admin controls.
     * @dev This function assigns the admin role for the calling contract to the specified address.
     * @param foreignCallAdmin The address to be assigned as the admin for the calling contract.
     * @param foreignCallSelector selector for the foreign call function to be registered as a permissioned foreign call.
     */
    function setForeignCallAdmin(address foreignCallAdmin, bytes4 foreignCallSelector) external virtual {
        IRulesEngine(rulesEngineAddress).grantForeignCallAdminRole(address(this), foreignCallAdmin, foreignCallSelector);
    }

    /**
     * @notice Sets the address of the Rules Engine contract.
     * @dev This function should be overridden in inheriting contracts to implement role-based access control.
     * @param rulesEngine The address of the Rules Engine contract.
     */
    function setRulesEngineAddress(address rulesEngine) public virtual {
        rulesEngineAddress = rulesEngine;
    }
}
