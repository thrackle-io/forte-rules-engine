// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @title Denied and Permission Oracle Interface
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett
 * @notice This stores the function signature for external oracles
 * @dev Both "allow list" and "deny list" oracles will use this interface
 */
interface IOracle {
    /**
     * @dev This function checks to see if the address is on the oracle's denied list. This is the DENIED_LIST type.
     * @param _address Account address to check
     * @return denied returns true if denied, false if not
     */
    function isDenied(address _address) external view returns (bool);

    /**
     * @dev This function checks to see if the address is on the oracle's allowed list. This is the ALLOWED_LIST type.
     * @param _address Account address to check
     * @return denied returns true if allowed, false if not
     */
    function isAllowed(address _address) external view returns (bool);
}
