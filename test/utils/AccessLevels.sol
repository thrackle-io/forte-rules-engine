// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;



/**
 * @dev This is a test contract to act as a callable contract for retrieving an access level of an address 
 */
contract AccessLevels {


    mapping(address => uint8) accessLevel; 
    /**
     * @dev Add the Access Level to the account. Restricted to the owner
     * @param _address address of the account
     * @param _level access level(0-4)
     */
    function addLevel(address _address, uint8 _level) public  {
        if (_level > 4) revert("AccessLevelIsNotValid");
        if (_address == address(0)) revert("ZeroAddress");
        accessLevel[_address] = _level;
    }

    /**
     * @dev Get the Access Level for the account.
     * @param _account address of the account
     * @return level Access Level(0-4)
     */
    function getAccessLevel(address _account) external view returns (uint8) {
        return (accessLevel[_account]);
    }

    /**
     * @dev Remove the Access Level for the account. Restricted to the owner
     * @param _account address of the account
     */
    function removeAccessLevel(address _account) external  {
        delete accessLevel[_account];
    }


}
