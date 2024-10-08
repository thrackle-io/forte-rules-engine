// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

struct VersionStorage{
    string version;
}

/**
 * @title Protocol Version Facet Library 
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett
 * @dev the library that handles the storage for the Version facet
 */
library VersionFacetLib {
     bytes32 constant VERSION_DATA_POSITION = keccak256("protocol-version");

    /**
     * @dev Function to access the version data
     * @return v Data storage for version
     */
    function versionStorage() internal pure returns (VersionStorage storage v) {
        bytes32 position = VERSION_DATA_POSITION;
        assembly {
            v.slot := position
        }
    }

}
