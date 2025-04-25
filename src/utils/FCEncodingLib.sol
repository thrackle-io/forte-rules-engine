// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "src/engine/RulesEngineStorageStructure.sol";

/**
 * @title Library for Encoding Foreign Call Return Values
 * @dev This library provides utility functions for decoding foreign call return values into their respective data types. 
 *      It ensures that the return values are properly decoded based on their parameter types (PT) as defined in the 
 *      Rules Engine Storage Structure. The library is designed to work with the Rules Engine's foreign call functionality.
 * @notice This library is a critical component for handling foreign call return values in the Rules Engine.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
library FCEncodingLib {

    /**
     * @notice Decodes a foreign call return value into an address.
     * @dev Ensures that the parameter type is `PT.ADDR` before decoding.
     * @param retVal The foreign call return value to decode.
     * @return address The decoded address.
     */
    function getFCAddress(ForeignCallReturnValue memory retVal) internal pure returns (address) {
        assert(retVal.pType == PT.ADDR);
        return abi.decode(retVal.value, (address));
    }

    /**
     * @notice Decodes a foreign call return value into a string.
     * @dev Ensures that the parameter type is `PT.STR` before decoding.
     * @param retVal The foreign call return value to decode.
     * @return string The decoded string.
     */
    function getFCString(ForeignCallReturnValue memory retVal) internal pure returns (string memory) {
        assert(retVal.pType == PT.STR);
        return abi.decode(retVal.value, (string));
    }

    /**
     * @notice Decodes a foreign call return value into a uint256.
     * @dev Ensures that the parameter type is `PT.UINT` before decoding.
     * @param retVal The foreign call return value to decode.
     * @return uint256 The decoded unsigned integer.
     */
    function getFCUint(ForeignCallReturnValue memory retVal) internal pure returns (uint256) {
        assert(retVal.pType == PT.UINT);
        return abi.decode(retVal.value, (uint256));
    }

    /**
     * @notice Decodes a foreign call return value into a boolean.
     * @dev Ensures that the parameter type is `PT.BOOL` before decoding.
     * @param retVal The foreign call return value to decode.
     * @return bool The decoded boolean value.
     */
    function getFCBool(ForeignCallReturnValue memory retVal) internal pure returns (bool) {
        assert(retVal.pType == PT.BOOL);
        return abi.decode(retVal.value, (bool));
    }
}
