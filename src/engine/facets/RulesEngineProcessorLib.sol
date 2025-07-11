// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;
import "src/engine/facets/FacetCommonImports.sol";
library RulesEngineProcessorLib {
    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Utility Functions
    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    /**
     * @dev converts a uint256 to a bool
     * @param _x the uint256 to convert
     */
    function _uintToBool(uint256 _x) internal pure returns (bool) {
        return _x == 1;
    }

    /**
     * @dev converts a bool to an uint256
     * @param _x the bool to convert
     */
    function _boolToUint(bool _x) internal pure returns (uint256 _ans) {
        assembly {
            _ans := _x
        }
    }

    /**
     * @dev converts a uint256 to an address
     * @param _x the uint256 to convert
     */
    function _uintToAddr(uint256 _x) internal pure returns (address) {
        return address(uint160(_x));
    }

    /**
     * @dev converts a uint256 to a bytes
     * @param _x the uint256 to convert
     */
    function _uintToBytes(uint256 _x) internal pure returns (bytes memory) {
        return abi.encode(_x);
    }

    /**
     * @notice Helper function to extract the actual string data from an ABI-encoded string
     * @param _encodedString The ABI-encoded string to extract the data from
     * @return stringData The extracted string data (length + content)
     */
    function _extractStringData(bytes memory _encodedString) internal pure returns (bytes memory) {
        // We want to skip the first 32 bytes (offset) and keep the rest
        require(_encodedString.length >= 64, "Invalid encoded string");

        // Create result with size needed for everything except the offset
        bytes memory result = new bytes(_encodedString.length - 32);
        uint256 dataLength = _encodedString.length;
        // Copy the length and data, skipping the offset
        assembly {
            // Copy from position 32 in source to position 0 in result
            let resultPtr := add(result, 32) // Point to result data area
            let sourcePtr := add(_encodedString, 64) // Skip offset (32) in source

            // Copy the length word
            mstore(resultPtr, mload(add(_encodedString, 32)))
            let len := div(dataLength, 32)

            for {
                let i := 0
            } lt(i, len) {
                i := add(i, 1)
            } {
                mstore(add(resultPtr, mul(i, 32)), mload(add(sourcePtr, mul(i, 32))))
            }
        }

        return result;
    }

    /**
     * @notice Extracts a dynamic array (length + values with their lengths) from ABI-encoded data
     * @param _encodedArray The ABI-encoded array data
     * @return _result The extracted array data
     */
    function _extractDynamicArrayData(bytes memory _encodedArray) internal pure returns (bytes memory _result) {
        // We need at least the offset (32 bytes) and length (32 bytes)
        require(_encodedArray.length >= 64, "Invalid encoded array");
        // Get the array length from the data
        uint256 arrayLength = (_encodedArray.length) / 32;

        // Create result with the calculated size
        _result = new bytes(_encodedArray.length - 32);

        // Copy the length and array elements
        assembly {
            // Point to the result data area (after length field of bytes array)
            let resultPtr := add(_result, 32)

            // Point to source data (skip offset)
            let sourcePtr := add(_encodedArray, 64)

            let len := add(arrayLength, 1)
            // Copy array elements word by word
            for {
                let i := 0
            } lt(i, len) {
                i := add(i, 1)
            } {
                mstore(
                    add(resultPtr, mul(i, 32)), // Start after length
                    mload(add(sourcePtr, mul(i, 32)))
                )
            }
        }

        return _result;
    }
}
