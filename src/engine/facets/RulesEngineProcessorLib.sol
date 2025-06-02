// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;
import "src/engine/facets/FacetCommonImports.sol";
library RulesEngineProcessorLib {
    
//-------------------------------------------------------------------------------------------------------------------------------------------------------
// Utility Functions
//-------------------------------------------------------------------------------------------------------------------------------------------------------
    /**
     * @dev converts a uint256 to a bool
     * @param x the uint256 to convert
     */
    function _ui2bool(uint256 x) internal pure returns (bool ans) {
        return x == 1;
    }

    /**
     * @dev converts a bool to an uint256
     * @param x the bool to convert
     */
    function _bool2ui(bool x) internal pure returns (uint256 ans) {
        return x ? 1 : 0;
    }


    /**
     * @dev converts a uint256 to an address
     * @param x the uint256 to convert
     */
    function _ui2addr(uint256 x) internal pure returns (address ans) {
        return address(uint160(x));
    }

    /**
     * @dev converts a uint256 to a bytes
     * @param x the uint256 to convert
     */
    function _ui2bytes(uint256 x) internal pure returns (bytes memory ans) {
        return abi.encode(x);
    }


    /**
     * @notice Helper function to extract the actual string data from an ABI-encoded string
     * @param encodedString The ABI-encoded string to extract the data from
     * @return stringData The extracted string data (length + content)
     */
    function _extractStringData(bytes memory encodedString) internal pure returns (bytes memory) {
        // We want to skip the first 32 bytes (offset) and keep the rest
        require(encodedString.length >= 64, "Invalid encoded string");
        
        // Create result with size needed for everything except the offset
        bytes memory result = new bytes(encodedString.length - 32);
        uint256 dataLength = encodedString.length;
        // Copy the length and data, skipping the offset
        assembly {
            // Copy from position 32 in source to position 0 in result
            let resultPtr := add(result, 32)  // Point to result data area
            let sourcePtr := add(encodedString, 64)  // Skip offset (32) in source
            
            // Copy the length word
            mstore(resultPtr, mload(add(encodedString, 32)))
            let len := div(dataLength, 32)
            
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                mstore(
                    add(resultPtr, mul(i, 32)),
                    mload(add(sourcePtr, mul(i, 32)))
                )
            }
        }
        
        return result;
    }

    /**
    * @notice Extracts a dynamic array (length + values with their lengths) from ABI-encoded data
    * @param encodedArray The ABI-encoded array data
    * @return result The extracted array data
    */
    function _extractDynamicArrayData(bytes memory encodedArray) internal pure returns (bytes memory result) {
        // We need at least the offset (32 bytes) and length (32 bytes)
        require(encodedArray.length >= 64, "Invalid encoded array");
        // Get the array length from the data
        uint256 arrayLength = (encodedArray.length) / 32;
        
        // Create result with the calculated size
        result = new bytes(encodedArray.length - 32);
        
        // Copy the length and array elements
        assembly {
            // Point to the result data area (after length field of bytes array)
            let resultPtr := add(result, 32)
            
            // Point to source data (skip offset)
            let sourcePtr := add(encodedArray, 64)
            
            let len := add(arrayLength, 1)
            // Copy array elements word by word
            for { let i := 0 } lt(i, len) { i := add(i, 1) } {
                mstore(
                    add(resultPtr, mul(i, 32)),  // Start after length
                    mload(add(sourcePtr, mul(i, 32)))
                )
            }
        }
        
        return result;
    }

}