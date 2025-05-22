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

}