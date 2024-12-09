// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "src/engine/RulesEngineStorageStructure.sol";

/**
 * @title Library for encoding foreign call return values
 * @author @mpetersoCode55 
 */
library FCEncodingLib {

    function getFCAddress(ForeignCallReturnValue memory retVal) internal pure returns (address) {
        assert(retVal.pType == PT.ADDR);
        return abi.decode(retVal.value, (address));
    }

    function getFCString(ForeignCallReturnValue memory retVal) internal pure returns (string memory) {
        assert(retVal.pType == PT.STR);
        return abi.decode(retVal.value, (string));
    }

    function getFCUint(ForeignCallReturnValue memory retVal) internal pure returns (uint256) {
        assert(retVal.pType == PT.UINT);
        return abi.decode(retVal.value, (uint256));
    }

    function getFCBool(ForeignCallReturnValue memory retVal) internal pure returns (bool) {
        assert(retVal.pType == PT.BOOL);
        return abi.decode(retVal.value, (bool));
    }
}
