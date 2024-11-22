// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "src/RulesStorageStructure.sol";

/**
 * @title Library for encoding foreign call return values
 * @author @mpetersoCode55 
 */
library FCEncodingLib {

    function getFCAddress(RulesStorageStructure.ForeignCallReturnValue memory retVal) internal pure returns (address) {
        assert(retVal.pType == RulesStorageStructure.PT.ADDR);
        return abi.decode(retVal.value, (address));
    }

    function getFCString(RulesStorageStructure.ForeignCallReturnValue memory retVal) internal pure returns (string memory) {
        assert(retVal.pType == RulesStorageStructure.PT.STR);
        return abi.decode(retVal.value, (string));
    }

    function getFCUint(RulesStorageStructure.ForeignCallReturnValue memory retVal) internal pure returns (uint256) {
        assert(retVal.pType == RulesStorageStructure.PT.UINT);
        return abi.decode(retVal.value, (uint256));
    }

    function getFCBool(RulesStorageStructure.ForeignCallReturnValue memory retVal) internal pure returns (bool) {
        assert(retVal.pType == RulesStorageStructure.PT.BOOL);
        return abi.decode(retVal.value, (bool));
    }
}
