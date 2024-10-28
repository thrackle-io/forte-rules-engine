// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "src/RulesEngineStructures.sol";

/**
 * @title Library for users to encode their rule enabled functions arguments
 * @author  @mpetersoCode55 
 */
library RuleEncodingLibrary {

    /**
     * @dev encode the arguments for a rule enabled functions so the rules engine can decode them
     * @param arguments the Arguments structure containing what needs to be encoded.
     * @return retVal the encoded bytes
     */
    function customEncoder(Arguments memory arguments) public pure returns (bytes memory retVal) {
        uint256 addressIter = 0;
        uint256 intIter = 0;
        uint256 stringIter = 0;

        for(uint256 i = 0; i < arguments.argumentTypes.length; i++) {
            if(arguments.argumentTypes[i] == PT.ADDR) {
                retVal = bytes.concat(retVal, abi.encode(arguments.addresses[addressIter]));
                addressIter += 1;
            } else if(arguments.argumentTypes[i] == PT.UINT) {
                retVal = bytes.concat(retVal, abi.encode(arguments.ints[intIter]));
                intIter += 1;
            } else if(arguments.argumentTypes[i] == PT.STR) {
                retVal = bytes.concat(retVal, abi.encode(arguments.strings[stringIter]));
                stringIter += 1;
            }
        }
    }
}