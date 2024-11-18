// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "src/RulesEngineStructures.sol";

/**
 * @title Library for users to parse expressions for Rule conditions and effects
 * @author  @mpetersoCode55 
 */
library ExpressionParsingLibrary {

    /**
     * @dev Decodes the encoded function arguments and fills out an Arguments struct to represent them
     * @param functionSignaturePTs the parmeter types of the arguments in the function in order, pulled from storage
     * @param arguments the encoded arguments 
     * @return functionSignatureArgs the Arguments struct containing the decoded function arguments
     */
    function decodeFunctionSignatureArgs(RulesStorageStructure.PT[] memory functionSignaturePTs, bytes calldata arguments) public pure returns (RulesStorageStructure.Arguments memory functionSignatureArgs) {
        uint256 placeIter = 32;
        uint256 addressIter = 0;
        uint256 intIter = 0;
        uint256 stringIter = 0;
        uint256 overallIter = 0;
        
        functionSignatureArgs.argumentTypes = new RulesStorageStructure.PT[](functionSignaturePTs.length);
        // Initializing each to the max size to avoid the cost of iterating through to determine how many of each type exist
        functionSignatureArgs.addresses = new address[](functionSignaturePTs.length);
        functionSignatureArgs.ints = new uint256[](functionSignaturePTs.length);
        functionSignatureArgs.strings = new string[](functionSignaturePTs.length);

        for(uint256 i = 0; i < functionSignaturePTs.length; i++) {
            if(functionSignaturePTs[i] == RulesStorageStructure.PT.ADDR) {
                // address data = abi.decode(arguments, (address));
                address data = i == 0 ? abi.decode(arguments[:32], (address)) : abi.decode(arguments[placeIter:(placeIter + 32)], (address));
                if(i != 0) {
                    placeIter += 32;
                }
                functionSignatureArgs.argumentTypes[overallIter] = RulesStorageStructure.PT.ADDR;
                functionSignatureArgs.addresses[addressIter] = data;
                overallIter += 1;
                addressIter += 1;
            } else if(functionSignaturePTs[i] == RulesStorageStructure.PT.UINT) {
                uint256 data = abi.decode(arguments[32:64], (uint256));
                if(i != 0) {
                    placeIter += 32;
                }
                functionSignatureArgs.argumentTypes[overallIter] = RulesStorageStructure.PT.UINT;
                functionSignatureArgs.ints[intIter] = data;
                overallIter += 1;
                intIter += 1;
            } else if(functionSignaturePTs[i] == RulesStorageStructure.PT.STR) {
                string memory data = i == 0 ? abi.decode(arguments[:32], (string)) : abi.decode(arguments[placeIter:(placeIter + 32)], (string));
                if(i != 0) {
                    placeIter += 32;
                }
                functionSignatureArgs.argumentTypes[overallIter] = RulesStorageStructure.PT.STR;
                functionSignatureArgs.strings[stringIter] = data;
                overallIter += 1;
                stringIter += 1;
            }
        }
    } 


    function evaluateForeignCalls(RulesStorageStructure.Placeholder[] memory placeHolders, RulesStorageStructure.ForeignCallArgumentMappings[] memory fcArgumentMappings, RulesStorageStructure.Arguments memory functionSignatureArgs, address contractAddress, uint256 placeholderIndex, mapping(address => RulesStorageStructure.foreignCallStorage) storage foreignCalls) public returns(RulesStorageStructure.ForeignCallReturnValue memory) {
        // Loop through the foreign call structures associated with the calling contracts address
        for(uint256 foreignCallsIdx = 0; foreignCallsIdx < foreignCalls[contractAddress].foreignCalls.length; foreignCallsIdx++) {
            // Check if the index for this placeholder matches the foreign calls index
            if(foreignCalls[contractAddress].foreignCalls[foreignCallsIdx].foreignCallIndex == placeHolders[placeholderIndex].typeSpecificIndex) {
                // Place the foreign call
                RulesStorageStructure.ForeignCallReturnValue memory retVal = evaluateForeignCallForRule(foreignCalls[contractAddress].foreignCalls[foreignCallsIdx], fcArgumentMappings, functionSignatureArgs);
                return retVal;
            }
        }
    }

        /**
     * @dev encodes the arguments and places a foreign call, returning the calls return value as long as it is successful
     * @param fc the Foreign Call structure
     * @param functionArguments the argument mappings for the foreign call (function arguments and tracker values)
     * @param functionArguments the arguments of the rules calling funciton (to be passed to the foreign call as needed)
     * @return retVal the foreign calls return value
     */
    function evaluateForeignCallForRule(RulesStorageStructure.ForeignCall memory fc, RulesStorageStructure.ForeignCallArgumentMappings[] memory fcArgumentMappings, RulesStorageStructure.Arguments memory functionArguments) public returns (RulesStorageStructure.ForeignCallReturnValue memory retVal) {
        // Arrays used to hold the parameter types and values to be encoded
        uint256[] memory paramTypeEncode = new uint256[](fc.parameterTypes.length);
        uint256[] memory uintEncode = new uint256[](fc.parameterTypes.length);
        address[] memory addressEncode = new address[](fc.parameterTypes.length);
        string[] memory stringEncode = new string[](fc.parameterTypes.length);
        // Iterators for the various types to make sure the correct indexes in each array are populated
        uint256 uintIter = 0;
        uint256 addrIter = 0;
        uint256 strIter = 0;

        // Iterate over the foreign call argument mappings contained within the rule structure
        for(uint256 i = 0; i < fcArgumentMappings.length; i++) {
            // verify this mappings foreign call index matches that of the foreign call structure
            if(fcArgumentMappings[i].foreignCallIndex == fc.foreignCallIndex) {
                // Iterate through the array of mappings between calling function arguments and foreign call arguments
                for(uint256 j = 0; j < fcArgumentMappings[i].mappings.length; j++) {
                    // Check the parameter type and set the values in the encode arrays accordingly 
                    if(fcArgumentMappings[i].mappings[j].functionCallArgumentType == RulesStorageStructure.PT.ADDR) {
                        paramTypeEncode[j] = 1; 
                        addressEncode[addrIter] = functionArguments.addresses[fcArgumentMappings[i].mappings[j].functionSignatureArg.typeSpecificIndex];
                        addrIter += 1;
                    } else if(fcArgumentMappings[i].mappings[j].functionCallArgumentType == RulesStorageStructure.PT.UINT) {
                        paramTypeEncode[j] = 0;
                        uintEncode[uintIter] = functionArguments.ints[fcArgumentMappings[i].mappings[j].functionSignatureArg.typeSpecificIndex];
                        uintIter += 1;
                    } else if(fcArgumentMappings[i].mappings[j].functionCallArgumentType == RulesStorageStructure.PT.STR) {
                        paramTypeEncode[j] = 2;
                        stringEncode[strIter] = functionArguments.strings[fcArgumentMappings[i].mappings[j].functionSignatureArg.typeSpecificIndex];
                        strIter += 1;
                    }
                }
            }
        }

        // Encode the arugments
        bytes memory argsEncoded = assemblyEncode(paramTypeEncode, uintEncode, addressEncode, stringEncode);

        // Build the bytes object with the function selector and the encoded arguments
        bytes memory encoded;
        encoded = bytes.concat(encoded, fc.signature);
        encoded = bytes.concat(encoded, argsEncoded);

        // place the foreign call
        (bool response, bytes memory data) = fc.foreignCallAddress.call(encoded);

        // Verify that the foreign call was successful
        if(response) {
            // Decode the return value based on the specified return value parameter type in the foreign call structure
            if(fc.returnType == RulesStorageStructure.PT.BOOL) {
                retVal.pType = RulesStorageStructure.PT.BOOL;
                retVal.boolValue = abi.decode(data, (bool));
            } else if(fc.returnType == RulesStorageStructure.PT.UINT) {
                retVal.pType = RulesStorageStructure.PT.UINT;
                retVal.intValue = abi.decode(data, (uint256));
            } else if(fc.returnType == RulesStorageStructure.PT.STR) {
                retVal.pType = RulesStorageStructure.PT.STR;
                retVal.str = abi.decode(data, (string));
            } else if(fc.returnType == RulesStorageStructure.PT.ADDR) {
                retVal.pType = RulesStorageStructure.PT.ADDR;
                retVal.addr = abi.decode(data, (address));
            } else if(fc.returnType == RulesStorageStructure.PT.VOID) {
                retVal.pType = RulesStorageStructure.PT.VOID;
            }
        }
    }

    /**
     * @dev Uses assembly to encode a variable length array of variable type arguments so they can be used in a foreign call
     * @param parameterTypes the parameter types of the arguments in order
     * @param ints the uint256 parameters to be encoded
     * @param addresses the address parameters to be encoded
     * @param strings the string parameters to be encoded
     * @return res the encoded arguments
     */
    function assemblyEncode(uint256[] memory parameterTypes, uint256[] memory ints, address[] memory addresses, string[] memory strings) public pure returns (bytes memory res) {
        uint256 len = parameterTypes.length;
        uint256 strCount = 0;
        uint256 remainingCount = 0;
        uint256[] memory strLengths = new uint256[](strings.length); 
        bytes32[] memory convertedStrings = new bytes32[](strings.length);
        for(uint256 i = 0; i < convertedStrings.length; i++) {
            strLengths[i] = bytes(strings[i]).length;
            convertedStrings[i] = stringToBytes32(strings[i]);
            strCount += 1;
        }
        remainingCount = parameterTypes.length - strCount;

        uint256 strStartLoc = parameterTypes.length;

        assembly {
            // Iterator for the uint256 array
            let intIter := 1
            // Iterator for the address array
            let addrIter := 1
            // Iterator for the string array
            let strIter := 1
            // get free memory pointer
            res := mload(0x40)        
            // set length based on size of parameter array                
            mstore(res, add(mul(0x20, remainingCount), mul(0x60, strCount))) 

            let i := 1
            for {} lt(i, add(len, 1)) {} {
                // Retrieve the next parameter type
                let pType := mload(add(parameterTypes, mul(0x20, i)))

                // If parameter type is integer encode the uint256
                if eq(pType, 0) {
                    let value := mload(add(ints, mul(0x20, intIter)))
                    mstore(add(res, mul(0x20, i)), value)
                    intIter := add(intIter, 1) 
                } 

                // If parameter type is address encode the address
                if eq(pType, 1) {
                    let value := mload(add(addresses, mul(0x20, addrIter)))
                    value := and(value, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
                    mstore(add(res, mul(0x20, i)), value)
                    addrIter := add(addrIter, 1)
                }

                if eq(pType, 2) {
                    mstore(add(res, mul(0x20, i)), mul(0x20, strStartLoc))
                    strStartLoc := add(strStartLoc, 2)
                }

                // Increment global iterators 
                i := add(i, 1)
            }

            let j := 0
            for {} lt(j, strCount) {} {
                let value := mload(add(convertedStrings, mul(0x20, strIter)))
                let leng := mload(add(strLengths, mul(0x20, strIter)))
                mstore(add(res, mul(0x20, i)), leng)   
                mstore(add(res, add(mul(0x20, i), 0x20)), value)
                i := add(i, 1)
                i := add(i, 1)
                strIter := add(strIter, 1)
                j := add(j, 1)
            }
            // update free memory pointer
            mstore(0x40, add(res, mul(0x20, i)))
        }
        
    }

    function stringToBytes32(string memory source) internal pure returns (bytes32 result) {
        assembly {
            result := mload(add(source, 32))
        }
    }
}