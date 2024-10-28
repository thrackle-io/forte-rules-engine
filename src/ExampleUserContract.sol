// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "src/RulesEngineStructures.sol";
import "src/IRulesEngine.sol";

contract exampleUserContract {
    address rulesEngineAddress;

    function transfer(address _to, uint256 _amount) public view returns (bool success) {
        Arguments memory args;
        args.addresses = new address[](1);
        args.addresses[0] = _to;
        args.ints = new uint256[](1);
        args.argumentTypes = new PT[](2);
        args.argumentTypes[0] = PT.ADDR;
        args.argumentTypes[1] = PT.UINT;
        bytes memory encoded = customEncoder(args);
        checkRulesCall(encoded);
        // This is where the overriden transfer would be called 

        return true;
    }

    function checkRulesCall(bytes memory arguments) public view {
        IRulesEngine rulesEngine = IRulesEngine(rulesEngineAddress);
        rulesEngine.checkRules(address(0x1234567), "transfer(address, uint256)", arguments);
    }

    function customEncoder(Arguments memory arguments) public pure returns (bytes memory retVal) {
        uint256 addressIter = 0;
        uint256 intIter = 0;
        uint256 stringIter = 0;

        for(uint256 i = 0; i < arguments.argumentTypes.length; i++) {
            if(arguments.argumentTypes[i] == PT.ADDR) {
                bytes.concat(retVal, abi.encode(arguments.addresses[addressIter]));
                addressIter += 1;
            } else if(arguments.argumentTypes[i] == PT.UINT) {
                bytes.concat(retVal, abi.encode(arguments.ints[i]));
                intIter += 1;
            } else if(arguments.argumentTypes[i] == PT.STR) {
                bytes.concat(retVal, abi.encode(arguments.strings[i]));
                stringIter += 1;
            }
        }
    }
}