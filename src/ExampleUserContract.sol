// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "src/RulesEngineStructures.sol";
import "src/IRulesEngine.sol";

contract ExampleUserContract {
    address rulesEngineAddress;

    function setRulesEngineAddress(address rulesEngine) public {
        rulesEngineAddress = rulesEngine;
    }

    function transfer(address _to, uint256 _amount) public view returns (bool) {
        Arguments memory args;
        args.addresses = new address[](1);
        args.addresses[0] = _to;
        args.ints = new uint256[](1);
        args.ints[0] = _amount;
        args.argumentTypes = new PT[](2);
        args.argumentTypes[0] = PT.ADDR;
        args.argumentTypes[1] = PT.UINT;
        bytes memory encoded = customEncoder(args);
        return checkRulesCall(encoded);
    }

    function checkRulesCall(bytes memory arguments) public view returns (bool) {
        IRulesEngine rulesEngine = IRulesEngine(rulesEngineAddress);
        return rulesEngine.checkRules(address(0x1234567), "transfer(address,uint256) returns (bool)", arguments);
    }

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