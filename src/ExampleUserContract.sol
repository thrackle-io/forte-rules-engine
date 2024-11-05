// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "src/RuleEncodingLibrary.sol";
import "src/IRulesEngine.sol";

/**
 * @title Example contract for testing the Rules Engine
 * @dev This contract provides the ability to test the rules engine with an external contract
 * @author @mpetersoCode55 
 */
contract ExampleUserContract {
    address rulesEngineAddress;

    uint256 one;
    uint256 two;
    string strS;

    function transfer(address _to, uint256 _amount) public returns (bool) {
        RulesStorageStructure.Arguments memory args;
        args.addresses = new address[](1);
        args.addresses[0] = _to;
        args.ints = new uint256[](1);
        args.ints[0] = _amount;
        args.argumentTypes = new RulesStorageStructure.PT[](2);
        args.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        args.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        bytes memory encoded = RuleEncodingLibrary.customEncoder(args);
        IRulesEngine rulesEngine = IRulesEngine(rulesEngineAddress);
        bool retVal = rulesEngine.checkRules(address(0x1234567), bytes("transfer(address,uint256) returns (bool)"), encoded);
        // This is where the overridden transfer would be called

        return retVal;
    }

    function setRulesEngineAddress(address rulesEngine) public {
        rulesEngineAddress = rulesEngine;
    }
}