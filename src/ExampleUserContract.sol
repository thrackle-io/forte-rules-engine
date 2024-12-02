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
    address public rulesEngineAddress;

    function transfer(address _to, uint256 _amount) public returns (bool) {
        RulesStorageStructure.Arguments memory args;
        args.values = new bytes[](2);
        args.values[0] = abi.encode(address(_to));
        args.values[1] = abi.encode(uint256(_amount));
        args.argumentTypes = new RulesStorageStructure.PT[](2);
        args.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        args.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        bytes memory encoded = abi.encode(args);
        IRulesEngine rulesEngine = IRulesEngine(rulesEngineAddress);
        uint256 retVal = rulesEngine.checkPolicies(address(this), bytes("transfer(address,uint256) returns (bool)"), encoded);
        // This is where the overridden transfer would be called

        return retVal == 1;
    }

    /**
     * Set the Rules Engine address
     * @param rulesEngine rules engine address
     */
    function setRulesEngineAddress(address rulesEngine) public {
        rulesEngineAddress = rulesEngine;
    }
}
