// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "src/RulesEngineStructures.sol";
import "src/RulesEngineRunLogic.sol";

/**
 * @title Wrapper around the Rules Engine Run Logic
 * @author @mpetersoCode55 
 */
contract RulesEngineRunLogicWrapper is RulesEngineRunLogic {

    function evaluateForeignCallForRuleExt(RulesStorageStructure.ForeignCall memory fc, RulesStorageStructure.Rule memory rule, RulesStorageStructure.Arguments memory functionArguments) public returns (RulesStorageStructure.ForeignCallReturnValue memory retVal) {
        return evaluateForeignCallForRule(fc, rule, functionArguments);
    }

    function assemblyEncodeExt(uint256[] memory parameterTypes, uint256[] memory ints, address[] memory addresses, string[] memory strings) public pure returns (bytes memory res) {
        return assemblyEncode(parameterTypes, ints, addresses, strings);
    }

}