pragma solidity ^0.8.13;

import "src/RulesEngineStructures.sol";
import "src/RulesEngineRunLogic.sol";

/**
 * @title Wrapper around the Rules Engine Run Logic
 * @author @mpetersoCode55 
 */
contract RulesEngineRunLogicWrapper is RulesEngineRunLogic {

    function evaluateForeignCallForRuleExt(RulesStorageStructure.ForeignCall memory fc, RulesStorageStructure.ForeignCallArgumentMappings[] memory fcArgumentMappings, RulesStorageStructure.Arguments memory functionArguments) public returns (RulesStorageStructure.ForeignCallReturnValue memory retVal) {
        return evaluateForeignCallForRule(fc, fcArgumentMappings, functionArguments);
    }

    function assemblyEncodeExt(RulesStorageStructure.PT[] memory parameterTypes, bytes[] memory values, bytes4 selector, uint[] memory dynamicVarLengths) public pure returns (bytes memory res) {
        return assemblyEncode(parameterTypes, values, selector, dynamicVarLengths);
    }

}