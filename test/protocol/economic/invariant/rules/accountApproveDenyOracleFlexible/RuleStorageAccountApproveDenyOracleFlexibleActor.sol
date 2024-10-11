// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import {RuleStorageInvariantActorCommon} from "test/protocol/economic/invariant/rules/util/RuleStorageInvariantActorCommon.sol";
import "test/util/TestCommonFoundry.sol";

/**
 * @title RuleStorageAccountApproveDenyOracleFlexibleActor
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett, @mpetersoCode55
 * @dev This is the rule storage handler for the AccountApproveDenyOracle rule. It will create the rule in the diamond and keep a total of how many it adds.
 */
contract RuleStorageAccountApproveDenyOracleFlexibleActor is TestCommonFoundry, RuleStorageInvariantActorCommon {

    constructor(RuleProcessorDiamond _processor, ApplicationAppManager _applicationAppManager){
        processor = _processor;
        appManager = _applicationAppManager;
    }

    /**
     * @dev add the rule to the diamond 
     */
    function addAccountApproveDenyOracleFlexible(address _oracleAddress, uint8 _type, uint8 _addressToggle) public returns (uint32 _ruleId){
        _ruleId = RuleDataFacet(address(processor)).addAccountApproveDenyOracleFlexible(address(appManager), _type, _addressToggle, _oracleAddress);
        ++totalRules;
    }
}
