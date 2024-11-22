/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/rulesEngine/unit/RulesEngineUnitTestsCommon.t.sol"; 


contract RulesEngineUnitTests is RulesEngineUnitTestsCommon {

  function setUp() public{
        logic = new RulesEngineLogicWrapper();
        userContract = new ExampleUserContract();
        userContract.setRulesEngineAddress(address(logic));
        testContract = new ForeignCallTestContract();
        _setupEffectProcessor();
    }

}
