/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/rulesEngine/fuzz/RulesEngineFuzzTestsCommon.t.sol"; 


contract RulesEngineFuzzTests is RulesEngineFuzzTestsCommon {

  function setUp() public{
        red = _createRulesEngineDiamond(); 
        userContract = new ExampleUserContract();
        userContract.setRulesEngineAddress(address(red));
        testContract = new ForeignCallTestContract();
        _setupEffectProcessor();
    }

}
