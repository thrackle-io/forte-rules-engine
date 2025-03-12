/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/rulesEngine/fuzz/RulesEngineFuzzTestsCommon.t.sol"; 
import "src/example/ExampleUserContract.sol";


contract RulesEngineFuzzTests is RulesEngineFuzzTestsCommon {
  
  ExampleUserContract userContract;

  function setUp() public{
        red = _createRulesEngineDiamond(address(0xB0b)); 
        userContract = new ExampleUserContract();
        userContractAddress = address(userContract);
        userContract.setRulesEngineAddress(address(red));
        testContract = new ForeignCallTestContract();
        userContract.setCallingContractAdmin(callingContractAdmin);
        _setupEffectProcessor();
    }

}
