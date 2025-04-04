/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/rulesEngine/unit/RulesEngineUnitTestsCommon.t.sol"; 
import "test/rulesEngine/unit/RulesEngineInternalFunctionsUnitTests.t.sol"; 

contract RulesEngineUnitTests is RulesEngineUnitTestsCommon, RulesEngineInternalFunctionsUnitTests {

  function setUp() public{
        red = _createRulesEngineDiamond(address(0xB0b)); 
        userContract = new ExampleUserContract();
        userContractInternal = new ExampleUserContract();
        userContractAddress = address(userContract);
        userContract.setRulesEngineAddress(address(red));
        testContract = new ForeignCallTestContract();
        userContract.setCallingContractAdmin(callingContractAdmin);
        newUserContract = new ExampleUserContract();
        newUserContractAddress = address(newUserContract);
        newUserContract.setRulesEngineAddress(address(red));
        _setupEffectProcessor();        
    }

}
