/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/token/ERC1155/unit/ERC1155UnitTestsCommon.t.sol"; 

contract ERC1155UnitTests is ERC1155UnitTestsCommon {

  function setUp() public{
        red = createRulesEngineDiamond(address(0xB0b)); 
        userContract1155 = new ExampleERC1155("example.uri/");
        userContract1155Address = address(userContract1155);
        userContract1155.setRulesEngineAddress(address(red));
        testContract = new ForeignCallTestContract();
        userContract1155.setCallingContractAdmin(callingContractAdmin);
        _setupEffectProcessor();    
        vm.startPrank(policyAdmin);    
    }
}
