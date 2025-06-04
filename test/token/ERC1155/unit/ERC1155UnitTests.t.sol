/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/token/ERC1155/unit/ERC1155UnitTestsCommon.t.sol"; 

contract ERC1155UnitTests is ERC1155UnitTestsCommon {

  function setUp() public{
        red = createRulesEngineDiamond(address(0xB0b)); 
        userContract = new ExampleERC1155("example.uri/");
        userContractAddress = address(userContract);
        userContract.setRulesEngineAddress(address(red));
        testContract = new ForeignCallTestContract();
        userContract.setCallingContractAdmin(callingContractAdmin);
        _setupEffectProcessor();    
        vm.startPrank(policyAdmin);    
    }
}
