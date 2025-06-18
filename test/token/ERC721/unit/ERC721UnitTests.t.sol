/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/token/ERC721/unit/ERC721UnitTestsCommon.t.sol"; 



contract ERC721UnitTests is ERC721UnitTestsCommon {

  function setUp() public{
        red = createRulesEngineDiamond(address(0xB0b)); 
        userContract721 = new ExampleERC721("Token Name", "SYMB");
        userContract721Address = address(userContract721);
        userContract721.setRulesEngineAddress(address(red));
        testContract = new ForeignCallTestContract();
        userContract721.setCallingContractAdmin(callingContractAdmin);
        _setupEffectProcessor();    
        vm.startPrank(policyAdmin);    
    }

}
