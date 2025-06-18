/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/token/ERC721/unit/ERC721A.sol/ERC721AUnitTestsCommon.t.sol"; 

contract ERC721AUnitTests is ERC721AUnitTestsCommon {

  function setUp() public{
        red = createRulesEngineDiamond(address(0xB0b));
        userContract721A = new ExampleERC721A("Name", "SYMB");
        userContract721AAddress = address(userContract721A);
        userContract721A.setRulesEngineAddress(address(red));
        testContract = new ForeignCallTestContract();
        userContract721A.setCallingContractAdmin(callingContractAdmin);
        _setupEffectProcessor();
        vm.startPrank(policyAdmin);
    }
}
