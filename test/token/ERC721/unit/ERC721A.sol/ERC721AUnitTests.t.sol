/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/token/ERC721/unit/ERC721A.sol/ERC721AUnitTestsCommon.t.sol"; 

contract ERC721AUnitTests is ERC721AUnitTestsCommon {

  function setUp() public{
        red = _createRulesEngineDiamond(address(0xB0b));
        userContract = new ExampleERC721A("Name", "SYMB");
        userContractAddress = address(userContract);
        userContract.setRulesEngineAddress(address(red));
        testContract = new ForeignCallTestContract();
        userContract.setCallingContractAdmin(callingContractAdmin);
        _setupEffectProcessor();
        vm.startPrank(policyAdmin);
    }
}
