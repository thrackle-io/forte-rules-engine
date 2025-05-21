/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/token/ERC20/unit/ERC20UnitTestsCommon.t.sol"; 



contract ERC20UnitTests is ERC20UnitTestsCommon {

  function setUp() public{
        red = _createRulesEngineDiamond(address(0xB0b)); 
        userContract = new ExampleERC20("Token Name", "SYMB");
        userContractAddress = address(userContract);
        userContract.setRulesEngineAddress(address(red));
        testContract = new ForeignCallTestContract();
        userContract.setCallingContractAdmin(callingContractAdmin);
        _setupEffectProcessor(); 
        vm.startPrank(policyAdmin);       
    }

}
