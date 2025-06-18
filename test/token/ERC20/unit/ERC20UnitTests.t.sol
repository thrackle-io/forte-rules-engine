/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/token/ERC20/unit/ERC20UnitTestsCommon.t.sol"; 



contract ERC20UnitTests is ERC20UnitTestsCommon {

  function setUp() public{
        red = createRulesEngineDiamond(address(0xB0b)); 
        userContractERC20 = new ExampleERC20("Token Name", "SYMB");
        userContractERC20Address = address(userContractERC20);
        userContractERC20.setRulesEngineAddress(address(red));
        testContract = new ForeignCallTestContract();
        userContractERC20.setCallingContractAdmin(callingContractAdmin);
        _setupEffectProcessor(); 
        vm.startPrank(policyAdmin);       
    }

}
