/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/rulesEngine/unit/RulesEngineUnitTestsCommon.t.sol"; 

/** 
 * Deployment set Up function that inherits from RulesEngineUnitTestCommon and set rules engine addresses within the file to remove need for local env 
 * This test suite is intended to be used to test a newly deployed Rules Engine and ensure the deployment was successful and configuration is complete. 
 */


contract RulesEngineDeploymentTests is RulesEngineUnitTestsCommon {
    // Set your Deployed Rules Engine address 
    address rulesEngineAddress = address(0x0000); 
    address deploymentOwner = address(0x0000); 


    function setUp() public{
        if (deploymentOwner != address(0x0)) {
            rulesEngine = RulesEngineRunLogic(rulesEngineAddress);
            userContract = new ExampleUserContract();
            userContract.setRulesEngineAddress(address(logic));
            testContract = new ForeignCallTestContract();
            _setupEffectProcessor();
            testDeployments = true;
        } else {
            testDeployments = false;
        }
    }

}




