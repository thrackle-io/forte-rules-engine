/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/validation/adminRoles/adminRoles.t.sol";
import "test/validation/components/components.t.sol";
import "test/validation/rules/rules.t.sol";
import "test/validation/policy/policies.t.sol";
/** 
 * This testing suite is intended to set deployed addresses of non rules engine contracts and test locally. Deployment tests of the Rules engine are here: 
 * test/rulesEngine/deployment/DeploymentValidation.t.sol
 * The tests here should be unique to marketplace and AMM style transactions and contian a skip with the testing addresses are blank (address(0x00)) so that they do not fail when not set up 
 * The tests here should not overlap with the deploymentValidation.t.sol testing suite. Those are for Rules Engine testing post deployment. 
 * This test file should be run with --fork-url <chain url that the marketplaces/AMMs are deployed on> once addresses are set. 

 * TODO create fork testing environment and logical fork tests from known deployed addresses: 
 * Opensea style marketplace 
 * ALTBC AMM 
 * URQTBC AMM
*/

contract RulesEngineForkTests is adminRoles, components, rules, policies 
    {
    // Set your Fork Test addresses 
    address deploymentOwner = address(0x000); 
    address marketPlace = address(0x0000);
    address ammALTBC = address(0x0000);
    address ammURQTBC = address(0x0000);


    function setUp() public{
        if (deploymentOwner != address(0x0)) {
            vm.startPrank(deploymentOwner);
            callingContractAdmin = address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8);
            policyAdmin = address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266);
            red = RulesEngineDiamond(payable(vm.envAddress("DIAMOND_ADDRESS")));        
            userContract = new ExampleUserContract();
            userContract.setRulesEngineAddress(address(red));
            userContract.setCallingContractAdmin(callingContractAdmin);
            userContractAddress = address(userContract);
            testContract = new ForeignCallTestContract();
            newUserContract = new ExampleUserContract();
            newUserContractAddress = address(newUserContract);
            newUserContract.setRulesEngineAddress(address(red));
            _setupEffectProcessor();
            testDeployments = true;
        } else {
            testDeployments = false;
        }
    }

}
