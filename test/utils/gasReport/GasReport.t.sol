// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./GasHelpers.sol";
import "test/utils/RulesEngineCommon.t.sol";
import "test/utils/ExampleUserContractWithMinTransfer.sol";
import "test/utils/ExampleUserContractWithMinTransferFC.sol";

contract GasReports is GasHelpers, RulesEngineCommon {

    uint256 gasUsed;
    function setUp() public {
        red = _createRulesEngineDiamond(address(0xB0b));
        userContract = new ExampleUserContract();
        userContract.setRulesEngineAddress(address(red));
        testContract = new ForeignCallTestContract();
        _setupEffectProcessor(); 
    }

    modifier resets() {
        _reset();
        _;
    }

    /// Reset the contracts so that everything is fresh
    function _reset() internal {
        red = _createRulesEngineDiamond(address(0xB0b));
        userContract = new ExampleUserContract();
        userContract.setRulesEngineAddress(address(red));
        testContract = new ForeignCallTestContract();
        _setupEffectProcessor(); 
    }


/**********  All gas tests should run through this function to keep results together **********/
    function testGasReport() public {
        _testGasExampleContract_NoPoliciesActive();
        _testGasExampleHardcodedMinTransferNotTriggered();
        _testGasExampleSimpleMinTransferNotTriggered();
        _testGasExampleHardcodedMinTransferTriggered();
        _testGasExampleSimpleMinTransferTriggeredWithEffect();
        _testGasExampleHardcodedMinTransferWithForeignCallNotTriggered();
        _testGasExampleSimpleMinTransferWithForeignCallNotTriggered();
        _testGasExampleHardcodedMinTransferWithForeignCallTriggered();
        _testGasExampleSimpleMinTransferWithForeignCallTriggeredWithEvent();
    }

/**********  BASELINE gas test with Integration but no policies active **********/
    function _testGasExampleContract_NoPoliciesActive() internal resets{
        _testExampleContractPrep(1, address(userContract));
        _exampleContractGasReport(1, address(userContract), "Using REv2 No Policies Active");   
    }

/**********  Simple Minimum Transfer Rule Checks **********/

    function _testGasExampleSimpleMinTransferNotTriggered() internal endWithStopPrank resets{
        // Create a minimum transaction(GT 4) rule with positive event
        _setupMinTransferWithPosEvent(4, address(userContract));
        _testExampleContractPrep(1, address(userContract));
        _exampleContractGasReport(1, address(userContract), "Using REv2 Min Transfer Not Triggered"); 
    }

    function _testGasExampleSimpleMinTransferTriggeredWithEffect() internal endWithStopPrank resets{
        // Create a minimum transaction(GT 4) rule with positive event
        _setupMinTransferWithPosEvent(4, address(userContract));
        _testExampleContractPrep(5, address(userContract));
        _exampleContractGasReport(5, address(userContract), "Using REv2 Min Transfer Triggered With Effect"); 
    }

    function _testGasExampleSimpleMinTransferWithForeignCallNotTriggered() internal endWithStopPrank resets{
        // Create a minimum transaction(GT 4) rule with positive event
        setupRuleWithForeignCall(4, ET.EVENT, true);
        _testExampleContractPrep(5, address(userContract));
        _exampleContractGasReport(1, address(userContract), "Using REv2 Min Transfer With Foreign Call Not Triggered"); 
    }

    function _testGasExampleSimpleMinTransferWithForeignCallTriggeredWithEvent() internal endWithStopPrank resets{
        // Create a minimum transaction(GT 4) rule with positive event
        setupRuleWithForeignCall(4, ET.EVENT, true);
        _testExampleContractPrep(5, address(userContract));
        _exampleContractGasReport(5, address(userContract), "Using REv2 Min Transfer With Foreign Call Triggered With Event"); 
    }

/**********  Hard-coded MinTransfer with positive effect **********/
    function _testGasExampleHardcodedMinTransferNotTriggered() public endWithStopPrank resets{
        ExampleUserContractWithMinTransfer hardCodedContract = new ExampleUserContractWithMinTransfer();
        // Create a minimum transaction(GT 4) rule with positive event
        _testExampleContractPrep(1, address(hardCodedContract));
        _exampleContractGasReport(1, address(hardCodedContract), "Hardcoding Min Transfer Not Triggered"); 
    }

    function _testGasExampleHardcodedMinTransferTriggered() public endWithStopPrank resets{
        ExampleUserContractWithMinTransfer hardCodedContract = new ExampleUserContractWithMinTransfer();
        // Create a minimum transaction(GT 4) rule with positive event
        _testExampleContractPrep(5, address(hardCodedContract));
        _exampleContractGasReport(5, address(hardCodedContract), "Hardcoding Min Transfer Triggered With Effect"); 
    }

/**********  Hard-coded MinTransfer with foreign call and positive effect **********/
    function _testGasExampleHardcodedMinTransferWithForeignCallNotTriggered() internal endWithStopPrank resets{
        ExampleUserContractWithMinTransferFC hardCodedContract = new ExampleUserContractWithMinTransferFC();
        // Create a minimum transaction(GT 4) rule with positive event
        _testExampleContractPrep(1, address(hardCodedContract));
        _exampleContractGasReport(1, address(hardCodedContract), "Hardcoding Min Transfer With Foreign Call Not Triggered"); 
    }

    function _testGasExampleHardcodedMinTransferWithForeignCallTriggered() internal endWithStopPrank resets{
        ExampleUserContractWithMinTransferFC hardCodedContract = new ExampleUserContractWithMinTransferFC();
        // Create a minimum transaction(GT 4) rule with positive event
        _testExampleContractPrep(5, address(hardCodedContract));
        _exampleContractGasReport(5, address(hardCodedContract), "Hardcoding Min Transfer With Foreign Call Triggered With Effect"); 
    }

/**********  Prep functions to ensure warm storage comparisons **********/

    function _testExampleContractPrep(uint256 _amount, address contractAddress) public {
        ExampleUserContract(contractAddress).transfer(address(0x7654321), _amount);
    }


/**********  Rule Setup Helpers **********/
    function _exampleContractGasReport(uint256 _amount, address contractAddress, string memory _label) public {
        startMeasuringGas(_label);
        ExampleUserContract(contractAddress).transfer(address(0x7654321), _amount);
        gasUsed = stopMeasuringGas();
        console.log(_label, gasUsed);  
    }



}
