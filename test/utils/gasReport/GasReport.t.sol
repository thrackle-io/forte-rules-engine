// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./GasHelpers.sol";
import "test/utils/RulesEngineCommon.t.sol";
import "test/utils/ExampleUserContractWithMinTransfer.sol";
import "test/utils/ExampleUserContractWithMinTransferFC.sol";

contract GasReports is GasHelpers, RulesEngineCommon {

    uint256 gasUsed;
    function setUp() public {
        red = _createRulesEngineDiamond();
        userContract = new ExampleUserContract();
        userContract.setRulesEngineAddress(address(red));
        testContract = new ForeignCallTestContract();
        _setupEffectProcessor(); 
    }


/**********  BASELINE gas test with Integration but no policies active **********/

    function testGasExampleContract_NoPoliciesActive() public {
        _testExampleContractPrep(1, address(userContract));
        _exampleContractGasReport(1, address(userContract), "Example_No_Policies_Active");   
    }

/**********  Simple Minimum Transfer Rule Checks **********/

    function testGasExampleSimpleMinTransferNotTriggered() public endWithStopPrank {
        // Create a minimum transaction(GT 4) rule with positive event
        _setupMinTransferWithPosEvent(4, address(userContract));
        _testExampleContractPrep(1, address(userContract));
        _exampleContractGasReport(1, address(userContract), "Example_Min_Transfer_Not_Triggered"); 
    }

    function testGasExampleSimpleMinTransferTriggeredWithEffect() public endWithStopPrank {
        // Create a minimum transaction(GT 4) rule with positive event
        _setupMinTransferWithPosEvent(4, address(userContract));
        _testExampleContractPrep(5, address(userContract));
        _exampleContractGasReport(5, address(userContract), "Example_Min_Transfer_Triggered_With_Effect"); 
    }

    function testGasExampleSimpleMinTransferWithForeignCallNotTriggered() public endWithStopPrank {
        // Create a minimum transaction(GT 4) rule with positive event
        setupRuleWithForeignCall(4, ET.EVENT, true);
        _testExampleContractPrep(5, address(userContract));
        _exampleContractGasReport(1, address(userContract), "Example_Min_Transfer_With_Foreign_Call_Not_Triggered"); 
    }

    function testGasExampleSimpleMinTransferWithForeignCallTriggeredWithEvent() public endWithStopPrank {
        // Create a minimum transaction(GT 4) rule with positive event
        setupRuleWithForeignCall(4, ET.EVENT, true);
        _testExampleContractPrep(5, address(userContract));
        _exampleContractGasReport(5, address(userContract), "Example_Min_Transfer_With_Foreign_Call_Triggered_With_Event"); 
    }

/**********  Hard-coded MinTransfer with positive effect **********/
    function _testGasExampleHardcodedMinTransferNotTriggered() public endWithStopPrank {
        ExampleUserContractWithMinTransfer hardCodedContract = new ExampleUserContractWithMinTransfer();
        // Create a minimum transaction(GT 4) rule with positive event
        _testExampleContractPrep(1, address(hardCodedContract));
        _exampleContractGasReport(1, address(hardCodedContract), "Example_Hardcoded_Min_Transfer_Not_Triggered"); 
    }

    function _testGasExampleHardcodedMinTransferTriggered() public endWithStopPrank {
        ExampleUserContractWithMinTransfer hardCodedContract = new ExampleUserContractWithMinTransfer();
        // Create a minimum transaction(GT 4) rule with positive event
        _testExampleContractPrep(5, address(hardCodedContract));
        _exampleContractGasReport(5, address(hardCodedContract), "Example_Hardcoded_Min_Transfer_Triggered_With_Effect"); 
    }

/**********  Hard-coded MinTransfer with foreign call and positive effect **********/
    function testGasExampleHardcodedMinTransferWithForeignCallNotTriggered() public endWithStopPrank {
        ExampleUserContractWithMinTransferFC hardCodedContract = new ExampleUserContractWithMinTransferFC();
        // Create a minimum transaction(GT 4) rule with positive event
        _testExampleContractPrep(1, address(hardCodedContract));
        _exampleContractGasReport(1, address(hardCodedContract), "Example_Hardcoded_Min_Transfer_With_Foreign_Call_Not_Triggered"); 
    }

    function testGasExampleHardcodedMinTransferWithForeignCallTriggered() public endWithStopPrank {
        ExampleUserContractWithMinTransferFC hardCodedContract = new ExampleUserContractWithMinTransferFC();
        // Create a minimum transaction(GT 4) rule with positive event
        _testExampleContractPrep(5, address(hardCodedContract));
        _exampleContractGasReport(5, address(hardCodedContract), "Example_Hardcoded_Min_Transfer_With_Foreign_Call_Triggered_With_Effect"); 
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
