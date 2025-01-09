// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./GasHelpers.sol";
import "test/utils/RulesEngineCommon.t.sol";
import "test/utils/ExampleUserContractWithMinTransfer.sol";
import "test/utils/ExampleUserContractWithMinTransferFC.sol";
import "test/utils/ExampleUserContractBase.sol";
import "test/utils/ExampleUserContractWithDenyList.sol";
import "test/utils/ExampleUserContractWithMinTransferAndDenyList.sol";
import "test/utils/ExampleUserContractWithMinTransferRevert.sol";

contract GasReports is GasHelpers, RulesEngineCommon {

    uint256 gasUsed;
    ForeignCallTestContractOFAC testContract2;
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
        _testGasExampleContract_Primer();
        // Only uncomment the Primer and the individual test you are intending to run to avoid coloring the data.
        // This default configuration only runs the Base test
        _testGasExampleContract_Base();
        
        _testGasExampleContract_NoPoliciesActive();
        _testGasExampleHardcodedMinTransferNotTriggered();
        _testGasExampleSimpleMinTransferNotTriggered();
        _testGasExampleHardcodedMinTransferTriggered();
        _testGasExampleHardcodedMinTransferRevert();
        _testGasExampleSimpleMinTransferTriggeredWithRevertEffect();
        _testGasExampleSimpleMinTransferTriggeredWithEffect();
        _testGasExampleHardcodedMinTransferWithForeignCallNotTriggered();
        _testGasExampleSimpleMinTransferWithForeignCallNotTriggered();
        _testGasExampleHardcodedMinTransferWithForeignCallTriggered();
        _testGasExampleSimpleMinTransferWithForeignCallTriggeredWithEvent();
        _testGasExampleSimpleMinTransferWithForeignCallTriggeredWithRevert();
        _testGasExampleOFAC();
        _testGasExampleHardcodedOFAC();
        _testGasExampleHardcodedOFACWithMinTransfer();
        _testGasExampleOFACWithMinTransfer();
    }

/**********  BASELINE gas test with Integration but no policies active **********/
    function _testGasExampleContract_NoPoliciesActive() internal resets{
        _testExampleContractPrep(1, address(userContract));
        _exampleContractGasReport(1, address(userContract), "Using REv2 No Policies Active");   
    }

/**********  BASELINE gas test with no integrations or rules **********/
    function _testGasExampleContract_Base() internal resets{
        ExampleUserContractBase hardCodedContract = new ExampleUserContractBase();
        _testExampleContractPrep(1, address(hardCodedContract));
        _exampleContractGasReport(1, address(hardCodedContract), "Base");   
    }
    function _testGasExampleContract_Primer() internal resets{
        ExampleUserContractBase hardCodedContract = new ExampleUserContractBase();
        _testExampleContractPrep(1, address(hardCodedContract));
        _exampleContractGasReport(1, address(hardCodedContract), "Primer -- disregard");   
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
        _exampleContractGasReport(5, address(userContract), "Using REv2 Min Transfer Triggered With Event Effect"); 
    }

    function _testGasExampleSimpleMinTransferTriggeredWithRevertEffect() internal endWithStopPrank resets{
        // Create a minimum transaction(GT 4) rule with positive event
        _setupRuleWithRevert();
        vm.expectRevert();
        _testExampleContractPrep(3, address(userContract));
        vm.expectRevert();
        _exampleContractGasReport(3, address(userContract), "Using REv2 Min Transfer Triggered With Revert Effect"); 
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
        _exampleContractGasReport(5, address(userContract), "Using REv2 Min Transfer With Foreign Call Triggered With Event Effect"); 
    }

    function _testGasExampleSimpleMinTransferWithForeignCallTriggeredWithRevert() internal endWithStopPrank resets{
        // Create a minimum transaction(GT 4) rule with positive event
        setupRuleWithForeignCall(5, ET.REVERT, false);
        vm.expectRevert();
        _testExampleContractPrep(4, address(userContract));
        vm.expectRevert();
        _exampleContractGasReport(4, address(userContract), "Using REv2 Min Transfer With Foreign Call Triggered With Revert Effect"); 
    }

/**********  Hard-coded MinTransfer with positive effect **********/
    function _testGasExampleHardcodedMinTransferNotTriggered() public endWithStopPrank resets{
        ExampleUserContractWithMinTransfer hardCodedContract = new ExampleUserContractWithMinTransfer();
        // Create a minimum transaction(GT 4) rule with positive event
        _testExampleContractPrep(1, address(hardCodedContract));
        _exampleContractGasReport(2, address(hardCodedContract), "Hardcoding Min Transfer Not Triggered"); 
    }

    function _testGasExampleHardcodedMinTransferRevert() public endWithStopPrank resets{
        ExampleUserContractWithMinTransferRevert hardCodedContract = new ExampleUserContractWithMinTransferRevert();
        // Create a minimum transaction(GT 4) rule with positive event
        vm.expectRevert();
        _testExampleContractPrep(2, address(hardCodedContract));
        vm.expectRevert();
        _exampleContractGasReport(2, address(hardCodedContract), "Hardcoding Min Transfer Revert"); 
    }

    function _testGasExampleHardcodedMinTransferTriggered() public endWithStopPrank resets{
        ExampleUserContractWithMinTransfer hardCodedContract = new ExampleUserContractWithMinTransfer();
        // Create a minimum transaction(GT 4) rule with positive event
        _testExampleContractPrep(5, address(hardCodedContract));
        _exampleContractGasReport(5, address(hardCodedContract), "Hardcoding Min Transfer Triggered With Event Effect"); 
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
        _exampleContractGasReport(5, address(hardCodedContract), "Hardcoding Min Transfer With Foreign Call Triggered With Event Effect"); 
    }

    function _testGasExampleHardcodedOFAC() internal endWithStopPrank resets{
        ExampleUserContractWithDenyList hardCodedContract = new ExampleUserContractWithDenyList();
        hardCodedContract.addToDenyList(address(0x7654321));
        // Create a deny list rule
        vm.expectRevert();
        _testExampleContractPrep(3, address(hardCodedContract));
        vm.expectRevert();
        _exampleContractGasReport(3, address(hardCodedContract), "Hardcoding OFAC deny list"); 
    }

    function _testGasExampleHardcodedOFACWithMinTransfer() internal endWithStopPrank resets{
        ExampleUserContractWithMinTransferAndDenyList hardCodedContract = new ExampleUserContractWithMinTransferAndDenyList();
        hardCodedContract.addToDenyList(address(0x7654321));
        // Create a minimum transaction(GT 4) rule with negative revert
        vm.expectRevert();
        _testExampleContractPrep(3, address(hardCodedContract));
        vm.expectRevert();
        _exampleContractGasReport(3, address(hardCodedContract), "Hardcoding OFAC deny list with min transfer"); 
    }

/**********  Prep functions to ensure warm storage comparisons **********/

    function _testExampleContractPrep(uint256 _amount, address contractAddress) public {
        ExampleUserContract(contractAddress).transfer(address(0x7654321), _amount);
    }

/**********  OFAC Prep functions to ensure warm storage comparisons **********/
    function _testGasExampleOFAC() public {
        testContract2 = new ForeignCallTestContractOFAC();
        setupRuleWithForeignCall2(address(testContract2), ET.REVERT, true);
        testContract2.addToNaughtyList(address(0x7654321));
        vm.expectRevert();
        _testExampleContractPrep(5, address(userContract));
        vm.expectRevert();
        _exampleContractGasReport(5, address(userContract), "Using REv2 OFAC gas report"); 
    }

    function setupRuleWithForeignCall2(
        address _contractAddress,
        ET _effectType,
        bool isPositive
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );

        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = 0;
        rule.placeHolders[1].pType = PT.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1;

        // Build the instruction set for the rule (including placeholders)
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LC.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;
        // Build the mapping between calling function arguments and foreign call arguments
        rule.fcArgumentMappingsConditions = new ForeignCallArgumentMappings[](
            1
        );
        rule
            .fcArgumentMappingsConditions[0]
            .mappings = new IndividualArgumentMapping[](1);
        rule
            .fcArgumentMappingsConditions[0]
            .mappings[0]
            .functionCallArgumentType = PT.ADDR;
        rule
            .fcArgumentMappingsConditions[0]
            .mappings[0]
            .functionSignatureArg
            .foreignCall = false;
        rule
            .fcArgumentMappingsConditions[0]
            .mappings[0]
            .functionSignatureArg
            .pType = PT.ADDR;
        rule
            .fcArgumentMappingsConditions[0]
            .mappings[0]
            .functionSignatureArg
            .typeSpecificIndex = 0;
        rule = _setUpEffect(rule, _effectType, isPositive);
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.ADDR;
        ForeignCall memory fc = RulesEngineDataFacet(address(red))
            .updateForeignCall(
                policyIds[0],
                address(_contractAddress),
                "getNaughty(address)",
                PT.UINT,
                fcArgs
            );
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(
            address(userContract),
            policyIds
        );
        fc; //added to silence warnings during testing revamp
    }


    function _testGasExampleOFACWithMinTransfer() public {
        testContract2 = new ForeignCallTestContractOFAC();
        setupRulesWithForeignCallAndMinTransfer(address(testContract2), ET.REVERT, true);
        testContract2.addToNaughtyList(address(0x7654321));
        vm.expectRevert();
        _testExampleContractPrep(5, address(userContract));
        vm.expectRevert();
        _exampleContractGasReport(5, address(userContract), "Using REv2 OFAC with min transfer gas report"); 
    }

    function setupRulesWithForeignCallAndMinTransfer(
        address _contractAddress,
        ET _effectType,
        bool isPositive
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );

        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule1;
        Rule memory rule2;
        // Build the foreign call placeholder
        rule1.placeHolders = new Placeholder[](2);
        rule1.placeHolders[0].foreignCall = true;
        rule1.placeHolders[0].typeSpecificIndex = 0;
        rule1.placeHolders[1].pType = PT.UINT;
        rule1.placeHolders[1].typeSpecificIndex = 1;
        // Build the instruction set for the rule (including placeholders)
        // We don't want this one to trigger the revert effect, we want both rules to be captured in the gas test
        // forcing this rule to fail
        rule1.instructionSet = new uint256[](7);
        rule1.instructionSet[0] = uint(LC.PLH);
        rule1.instructionSet[1] = 0;
        rule1.instructionSet[2] = uint(LC.NUM);
        rule1.instructionSet[3] = 0;
        rule1.instructionSet[4] = uint(LC.EQ);
        rule1.instructionSet[5] = 0;
        rule1.instructionSet[6] = 1;
        // Build the mapping between calling function arguments and foreign call arguments
        rule1.fcArgumentMappingsConditions = new ForeignCallArgumentMappings[](
            1
        );
        rule1
            .fcArgumentMappingsConditions[0]
            .mappings = new IndividualArgumentMapping[](1);
        rule1
            .fcArgumentMappingsConditions[0]
            .mappings[0]
            .functionCallArgumentType = PT.ADDR;
        rule1
            .fcArgumentMappingsConditions[0]
            .mappings[0]
            .functionSignatureArg
            .foreignCall = false;
        rule1
            .fcArgumentMappingsConditions[0]
            .mappings[0]
            .functionSignatureArg
            .pType = PT.ADDR;
        rule1
            .fcArgumentMappingsConditions[0]
            .mappings[0]
            .functionSignatureArg
            .typeSpecificIndex = 0;
        rule1 = _setUpEffect(rule1, _effectType, isPositive);
        // Save the rule
        uint256 ruleId1 = RulesEngineDataFacet(address(red)).updateRule(0, rule1);
        rule2 = _createGTRule(4);
        rule2.posEffects[0] = effectId_revert;
        uint256 ruleId2 = RulesEngineDataFacet(address(red)).updateRule(0, rule2);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.ADDR;
        ForeignCall memory fc = RulesEngineDataFacet(address(red))
            .updateForeignCall(
                policyIds[0],
                address(_contractAddress),
                "getNaughty(address)",
                PT.UINT,
                fcArgs
            );
        ruleIds.push(new uint256[](2));
        ruleIds[0][0] = ruleId1;
        ruleIds[0][1] = ruleId2;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(
            address(userContract),
            policyIds
        );
        fc; //added to silence warnings during testing revamp
    }

/**********  Rule Setup Helpers **********/
    function _exampleContractGasReport(uint256 _amount, address contractAddress, string memory _label) public {
        startMeasuringGas(_label);
        ExampleUserContract(contractAddress).transfer(address(0x7654321), _amount);
        gasUsed = stopMeasuringGas();
        console.log(_label, gasUsed);  
    }



}
