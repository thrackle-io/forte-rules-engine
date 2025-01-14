// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./GasHelpers.sol";
import "test/utils/RulesEngineCommon.t.sol";
import "test/utils/ExampleUserContractWithMinTransfer.sol";
import "test/utils/ExampleUserContractWithMinTransferFC.sol";
import "test/utils/ExampleUserContractBase.sol";
import "src/example/ExampleUserContract.sol";
import "test/utils/ExampleUserContractWithDenyList.sol";
import "test/utils/ExampleUserContractWithMinTransferAndDenyList.sol";
import "test/utils/ExampleUserContractWithMinTransferRevert.sol";
import "test/utils/ExampleUserContractWithMinTransferMaxTransferAndDenyList.sol";
import "test/utils/ExampleERC20WithMinTransfer.sol"; 
import "test/utils/ExampleERC20WithDenyList.sol"; 
import "test/utils/ExampleERC20WithDenyListAndMinTransfer.sol";
import "test/utils/ExampleERC20Hardcoded.sol";
import "src/example/ExampleERC20.sol";
import "test/utils/ExampleERC20WithDenyListMinAndMax.sol";
import "test/utils/ExampleERC20WithManyConditionMinTransfer.sol";

contract GasReports is GasHelpers, RulesEngineCommon {

    uint256 gasUsed;
    ForeignCallTestContractOFAC testContract2;
    ExampleERC20 userContract;

    function setUp() public {
        red = _createRulesEngineDiamond(address(0xB0b));
        userContract = new ExampleERC20("Token Name", "SYMB");
        userContractAddress = address(userContract);
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
        userContract = new ExampleERC20("Token Name", "SYMB");
        userContractAddress = address(userContract);
        userContract.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContract.setRulesEngineAddress(address(red));
        testContract = new ForeignCallTestContract();
        _setupEffectProcessor(); 
    }


/**********  All gas tests should run through this function to keep results together **********/
    function testGasReport() public endWithStopPrank {
        vm.startPrank(USER_ADDRESS);
        _testGasExampleContract_Primer();
        // Only uncomment the Primer and the individual test you are intending to run to avoid coloring the data.
        // This default configuration only runs the Base test

        //-----------------------------------------------------------------------------
        // Hard coded
        _testGasExampleContract_Base();
        // _testGasExampleHardcodedMinTransferRevert();
        // _testGasExampleHardcodedManyMinTransferRevert();
        // _testGasExampleHardcodedOFAC();
        // _testGasExampleHardcodedOFACWithMinTransfer();
        // _testGasExampleHardcodedOFACWithMinTransferAndMaxTransfer();
        //-----------------------------------------------------------------------------
        // R2V2
        // _testGasExampleContract_NoPoliciesActive();
        // _testGasExampleSimpleMinTransferTriggeredWithRevertEffect();
        // _testGasExampleManyMinTransferTriggeredWithRevertEffect();
        // _testGasExampleOFAC();
        // _testGasExampleOFACWithMinTransfer();
        // _testGasExampleOFACWithMinTransferAndMaxTransfer();
        // _testGasExampleOFACWithMinTransferInOneRule();
        // _testGasExampleOFACWithMinTransferInSeparatePolicies();

        //-----------------------------------------------------------------------------
        vm.stopPrank();
    }

    function _testGasExampleContract_Primer() internal resets{
        ExampleUserContractBase hardCodedContract = new ExampleUserContractBase();
        _testExampleContractPrep(1, address(userContract));
        _exampleContractGasReport(1, address(userContract), "Primer -- disregard");   
    }

/**********  HARD CODED, No Rules Engine Integration **********/
//---------------------------------------------------------------------------------------------
    /**********  BASELINE gas test with no integrations or rules **********/
    function _testGasExampleContract_Base() internal resets{
        ExampleERC20Hardcoded hardCodedContract = new ExampleERC20Hardcoded("Token Name", "SYMB");
        hardCodedContract.mint(USER_ADDRESS, 1_000_000 * ATTO);
        _testExampleContractPrep(1, address(hardCodedContract));
        _exampleContractGasReport(1, address(hardCodedContract), "Base");   
    }

    
//---------------------------------------------------------------------------------------------

/**********  Rules Engine Integration **********/
//---------------------------------------------------------------------------------------------



//---------------------------------------------------------------------------------------------
/**********  BASELINE gas test with Integration but no policies active **********/
    function _testGasExampleContract_NoPoliciesActive() internal resets{
        _testExampleContractPrep(1, address(userContract));
        _exampleContractGasReport(1, address(userContract), "Using REv2 No Policies Active");   
    }


/**********  Simple Minimum Transfer Rule Checks **********/

    function _testGasExampleSimpleMinTransferTriggeredWithRevertEffect() internal endWithStopPrank resets{
        userContract.mint(USER_ADDRESS, 1_000_000 * ATTO);
        // Create a minimum transaction(GT 4) rule with positive event
        _setupRuleWithRevert();
        _testExampleContractPrep(3, address(userContract));
        _exampleContractGasReport(3, address(userContract), "Using REv2 Min Transfer Triggered With Revert Effect"); 
    }

    function _testGasExampleManyMinTransferTriggeredWithRevertEffect() internal endWithStopPrank resets{
        userContract.mint(USER_ADDRESS, 1_000_000 * ATTO);
        // Create a minimum transaction(GT 4) rule with positive event
        _setupRuleWithRevertManyCondition();
        _testExampleContractPrep(3, address(userContract));
        _exampleContractGasReport(3, address(userContract), "Using REv2 Min Transfer Triggered With Revert Effect"); 
    }

/**********  Hard-coded MinTransfer with positive effect **********/

    function _testGasExampleHardcodedMinTransferRevert() public endWithStopPrank resets{
        ExampleERC20WithMinTransfer hardCodedContract = new ExampleERC20WithMinTransfer("Token Name", "SYMB");
        ExampleERC20WithMinTransfer(address(hardCodedContract)).mint(USER_ADDRESS, 1_000_000 * ATTO);
        // Create a minimum transaction(GT 4) rule with positive event
        _testExampleContractPrep(5, address(hardCodedContract));
        _exampleContractGasReport(5, address(hardCodedContract), "Hardcoding Min Transfer Revert"); 
    }

    function _testGasExampleHardcodedManyMinTransferRevert() public endWithStopPrank resets{
        ExampleERC20WithManyConditionMinTransfer hardCodedContract = new ExampleERC20WithManyConditionMinTransfer("Token Name", "SYMB");
        ExampleERC20WithMinTransfer(address(hardCodedContract)).mint(USER_ADDRESS, 1_000_000 * ATTO);
        // Create a minimum transaction(GT 4) rule with positive event
        _testExampleContractPrep(5, address(hardCodedContract));
        _exampleContractGasReport(5, address(hardCodedContract), "Hardcoding Min Transfer Revert"); 
    }

/**********  Hard-coded MinTransfer with foreign call and positive effect **********/

    function _testGasExampleHardcodedOFAC() internal endWithStopPrank resets{
        ExampleERC20WithDenyList hardCodedContract = new ExampleERC20WithDenyList("Token Name", "SYMB");
        ExampleERC20WithDenyList(address(hardCodedContract)).mint(USER_ADDRESS, 1_000_000 * ATTO);
        hardCodedContract.addToDenyList(address(0x7000000));
        // Create a deny list rule
        _testExampleContractPrep(3, address(hardCodedContract));
        _exampleContractGasReport(3, address(hardCodedContract), "Hardcoding OFAC deny list"); 
    }

    function _testGasExampleHardcodedOFACWithMinTransfer() internal endWithStopPrank resets{
        ExampleERC20WithDenyListAndMinTransfer hardCodedContract = new ExampleERC20WithDenyListAndMinTransfer("Token Name", "SYMB");
        ExampleERC20WithDenyList(address(hardCodedContract)).mint(USER_ADDRESS, 1_000_000 * ATTO);
        hardCodedContract.addToDenyList(address(0x7654321));
        // Create a minimum transaction(GT 4) rule with negative revert
        _testExampleContractPrep(5, address(hardCodedContract));
        _exampleContractGasReport(5, address(hardCodedContract), "Hardcoding OFAC deny list with min transfer"); 
    }

    function _testGasExampleHardcodedOFACWithMinTransferAndMaxTransfer() internal endWithStopPrank resets{
        ExampleERC20WithDenyListMinAndMax hardCodedContract = new ExampleERC20WithDenyListMinAndMax("Token Name", "SYMB");
        ExampleERC20WithDenyList(address(hardCodedContract)).mint(USER_ADDRESS, 1_000_000 * ATTO);
        hardCodedContract.addToDenyList(address(0x7654321));
        // Create a minimum transaction(GT 4) rule with negative revert
        _testExampleContractPrep(5, address(hardCodedContract));
        _exampleContractGasReport(5, address(hardCodedContract), "Hardcoding OFAC deny list with min transfer"); 
    }

/**********  OFAC Prep functions to ensure warm storage comparisons **********/
    function _testGasExampleOFAC() public {
        userContract.mint(USER_ADDRESS, 1_000_000 * ATTO);
        testContract2 = new ForeignCallTestContractOFAC();
        setupRuleWithOFACForeignCall(address(testContract2), ET.REVERT, true);
        testContract2.addToNaughtyList(address(0x7654321));
        _testExampleContractPrep(5, address(userContract));
        _exampleContractGasReport(5, address(userContract), "Using REv2 OFAC gas report"); 
    }

    function _testGasExampleOFACWithMinTransfer() public {
        userContract.mint(USER_ADDRESS, 1_000_000 * ATTO);
        testContract2 = new ForeignCallTestContractOFAC();
        setupRulesWithForeignCallAndMinTransfer(address(testContract2), ET.REVERT, true);
        testContract2.addToNaughtyList(address(0x7654321));
        _testExampleContractPrep(5, address(userContract));
        _exampleContractGasReport(5, address(userContract), "Using REv2 OFAC with min transfer gas report"); 
    }

    function _testGasExampleOFACWithMinTransferAndMaxTransfer() public {
        userContract.mint(USER_ADDRESS, 1_000_000 * ATTO);
        testContract2 = new ForeignCallTestContractOFAC();
        setupRulesWithForeignCallPlusMinTransferAndMaxTransfer(address(testContract2), ET.REVERT, true);
        testContract2.addToNaughtyList(address(0x7654321));
        _testExampleContractPrep(1, address(userContract));
        _exampleContractGasReport(1, address(userContract), "Using REv2 OFAC with min transfer gas report"); 
    }

    function _testGasExampleOFACWithMinTransferInOneRule() public {
        userContract.mint(USER_ADDRESS, 1_000_000 * ATTO);
        testContract2 = new ForeignCallTestContractOFAC();
        setupRulesWithForeignCallPlusMinTransferAndMaxTransferInOneRule(address(testContract2), ET.REVERT, true);
        testContract2.addToNaughtyList(address(0x7654321));
        _testExampleContractPrep(5, address(userContract));
        _exampleContractGasReport(5, address(userContract), "Using REv2 OFAC with min transfer gas report"); 
    }

    function _testGasExampleOFACWithMinTransferInSeparatePolicies() public {
        userContract.mint(USER_ADDRESS, 1_000_000 * ATTO);
        testContract2 = new ForeignCallTestContractOFAC();
        setupRulesWithForeignCallAndMinTransferSeparatePolicies(address(testContract2), ET.REVERT, true);
        testContract2.addToNaughtyList(address(0x7654321));
        _testExampleContractPrep(5, address(userContract));
        _exampleContractGasReport(5, address(userContract), "Using REv2 OFAC with min transfer gas report"); 
    }

/**********  Prep functions to ensure warm storage comparisons **********/

    function _testExampleContractPrep(uint256 _amount, address contractAddress) public {
        ExampleERC20(contractAddress).transfer(address(0x7654321), _amount);
    }

    function setupRuleWithOFACForeignCall(
        address _contractAddress,
        ET _effectType,
        bool isPositive
    ) public ifDeploymentTestsEnabled resetsGlobalVariables {
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

        // Swapping isPositive to make sure the revert doesn't trigger (for comparison with V1 numbers)
        rule = _setUpEffect(rule, _effectType, !isPositive);
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(0, rule);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.ADDR;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 0;
        ForeignCall memory fc = RulesEngineDataFacet(address(red))
            .updateForeignCall(
                policyIds[0],
                address(_contractAddress),
                "getNaughty(address)",
                PT.UINT,
                fcArgs,
                typeSpecificIndices
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

    function setupRulesWithForeignCallAndMinTransfer(
        address _contractAddress,
        ET _effectType,
        bool isPositive
    ) public ifDeploymentTestsEnabled resetsGlobalVariables {
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

        rule1 = _setUpEffect(rule1, _effectType, isPositive);
        // Save the rule
        uint256 ruleId1 = RulesEngineDataFacet(address(red)).updateRule(0, rule1);
        rule2 = _createGTRule(4);
        // Swapping from posEffect to negEffects to make sure the revert doesn't trigger (for comparison with V1 numbers)
        rule2.negEffects[0] = effectId_revert;
        uint256 ruleId2 = RulesEngineDataFacet(address(red)).updateRule(0, rule2);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.ADDR;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 0;
        ForeignCall memory fc = RulesEngineDataFacet(address(red))
            .updateForeignCall(
                policyIds[0],
                address(_contractAddress),
                "getNaughty(address)",
                PT.UINT,
                fcArgs,
                typeSpecificIndices
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

   function setupRulesWithForeignCallPlusMinTransferAndMaxTransferInOneRule(
        address _contractAddress,
        ET _effectType,
        bool isPositive
    ) public ifDeploymentTestsEnabled resetsGlobalVariables {
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
        // Build the foreign call placeholder
        rule1.placeHolders = new Placeholder[](2);
        rule1.placeHolders[0].foreignCall = true;
        rule1.placeHolders[0].typeSpecificIndex = 0;
        rule1.placeHolders[1].pType = PT.UINT;
        rule1.placeHolders[1].typeSpecificIndex = 1;

        rule1.instructionSet = new uint256[](17);
        rule1.instructionSet[0] = uint(LC.PLH);
        rule1.instructionSet[1] = 0; // register 0
        rule1.instructionSet[2] = uint(LC.NUM);
        rule1.instructionSet[3] = 1; // register 1
        rule1.instructionSet[4] = uint(LC.EQ);
        rule1.instructionSet[5] = 0;
        rule1.instructionSet[6] = 1; // register 2
        rule1.instructionSet[7] = uint(LC.PLH);
        rule1.instructionSet[8] = 1; // register 3
        rule1.instructionSet[9] = uint(LC.NUM);
        rule1.instructionSet[10] = 4; // register 4
        rule1.instructionSet[11] = uint(LC.GT);
        rule1.instructionSet[12] = 3;
        rule1.instructionSet[13] = 4; // register 5
        rule1.instructionSet[14] = uint256(LC.AND);
        rule1.instructionSet[15] = 2;
        rule1.instructionSet[16] = 5;
        // Swapping isPositive to make sure the revert doesn't trigger (for comparison with V1 numbers)
        rule1 = _setUpEffect(rule1, _effectType, !isPositive);
        // Save the rule
        uint256 ruleId1 = RulesEngineDataFacet(address(red)).updateRule(0, rule1);
        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.ADDR;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 0;
        ForeignCall memory fc = RulesEngineDataFacet(address(red))
            .updateForeignCall(
                policyIds[0],
                address(_contractAddress),
                "getNaughty(address)",
                PT.UINT,
                fcArgs,
                typeSpecificIndices
            );
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId1;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(
            address(userContract),
            policyIds
        );
        fc; //added to silence warnings during testing revamp
    }

    function setupRulesWithForeignCallAndMinTransferSeparatePolicies(
        address _contractAddress,
        ET _effectType,
        bool isPositive
    ) public ifDeploymentTestsEnabled resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](2);

        policyIds[0] = _createBlankPolicy();
        policyIds[1] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(
            policyIds[0],
            bytes4(keccak256(bytes(functionSignature))),
            pTypes
        );

        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEngineDataFacet(address(red)).updatePolicy(
            policyIds[1],
            signatures,
            functionSignatureIds,
            blankRuleIds
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
        rule1 = _setUpEffect(rule1, _effectType, isPositive);
        // Save the rule
        uint256 ruleId1 = RulesEngineDataFacet(address(red)).updateRule(0, rule1);
        rule2 = _createGTRule(4);
        // Swapping from posEffects to negEffects to make sure the revert doesn't trigger (for comparison with V1 numbers)
        rule2.negEffects[0] = effectId_revert;
        uint256 ruleId2 = RulesEngineDataFacet(address(red)).updateRule(0, rule2);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.ADDR;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 0;
        ForeignCall memory fc = RulesEngineDataFacet(address(red))
            .updateForeignCall(
                policyIds[0],
                address(_contractAddress),
                "getNaughty(address)",
                PT.UINT,
                fcArgs,
                typeSpecificIndices
            );
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId1;


        // ruleIds[0][1] = ruleId2;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        ruleIds[0][0] = ruleId2;
        _addRuleIdsToPolicy(policyIds[1], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(
            address(userContract),
            policyIds
        );
        fc; //added to silence warnings during testing revamp
    }

   function setupRulesWithForeignCallPlusMinTransferAndMaxTransfer(
        address _contractAddress,
        ET _effectType,
        bool isPositive
    ) public ifDeploymentTestsEnabled resetsGlobalVariables {
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

        {
            // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
            Rule memory rule1;
            Rule memory rule2;
            Rule memory rule3;
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
            rule1 = _setUpEffect(rule1, _effectType, isPositive);
            // Save the rule
            uint256 ruleId1 = RulesEngineDataFacet(address(red)).updateRule(0, rule1);
            rule2 = _createGTRule(4);
            rule3 = _createLTRule(4);
            rule2.posEffects[0] = effectId_revert;
            // Swapping from posEffect to negEffects to make sure the revert doesn't trigger (for comparison with V1 numbers)
            rule3.negEffects[0] = effectId_revert;
            uint256 ruleId2 = RulesEngineDataFacet(address(red)).updateRule(0, rule2);
            uint256 ruleId3 = RulesEngineDataFacet(address(red)).updateRule(0, rule3);
            ruleIds.push(new uint256[](3));
            ruleIds[0][0] = ruleId1;
            ruleIds[0][1] = ruleId2;
            ruleIds[0][2] = ruleId3;
            _addRuleIdsToPolicy(policyIds[0], ruleIds);
        }
        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.ADDR;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 0;
        {
            ForeignCall memory fc = RulesEngineDataFacet(address(red))
                .updateForeignCall(
                    policyIds[0],
                    _contractAddress,
                    "getNaughty(address)",
                    PT.UINT,
                    fcArgs,
                    typeSpecificIndices
                );
        }

        RulesEngineDataFacet(address(red)).applyPolicy(
            address(userContract),
            policyIds
        );
        //fc; //added to silence warnings during testing revamp
    }

/**********  Rule Setup Helpers **********/
    function _exampleContractGasReport(uint256 _amount, address contractAddress, string memory _label) public {
        startMeasuringGas(_label);
        ExampleERC20(contractAddress).transfer(address(0x7654321), _amount);
        gasUsed = stopMeasuringGas();
        console.log(_label, gasUsed);  
    }



}
