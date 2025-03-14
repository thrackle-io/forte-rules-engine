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

    // ERC20's for Tests with Rules Engine
    //-------------------------------------------------------------------------------------
    ExampleERC20 userContractNoPolicy;
    ExampleERC20 userContractMinTransfer;
    ExampleERC20 userContractFC;
    ExampleERC20 userContractFCPlusMin;
    ExampleERC20 userContractFCPlusMinPlusMax;
    ExampleERC20 userContractFCPlusMinPlusMaxOneRule;
    ExampleERC20 userContractFCPlusMinSeparatePolicy;
    ExampleERC20 userContractManyChecksMin;
    ExampleERC20 userContractMTplusEvent;
    ExampleERC20 userContractMTplusEventDynamic;
    //-------------------------------------------------------------------------------------

    function setUp() public {
        red = _createRulesEngineDiamond(address(0xB0b));

        //R2V2 Setup
        //-------------------------------------------------------------------------------------
        // No Policy
        userContractNoPolicy = new ExampleERC20("Token Name", "SYMB");
        userContractNoPolicy.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractNoPolicy.setRulesEngineAddress(address(red));
        userContractNoPolicy.setCallingContractAdmin(callingContractAdmin);

        // Min Transfer
        userContractMinTransfer = new ExampleERC20("Token Name", "SYMB");
        userContractMinTransfer.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractMinTransfer.setRulesEngineAddress(address(red));
        userContractMinTransfer.setCallingContractAdmin(callingContractAdmin);
        _setupRuleWithRevert(address(userContractMinTransfer));

        // OFAC
        userContractFC = new ExampleERC20("Token Name", "SYMB");
        userContractFC.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractFC.setRulesEngineAddress(address(red));
        userContractFC.setCallingContractAdmin(callingContractAdmin);
        testContract2 = new ForeignCallTestContractOFAC();
        setupRuleWithOFACForeignCall(address(testContract2), ET.REVERT, true);
        testContract2.addToNaughtyList(address(0x7654321));

        // OFAC Plus Min Transfer
        userContractFCPlusMin = new ExampleERC20("Token Name", "SYMB");
        userContractFCPlusMin.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractFCPlusMin.setRulesEngineAddress(address(red));
        userContractFCPlusMin.setCallingContractAdmin(callingContractAdmin);
        setupRulesWithForeignCallAndMinTransfer(address(testContract2), ET.REVERT, true);

        // OFAC Plus Min In One Rule        
        userContractFCPlusMinPlusMaxOneRule = new ExampleERC20("Token Name", "SYMB");
        userContractFCPlusMinPlusMaxOneRule.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractFCPlusMinPlusMaxOneRule.setRulesEngineAddress(address(red));
        userContractFCPlusMinPlusMaxOneRule.setCallingContractAdmin(callingContractAdmin);
        setupRulesWithForeignCallPlusMinTransferAndMaxTransferInOneRule(address(testContract2), ET.REVERT, true);

        // OFAC Plus Min In Separate Policies
        userContractFCPlusMinSeparatePolicy = new ExampleERC20("Token Name", "SYMB");
        userContractFCPlusMinSeparatePolicy.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractFCPlusMinSeparatePolicy.setRulesEngineAddress(address(red));
        userContractFCPlusMinSeparatePolicy.setCallingContractAdmin(callingContractAdmin);
        setupRulesWithForeignCallAndMinTransferSeparatePolicies(address(testContract2), ET.REVERT, true);

        // Min Transfer 20 iterations 
        userContractManyChecksMin = new ExampleERC20("Token Name", "SYMB");
        userContractManyChecksMin.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractManyChecksMin.setRulesEngineAddress(address(red));
        userContractManyChecksMin.setCallingContractAdmin(callingContractAdmin);
        _setupRuleWithRevertManyCondition();

        // OFAC Plus Min Plus Max Transfer 
        userContractFCPlusMinPlusMax = new ExampleERC20("Token Name", "SYMB");
        userContractFCPlusMinPlusMax.mint(USER_ADDRESS, 1_000_000 * ATTO);
        userContractFCPlusMinPlusMax.setRulesEngineAddress(address(red));
        userContractFCPlusMinPlusMax.setCallingContractAdmin(callingContractAdmin);
        setupRulesWithForeignCallPlusMinTransferAndMaxTransfer(address(testContract2), ET.REVERT, true);

        //-------------------------------------------------------------------------------------

        testContract = new ForeignCallTestContract();
        _setupEffectProcessor(); 

    }
    function testGasExampleContract_NoPoliciesActive() public endWithStopPrank {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(1, address(userContractNoPolicy), "Using REv2 No Policies Active");   
    }

    function testGasExampleSimpleMinTransferTriggeredWithRevertEffect() public endWithStopPrank {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(3, address(userContractMinTransfer), "Using REv2 Min Transfer Triggered With Revert Effect"); 
    }


/**********  OFAC Prep functions to ensure warm storage comparisons **********/
    function testGasExampleOFAC() public endWithStopPrank() {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(5, address(userContractFC), "Using REv2 OFAC gas report"); 
    }

    function testGasExampleOFACWithMinTransfer() public endWithStopPrank() {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(5, address(userContractFCPlusMin), "Using REv2 OFAC with min transfer gas report"); 
    }

    function testGasExampleOFACWithMinTransferAndMaxTransfer() public endWithStopPrank() {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(1, address(userContractFCPlusMinPlusMax), "Using REv2 OFAC with min and max transfer gas report"); 
    }

    function testGasExampleOFACWithMinTransferInOneRule() public endWithStopPrank() {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(5, address(userContractFCPlusMinPlusMaxOneRule), "Using REv2 OFAC with min transfer gas report"); 
    }

    function testGasExampleOFACWithMinTransferInSeparatePolicies() public endWithStopPrank() {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(5, address(userContractFCPlusMinSeparatePolicy), "Using REv2 OFAC with min transfer gas report"); 
    }

    function testGasExampleMinTransferMany() public endWithStopPrank() {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(5, address(userContractManyChecksMin), "Using REv2 min transfer 20 iterations"); 
    }

    function _testGasExampleMinTransferWithSetEventParams() public {
        vm.startPrank(USER_ADDRESS);
        vm.expectEmit(true, true, false, false);
        emit x5f6d49ad_RulesEngineEvent(1, EVENTTEXT, 5);
        _exampleContractGasReport(5, address(userContractMTplusEvent), "Using REv2 Event Effect with min transfer gas report"); 
    }

    function _testGasExampleMinTransferWithDynamicEventParams() public {
        vm.startPrank(USER_ADDRESS);
        vm.expectEmit(true, true, false, false);
        emit x5f6d49ad_RulesEngineEvent(1, EVENTTEXT, 5);
        _exampleContractGasReport(5, address(userContractMTplusEventDynamic), "Using REv2 Event Effect with min transfer gas report"); 
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

        _addFunctionSignatureToPolicy(policyIds[0]);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.ADDR;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 0;
        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = _contractAddress;
        fc.signature = bytes4(keccak256(bytes("getNaughty(address)")));
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 1;
        uint256 foreignCallId = RulesEngineDataFacet(address(red))
            .createForeignCall(
                policyIds[0],
                fc
            );

        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;

        // Build the foreign call placeholder
        rule.placeHolders = new Placeholder[](2);
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = uint128(foreignCallId);
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
        uint256 ruleId = RulesEngineDataFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEngineDataFacet(address(red)).applyPolicy(
            address(userContractFC),
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

        _addFunctionSignatureToPolicy(policyIds[0]);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.ADDR;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 0;
        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = _contractAddress;
        fc.signature = bytes4(keccak256(bytes("getNaughty(address)")));
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 1;
        uint256 foreignCallId = RulesEngineDataFacet(address(red))
            .createForeignCall(
                policyIds[0],
                fc
            );

        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule1;
        Rule memory rule2;
        // Build the foreign call placeholder
        rule1.placeHolders = new Placeholder[](2);
        rule1.placeHolders[0].foreignCall = true;
        rule1.placeHolders[0].typeSpecificIndex = uint128(foreignCallId);
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
        uint256 ruleId1 = RulesEngineDataFacet(address(red)).createRule(policyIds[0], rule1);
        rule2 = _createGTRule(4);
        // Swapping from posEffect to negEffects to make sure the revert doesn't trigger (for comparison with V1 numbers)
        rule2.negEffects[0] = effectId_revert;
        uint256 ruleId2 = RulesEngineDataFacet(address(red)).createRule(policyIds[0], rule2);

        ruleIds.push(new uint256[](2));
        ruleIds[0][0] = ruleId1;
        ruleIds[0][1] = ruleId2;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEngineDataFacet(address(red)).applyPolicy(
            address(userContractFCPlusMin),
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

        _addFunctionSignatureToPolicy(policyIds[0]);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.ADDR;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 1;
        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = _contractAddress;
        fc.signature = bytes4(keccak256(bytes("getNaughty(address)")));
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 1;
        uint256 foreignCallId = RulesEngineDataFacet(address(red))
            .createForeignCall(
                policyIds[0],
                fc
            );

        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule1;
        // Build the foreign call placeholder
        rule1.placeHolders = new Placeholder[](2);
        rule1.placeHolders[0].foreignCall = true;
        rule1.placeHolders[0].typeSpecificIndex = uint128(foreignCallId);
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
        rule1 = _setUpEffect(rule1, _effectType, isPositive);
        // Save the rule
        uint256 ruleId1 = RulesEngineDataFacet(address(red)).createRule(policyIds[0], rule1);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId1;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEngineDataFacet(address(red)).applyPolicy(
            address(userContractFCPlusMinPlusMaxOneRule),
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
        
        _addFunctionSignatureToPolicy(policyIds[0]);

        _addFunctionSignatureToPolicy(policyIds[1]);

        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.ADDR;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 0;
        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = _contractAddress;
        fc.signature = bytes4(keccak256(bytes("getNaughty(address)")));
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 1;
        uint256 foreignCallId = RulesEngineDataFacet(address(red))
            .createForeignCall(
                policyIds[0],
                fc
            );

        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule1;
        Rule memory rule2;
        // Build the foreign call placeholder
        rule1.placeHolders = new Placeholder[](2);
        rule1.placeHolders[0].foreignCall = true;
        rule1.placeHolders[0].typeSpecificIndex = uint128(foreignCallId);
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
        uint256 ruleId1 = RulesEngineDataFacet(address(red)).createRule(policyIds[0], rule1);
        rule2 = _createGTRule(4);
        // Swapping from posEffects to negEffects to make sure the revert doesn't trigger (for comparison with V1 numbers)
        rule2.negEffects[0] = effectId_revert;
        uint256 ruleId2 = RulesEngineDataFacet(address(red)).createRule(policyIds[0], rule2);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId1;

        bytes4[] memory signaturesNew = new bytes4[](1);
        signaturesNew[0] = bytes4(keccak256(bytes(functionSignature)));
        uint256[] memory functionSignatureIdsNew = new uint256[](1);
        functionSignatureIdsNew[0] = 1;
        // ruleIds[0][1] = ruleId2;
        RulesEngineDataFacet(address(red)).updatePolicy(policyIds[0], signaturesNew, functionSignatureIdsNew, ruleIds, PolicyType.CLOSED_POLICY);

        // Add rules for the second policy
        ruleId1 = RulesEngineDataFacet(address(red)).createRule(policyIds[1], rule1);
        ruleId2 = RulesEngineDataFacet(address(red)).createRule(policyIds[1], rule2);
        ruleIds[0][0] = ruleId2;

        RulesEngineDataFacet(address(red)).updatePolicy(policyIds[1], signaturesNew, functionSignatureIdsNew, ruleIds, PolicyType.CLOSED_POLICY);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEngineDataFacet(address(red)).applyPolicy(
            address(userContractFCPlusMinSeparatePolicy),
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

        _addFunctionSignatureToPolicy(policyIds[0]);
        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.ADDR;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 0;

        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = _contractAddress;
        fc.signature = bytes4(keccak256(bytes("getNaughty(address)")));
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 1;
        uint256 foreignCallId; 
        {
            foreignCallId = RulesEngineDataFacet(address(red))
                .createForeignCall(
                    policyIds[0],
                    fc
                );
        }

        {
            // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
            Rule memory rule1;
            Rule memory rule2;
            Rule memory rule3;
            // Build the foreign call placeholder
            rule1.placeHolders = new Placeholder[](2);
            rule1.placeHolders[0].foreignCall = true;
            rule1.placeHolders[0].typeSpecificIndex = uint128(foreignCallId);
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
            uint256 ruleId1 = RulesEngineDataFacet(address(red)).createRule(policyIds[0], rule1);
            rule2 = _createGTRule(4);
            rule3 = _createLTRule();
            rule2.posEffects[0] = effectId_revert;
            // Swapping from posEffect to negEffects to make sure the revert doesn't trigger (for comparison with V1 numbers)
            rule3.negEffects[0] = effectId_revert;
            uint256 ruleId2 = RulesEngineDataFacet(address(red)).createRule(policyIds[0], rule2);
            uint256 ruleId3 = RulesEngineDataFacet(address(red)).createRule(policyIds[0], rule3);
            ruleIds.push(new uint256[](3));
            ruleIds[0][0] = ruleId1;
            ruleIds[0][1] = ruleId2;
            ruleIds[0][2] = ruleId3;
            _addRuleIdsToPolicy(policyIds[0], ruleIds);
        }
        
        
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEngineDataFacet(address(red)).applyPolicy(
            address(userContractFCPlusMinPlusMax),
            policyIds
        );
    }

    function _setupRuleWithRevertManyCondition()
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicy();

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0]);

        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        // Rule memory rule = _createGTRule(4);
        Rule memory rule;
        _setupEffectProcessor();
        // Instruction set: LC.PLH, 0, LC.NUM, _amount, LC.GT, 0, 1
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);

        rule.instructionSet = new uint256[](194);
        rule.instructionSet[0] = uint(LC.PLH); // register 0
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LC.NUM); // register 1
        rule.instructionSet[3] = 4;
        rule.instructionSet[4] = uint(LC.GT); // register 2
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.instructionSet[7] = uint(LC.PLH); // register 3
        rule.instructionSet[8] = 0;
        rule.instructionSet[9] = uint(LC.NUM); // register 4
        rule.instructionSet[10] = 4;
        rule.instructionSet[11] = uint(LC.GT); // register 5
        rule.instructionSet[12] = 3;
        rule.instructionSet[13] = 4;

        rule.instructionSet[14] = uint(LC.PLH); // register 6
        rule.instructionSet[15] = 0;
        rule.instructionSet[16] = uint(LC.NUM); // register 7
        rule.instructionSet[17] = 4;
        rule.instructionSet[18] = uint(LC.GT); // register 8
        rule.instructionSet[19] = 6;
        rule.instructionSet[20] = 7;

        rule.instructionSet[21] = uint(LC.PLH); // register 9
        rule.instructionSet[22] = 0;
        rule.instructionSet[23] = uint(LC.NUM); // register 10
        rule.instructionSet[24] = 4;
        rule.instructionSet[25] = uint(LC.GT); // register 11
        rule.instructionSet[26] = 9;
        rule.instructionSet[27] = 10;

        rule.instructionSet[28] = uint(LC.PLH); // register 12
        rule.instructionSet[29] = 0;
        rule.instructionSet[30] = uint(LC.NUM); // register 13
        rule.instructionSet[31] = 4;
        rule.instructionSet[32] = uint(LC.GT); // register 14
        rule.instructionSet[33] = 12;
        rule.instructionSet[34] = 13;

        rule.instructionSet[35] = uint(LC.PLH); // register 15
        rule.instructionSet[36] = 0;
        rule.instructionSet[37] = uint(LC.NUM); // register 16
        rule.instructionSet[38] = 4;
        rule.instructionSet[39] = uint(LC.GT); // register 17
        rule.instructionSet[40] = 15;
        rule.instructionSet[41] = 16;

        rule.instructionSet[42] = uint(LC.PLH); // register 18
        rule.instructionSet[43] = 0;
        rule.instructionSet[44] = uint(LC.NUM); // register 19
        rule.instructionSet[45] = 4;
        rule.instructionSet[46] = uint(LC.GT); // register 20
        rule.instructionSet[47] = 18;
        rule.instructionSet[48] = 19;

        rule.instructionSet[49] = uint(LC.PLH); // register 21
        rule.instructionSet[50] = 0;
        rule.instructionSet[51] = uint(LC.NUM); // register 22
        rule.instructionSet[52] = 4;
        rule.instructionSet[53] = uint(LC.GT); // register 23
        rule.instructionSet[54] = 21;
        rule.instructionSet[55] = 22;

        rule.instructionSet[56] = uint(LC.PLH); // register 24
        rule.instructionSet[57] = 0;
        rule.instructionSet[58] = uint(LC.NUM); // register 25
        rule.instructionSet[59] = 4;
        rule.instructionSet[60] = uint(LC.GT); // register 26
        rule.instructionSet[61] = 24;
        rule.instructionSet[62] = 25;

        rule.instructionSet[63] = uint(LC.PLH); // register 27
        rule.instructionSet[64] = 0;
        rule.instructionSet[65] = uint(LC.NUM); // register 28
        rule.instructionSet[66] = 4;
        rule.instructionSet[67] = uint(LC.GT); // register 29
        rule.instructionSet[68] = 27;
        rule.instructionSet[69] = 28;

        rule.instructionSet[70] = uint(LC.PLH); // register 30
        rule.instructionSet[71] = 0;
        rule.instructionSet[72] = uint(LC.NUM); // register 31
        rule.instructionSet[73] = 4;
        rule.instructionSet[74] = uint(LC.GT); // register 32
        rule.instructionSet[75] = 30;
        rule.instructionSet[76] = 31;

        rule.instructionSet[77] = uint(LC.PLH); // register 33
        rule.instructionSet[78] = 0;
        rule.instructionSet[79] = uint(LC.NUM); // register 34
        rule.instructionSet[80] = 4;
        rule.instructionSet[81] = uint(LC.GT); // register 35
        rule.instructionSet[82] = 33;
        rule.instructionSet[83] = 34;

        rule.instructionSet[84] = uint(LC.PLH); // register 36
        rule.instructionSet[85] = 0;
        rule.instructionSet[86] = uint(LC.NUM); // register 37
        rule.instructionSet[87] = 4;
        rule.instructionSet[88] = uint(LC.GT); // register 38
        rule.instructionSet[89] = 36;
        rule.instructionSet[90] = 37;

        rule.instructionSet[91] = uint(LC.PLH); // register 39
        rule.instructionSet[92] = 0;
        rule.instructionSet[93] = uint(LC.NUM); // register 40
        rule.instructionSet[94] = 4;
        rule.instructionSet[95] = uint(LC.GT); // register 41
        rule.instructionSet[96] = 39;
        rule.instructionSet[97] = 40;

        rule.instructionSet[98] = uint(LC.PLH); // register 42
        rule.instructionSet[99] = 0;
        rule.instructionSet[100] = uint(LC.NUM); // register 43
        rule.instructionSet[101] = 4;
        rule.instructionSet[102] = uint(LC.GT); // register 44
        rule.instructionSet[103] = 42;
        rule.instructionSet[104] = 43;

        rule.instructionSet[105] = uint(LC.PLH); // register 45
        rule.instructionSet[106] = 0;
        rule.instructionSet[107] = uint(LC.NUM); // register 46
        rule.instructionSet[108] = 4;
        rule.instructionSet[109] = uint(LC.GT); // register 47
        rule.instructionSet[110] = 45;
        rule.instructionSet[111] = 46;

        rule.instructionSet[112] = uint(LC.PLH); // register 48
        rule.instructionSet[113] = 0;
        rule.instructionSet[114] = uint(LC.NUM); // register 49
        rule.instructionSet[115] = 4;
        rule.instructionSet[116] = uint(LC.GT); // register 50
        rule.instructionSet[117] = 48;
        rule.instructionSet[118] = 49;

        rule.instructionSet[119] = uint(LC.PLH); // register 51
        rule.instructionSet[120] = 0;
        rule.instructionSet[121] = uint(LC.NUM); // register 52
        rule.instructionSet[122] = 4;
        rule.instructionSet[123] = uint(LC.GT); // register 53
        rule.instructionSet[124] = 51;
        rule.instructionSet[125] = 52;

        rule.instructionSet[126] = uint(LC.PLH); // register 54
        rule.instructionSet[127] = 0;
        rule.instructionSet[128] = uint(LC.NUM); // register 55
        rule.instructionSet[129] = 4;
        rule.instructionSet[130] = uint(LC.GT); // register 56
        rule.instructionSet[131] = 54;
        rule.instructionSet[132] = 55;

        rule.instructionSet[133] = uint(LC.PLH); // register 57
        rule.instructionSet[134] = 0;
        rule.instructionSet[135] = uint(LC.NUM); // register 58
        rule.instructionSet[136] = 4;
        rule.instructionSet[137] = uint(LC.GT); // register 59
        rule.instructionSet[138] = 56;
        rule.instructionSet[139] = 57;

        rule.instructionSet[140] = uint(LC.AND); // register 60
        rule.instructionSet[141] = 2;
        rule.instructionSet[142] = 5;

        rule.instructionSet[140] = uint(LC.AND); // register 61
        rule.instructionSet[141] = 60;
        rule.instructionSet[142] = 8;

        rule.instructionSet[143] = uint(LC.AND); // register 62
        rule.instructionSet[144] = 61;
        rule.instructionSet[145] = 11;

        rule.instructionSet[146] = uint(LC.AND); // register 63
        rule.instructionSet[147] = 62;
        rule.instructionSet[148] = 14;

        rule.instructionSet[149] = uint(LC.AND); // register 64
        rule.instructionSet[150] = 63;
        rule.instructionSet[151] = 17;

        rule.instructionSet[152] = uint(LC.AND); // register 65
        rule.instructionSet[153] = 64;
        rule.instructionSet[154] = 20;

        rule.instructionSet[155] = uint(LC.AND); // register 66
        rule.instructionSet[156] = 65;
        rule.instructionSet[157] = 23;

        rule.instructionSet[158] = uint(LC.AND); // register 67
        rule.instructionSet[159] = 66;
        rule.instructionSet[160] = 26;

        rule.instructionSet[161] = uint(LC.AND); // register 68
        rule.instructionSet[162] = 67;
        rule.instructionSet[163] = 29;

        rule.instructionSet[164] = uint(LC.AND); // register 69
        rule.instructionSet[165] = 68;
        rule.instructionSet[166] = 32;

        rule.instructionSet[167] = uint(LC.AND); // register 70
        rule.instructionSet[168] = 69;
        rule.instructionSet[169] = 35;

        rule.instructionSet[170] = uint(LC.AND); // register 71
        rule.instructionSet[171] = 70;
        rule.instructionSet[172] = 38;

        rule.instructionSet[173] = uint(LC.AND); // register 72
        rule.instructionSet[174] = 71;
        rule.instructionSet[175] = 41;

        rule.instructionSet[176] = uint(LC.AND); // register 73
        rule.instructionSet[177] = 72;
        rule.instructionSet[178] = 44;

        rule.instructionSet[179] = uint(LC.AND); // register 74
        rule.instructionSet[180] = 73;
        rule.instructionSet[181] = 47;

        rule.instructionSet[182] = uint(LC.AND); // register 75
        rule.instructionSet[183] = 74;
        rule.instructionSet[184] = 50;

        rule.instructionSet[185] = uint(LC.AND); // register 76
        rule.instructionSet[186] = 75;
        rule.instructionSet[187] = 53;

        rule.instructionSet[188] = uint(LC.AND); // register 77
        rule.instructionSet[189] = 76;
        rule.instructionSet[190] = 56;

        rule.instructionSet[191] = uint(LC.AND); // register 78
        rule.instructionSet[192] = 77;
        rule.instructionSet[193] = 59;

        rule.posEffects[0] = effectId_revert;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEngineDataFacet(address(red)).applyPolicy(address(userContractManyChecksMin), policyIds);
    }

    function _setupRuleWithEventParamsMinTransfer(bytes memory param, PT pType) 
        public
        ifDeploymentTestsEnabled
        resetsGlobalVariables
    {

        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        _addFunctionSignatureToPolicy(policyIds[0]);

        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        // Rule memory rule = _createGTRule(4);
        Rule memory rule;
        effectId_event = _createCustomEffectEvent(param, pType);
        // Instruction set: LC.PLH, 0, LC.NUM, _amount, LC.GT, 0, 1
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = uint(LC.NUM);
        rule.instructionSet[3] = 4;
        rule.instructionSet[4] = uint(LC.GT); // register 2
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).createRule(policyIds[0], rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

/**********  Rule Setup Helpers **********/
    function _exampleContractGasReport(uint256 _amount, address contractAddress, string memory _label) public {
        startMeasuringGas(_label);
        ExampleERC20(contractAddress).transfer(address(0x7654321), _amount);
        gasUsed = stopMeasuringGas();
        console.log(_label, gasUsed);  
    }



}
