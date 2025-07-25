/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract ERC20UnitTestsCommon is RulesEngineCommon {
    string constant ERC20_TRANSFER_SIGNATURE = "transfer(address,uint256)";
    string constant ERC20_TRANSFER_FROM_SIGNATURE = "transferFrom(address,address,uint256)";
    string constant ERC20_MINT_SIGNATURE = "mint(address,uint256)";

    function testERC20_Transfer_Before_Unit_checkRule_ForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        userContractERC20.mint(USER_ADDRESS, 1_000_000 * ATTO);
        _setup_checkRule_ForeignCall_Positive(ruleValue, userContractERC20Address);

        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        vm.startPrank(USER_ADDRESS);
        bool response = userContractERC20.transfer(address(0x7654321), transferValue);
        assertTrue(response);
    }

    function testERC20_Transfer_Before_Unit_checkRule_ForeignCall_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        userContractERC20.mint(USER_ADDRESS, 1_000_000 * ATTO);
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        ruleValue = 15;
        transferValue = 10;
        _setup_checkRule_ForeignCall_Negative(ruleValue, userContractERC20Address);
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        vm.startPrank(USER_ADDRESS);
        vm.expectRevert(abi.encodePacked(revert_text));
        userContractERC20.transfer(address(0x7654321), transferValue);
    }

    function testERC20_TransferFrom_Before_Unit_checkRule_ForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        userContractERC20.mint(USER_ADDRESS, 1_000_000 * ATTO);
        _setup_checkRule_TransferFrom_ForeignCall_Positive(ruleValue, userContractERC20Address);

        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        vm.startPrank(USER_ADDRESS);
        userContractERC20.approve(USER_ADDRESS, transferValue);
        bool response = userContractERC20.transferFrom(USER_ADDRESS, address(0x7654321), transferValue);
        assertTrue(response);
    }

    function testERC20_Transfer_Unit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        userContractERC20.mint(USER_ADDRESS, 1_000_000 * ATTO);
        _setupRuleWithRevert(address(userContractERC20));
        vm.startPrank(USER_ADDRESS);
        vm.expectRevert(abi.encodePacked(revert_text));
        userContractERC20.transfer(address(0x7654321), 5);
    }

    function testERC20_TransferFrom_Unit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        userContractERC20.mint(USER_ADDRESS, 1_000_000 * ATTO);
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.UINT;
        pTypes[3] = ParamTypes.ADDR;
        _setupRuleWithRevertTransferFrom(ERC20_TRANSFER_FROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        userContractERC20.approve(USER_ADDRESS, 3);
        vm.expectRevert(abi.encodePacked(revert_text));
        userContractERC20.transferFrom(USER_ADDRESS, address(0x7654321), 3);
    }

    function testERC20_TransferFrom_Unit_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        userContractERC20.mint(USER_ADDRESS, 1_000_000 * ATTO);
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.UINT;
        pTypes[3] = ParamTypes.ADDR;
        _setupRuleWithRevertTransferFrom(ERC20_TRANSFER_FROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        userContractERC20.approve(USER_ADDRESS, 5);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        bool response = userContractERC20.transferFrom(USER_ADDRESS, address(0x7654321), 5);
        assertTrue(response);
    }

    function testERC20_Mint_Unit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        _setupRuleWithRevertMint(ERC20_MINT_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        vm.expectRevert(abi.encodePacked(revert_text));
        userContractERC20.mint(USER_ADDRESS, 3);
    }

    function testERC20_Mint_Unit_Positve() public ifDeploymentTestsEnabled endWithStopPrank {
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        _setupRuleWithRevertMint(ERC20_MINT_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        userContractERC20.mint(USER_ADDRESS, 5);
    }

    function testERC20_Unit_Disabled_Policy() public ifDeploymentTestsEnabled endWithStopPrank {
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        // Expect revert while rule is enabled
        uint256 _policyId = _setupRuleWithRevertMint(ERC20_MINT_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        vm.expectRevert(abi.encodePacked(revert_text));
        userContractERC20.mint(USER_ADDRESS, 3);

        // Disable the policy and expect it to go through
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).disablePolicy(_policyId);
        assertTrue(RulesEnginePolicyFacet(address(red)).isDisabledPolicy(_policyId));
        vm.startPrank(USER_ADDRESS);
        userContractERC20.mint(USER_ADDRESS, 3);
    }

    function _setupRuleWithRevertTransferFrom(
        string memory _callingFunction,
        ParamTypes[] memory pTypes
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables {
        uint256[] memory policyIds = new uint256[](1);

        policyIds[0] = _createBlankPolicyOpen();

        _addCallingFunctionToPolicyOpen(policyIds[0], bytes4(keccak256(bytes(_callingFunction))), pTypes, _callingFunction);

        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule = _createGTRuleTransferFrom(4);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyIds[0], 0, rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractERC20Address, policyIds);
    }

    function _setupRuleWithRevertMint(
        string memory _callingFunction,
        ParamTypes[] memory pTypes
    ) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables returns (uint256 _policyId) {
        uint256[] memory policyIds = new uint256[](1);

        _policyId = policyIds[0] = _createBlankPolicyOpen();

        _addCallingFunctionToPolicyOpen(policyIds[0], bytes4(keccak256(bytes(_callingFunction))), pTypes, _callingFunction);

        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule = _createGTRuleMint(4);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyIds[0], 0, rule, ruleName, ruleDescription);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractERC20Address, policyIds);
        return _policyId;
    }

    function _createGTRuleTransferFrom(uint256 _amount) public returns (Rule memory) {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        uint256[] memory instructionSet = new uint256[](7);
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LogicalOp.NUM);
        instructionSet[3] = _amount;
        instructionSet[4] = uint(LogicalOp.GT);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        rule.instructionSet = rule.instructionSet = instructionSet;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 2;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

    function _createGTRuleMint(uint256 _amount) public returns (Rule memory) {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        uint256[] memory instructionSet = new uint256[](7);
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LogicalOp.NUM);
        instructionSet[3] = _amount;
        instructionSet[4] = uint(LogicalOp.GT);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        rule.instructionSet = rule.instructionSet = instructionSet;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }
}
