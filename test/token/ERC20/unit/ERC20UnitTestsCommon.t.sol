/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "src/example/ExampleERC20.sol";

abstract contract ERC20UnitTestsCommon is RulesEngineCommon {

    ExampleERC20 userContract;
    string constant ERC20_TRANSFER_SIGNATURE = "transfer(address,uint256)";
    string constant ERC20_TRANSFER_FROM_SIGNATURE = "transferFrom(address,address,uint256)";
    string constant ERC20_MINT_SIGNATURE = "mint(address,uint256)";

    function testERC20_Transfer_Before_Unit_checkRule_ForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        userContract.mint(USER_ADDRESS, 1_000_000 * ATTO);
        uint256 ruleValue = 10; 
        uint256 transferValue = 15;
        _setup_checkRule_ForeignCall_Positive(ruleValue, ERC20_TRANSFER_SIGNATURE);

        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly 
        vm.startPrank(USER_ADDRESS);
        bool response = userContract.transfer(address(0x7654321), transferValue);
        assertTrue(response);
    }

    function testERC20_Transfer_Before_Unit_checkRule_ForeignCall_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        userContract.mint(USER_ADDRESS, 1_000_000 * ATTO);
        uint256 ruleValue = 15; 
        uint256 transferValue = 10;
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        _setup_checkRule_ForeignCall_Negative(ruleValue, ERC20_TRANSFER_SIGNATURE, pTypes);
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly 
        vm.startPrank(USER_ADDRESS);
        vm.expectRevert(abi.encodePacked(revert_text)); 
        userContract.transfer(address(0x7654321), transferValue);
    }

    function testERC20_TransferFrom_Before_Unit_checkRule_ForeignCall_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        userContract.mint(USER_ADDRESS, 1_000_000 * ATTO);
        uint256 ruleValue = 10; 
        uint256 transferValue = 15;
        _setup_checkRule_TransferFrom_ForeignCall_Positive(ruleValue, ERC20_TRANSFER_FROM_SIGNATURE);

        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly 
        vm.startPrank(USER_ADDRESS);
        userContract.approve(USER_ADDRESS, transferValue);
        bool response = userContract.transferFrom(USER_ADDRESS, address(0x7654321), transferValue);
        assertTrue(response);
    }

    function testERC20_Transfer_Unit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        userContract.mint(USER_ADDRESS, 1_000_000 * ATTO);
        _setupRuleWithRevert(address(userContract));
        vm.startPrank(USER_ADDRESS);
        vm.expectRevert(abi.encodePacked(revert_text)); 
        userContract.transfer(address(0x7654321), 5);
    }

    function testERC20_TransferFrom_Unit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        userContract.mint(USER_ADDRESS, 1_000_000 * ATTO);
        PT[] memory pTypes = new PT[](4);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.ADDR;
        pTypes[2] = PT.UINT;
        pTypes[3] = PT.ADDR;
        _setupRuleWithRevertTransferFrom(ERC20_TRANSFER_FROM_SIGNATURE,pTypes);
        vm.startPrank(USER_ADDRESS);
        userContract.approve(USER_ADDRESS, 3);
        vm.expectRevert(abi.encodePacked(revert_text)); 
        userContract.transferFrom(USER_ADDRESS, address(0x7654321), 3);
    }

    function testERC20_TransferFrom_Unit_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        // set up the ERC20
        userContract.mint(USER_ADDRESS, 1_000_000 * ATTO);
        PT[] memory pTypes = new PT[](4);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.ADDR;
        pTypes[2] = PT.UINT;
        pTypes[3] = PT.ADDR;
        _setupRuleWithRevertTransferFrom(ERC20_TRANSFER_FROM_SIGNATURE,pTypes);
        vm.startPrank(USER_ADDRESS);
        userContract.approve(USER_ADDRESS, 5);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        bool response = userContract.transferFrom(USER_ADDRESS, address(0x7654321), 5);
        assertTrue(response);
    }

    function testERC20_Mint_Unit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        PT[] memory pTypes = new PT[](3);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.ADDR;
        _setupRuleWithRevertMint(ERC20_MINT_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        vm.expectRevert(abi.encodePacked(revert_text)); 
        userContract.mint(USER_ADDRESS, 3);
    }

    function testERC20_Mint_Unit_Positve() public ifDeploymentTestsEnabled endWithStopPrank {
        PT[] memory pTypes = new PT[](3);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;
        pTypes[2] = PT.ADDR;
        _setupRuleWithRevertMint(ERC20_MINT_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text); 
        userContract.mint(USER_ADDRESS, 5);
    }

    function _setupRuleWithRevertTransferFrom(string memory _functionSignature, PT[] memory pTypes) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables{
        uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicy();

        _addFunctionSignatureToPolicy(policyIds[0], bytes4(keccak256(bytes(_functionSignature))), pTypes);

        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule =  _createGTRuleTransferFrom(4);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(policyIds[0], 0, rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _setupRuleWithRevertMint(string memory _functionSignature, PT[] memory pTypes) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables{
        uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicy();

        _addFunctionSignatureToPolicy(policyIds[0], bytes4(keccak256(bytes(_functionSignature))), pTypes);

        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule =  _createGTRuleMint(4);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).updateRule(policyIds[0], 0, rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _createGTRuleTransferFrom(uint256 _amount) public returns(Rule memory){
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LC.PLH, 0, LC.NUM, _amount, LC.GT, 0, 1
        uint256[] memory instructionSet = new uint256[](7);
        instructionSet[0] = uint(LC.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LC.NUM);
        instructionSet[3] = _amount;
        instructionSet[4] = uint(LC.GT);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        rule.instructionSet = rule.instructionSet = instructionSet;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 2;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

    function _createGTRuleMint(uint256 _amount) public returns(Rule memory){
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LC.PLH, 0, LC.NUM, _amount, LC.GT, 0, 1
        uint256[] memory instructionSet = new uint256[](7);
        instructionSet[0] = uint(LC.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LC.NUM);
        instructionSet[3] = _amount;
        instructionSet[4] = uint(LC.GT);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        rule.instructionSet = rule.instructionSet = instructionSet;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

}
