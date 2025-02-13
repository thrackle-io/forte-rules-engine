/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "src/example/ExampleERC721.sol";

abstract contract ERC721UnitTestsCommon is RulesEngineCommon {

    ExampleERC721 userContract;
    string constant ERC721_SAFEMINT_SIGNATURE = "safeMint(address)";
    string constant ERC721_SAFETRANSFERFROM_SIGNATURE = "safeTransferFrom(address,address,uint256,bytes)";
    string constant ERC721_TRANSFERFROM_SIGNATURE = "transferFrom(address,address,uint256)";

    
    function testERC721_SafeMint_Unit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.ADDR;
        _setupRuleWithRevertSafeMint(ERC721_SAFEMINT_SIGNATURE, pTypes);
        vm.expectRevert(abi.encodePacked(revert_text)); 
        userContract.safeMint(address(55));
    }

    function testERC721_SafeMint_Unit_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.ADDR;
        _setupRuleWithRevertSafeMint(ERC721_SAFEMINT_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text); 
        userContract.safeMint(USER_ADDRESS);
    }

    function testERC721_SafeTransferFrom_Unit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        userContract.safeMint(USER_ADDRESS);
        PT[] memory pTypes = new PT[](5);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.ADDR;
        pTypes[2] = PT.UINT;
        pTypes[3] = PT.BYTES;
        pTypes[4] = PT.ADDR;
        _setupRuleWithRevertSafeTransferFrom(ERC721_SAFETRANSFERFROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        vm.expectRevert(abi.encodePacked(revert_text)); 
        userContract.safeTransferFrom(USER_ADDRESS, USER_ADDRESS_2, 0, "");
    }

    function testERC721_SafeTransferFrom_Unit_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        userContract.safeMint(USER_ADDRESS_2);
        PT[] memory pTypes = new PT[](5);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.ADDR;
        pTypes[2] = PT.UINT;
        pTypes[3] = PT.BYTES;
        pTypes[4] = PT.ADDR;
        _setupRuleWithRevertSafeTransferFrom(ERC721_SAFETRANSFERFROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS_2);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        userContract.safeTransferFrom(USER_ADDRESS_2, USER_ADDRESS, 0, "");
    }

    function testERC721_TransferFrom_Unit_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        userContract.safeMint(USER_ADDRESS_2);
       PT[] memory pTypes = new PT[](4);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.ADDR;
        pTypes[2] = PT.UINT;
        pTypes[3] = PT.ADDR;
        _setupRuleWithRevertTransferFrom(ERC721_TRANSFERFROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS_2);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        userContract.transferFrom(USER_ADDRESS_2, USER_ADDRESS, 0);
    }

    function testERC721_TransferFrom_Unit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        userContract.safeMint(USER_ADDRESS);
        PT[] memory pTypes = new PT[](4);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.ADDR;
        pTypes[2] = PT.UINT;
        pTypes[3] = PT.ADDR;
        _setupRuleWithRevertTransferFrom(ERC721_TRANSFERFROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        vm.expectRevert(abi.encodePacked(revert_text)); 
        userContract.transferFrom(USER_ADDRESS, USER_ADDRESS_2, 0);
    }
    
    function _setupRuleWithRevertSafeMint(string memory _functionSignature, PT[] memory pTypes) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables{
        // if the address equals the mint to address, then emit event, else revert
        uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicy();

        _addFunctionSignatureToPolicy(policyIds[0], bytes4(keccak256(bytes(_functionSignature))), pTypes);

        Rule memory rule =  _createEQRuleSafeMint(USER_ADDRESS);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;
        rule.policyId = policyIds[0];
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).createRule(0,rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _setupRuleWithRevertSafeTransferFrom(string memory _functionSignature, PT[] memory pTypes) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables{
        // if the address equals the mint to address, then emit event, else revert
        uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicy();

        _addFunctionSignatureToPolicy(policyIds[0], bytes4(keccak256(bytes(_functionSignature))), pTypes);

        Rule memory rule =  _createEQRuleSafeTransferFrom(USER_ADDRESS);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;
        rule.policyId = policyIds[0];
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).createRule(0,rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _setupRuleWithRevertTransferFrom(string memory _functionSignature, PT[] memory pTypes) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables{
        // if the address equals the mint to address, then emit event, else revert
        uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicy();

        _addFunctionSignatureToPolicy(policyIds[0], bytes4(keccak256(bytes(_functionSignature))), pTypes);

        Rule memory rule =  _createEQRuleTransferFrom(USER_ADDRESS);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;
        rule.policyId = policyIds[0];
        // Save the rule
        uint256 ruleId = RulesEngineDataFacet(address(red)).createRule(0,rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEngineDataFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _createEQRuleSafeMint(address _address) public returns(Rule memory){
        // Rule: _to == _address -> revert -> safeMint(address _to)"
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LC.PLH, 0, LC.NUM, _amount, LC.GT, 0, 1
        uint256[] memory instructionSet = new uint256[](7);
        instructionSet[0] = uint(LC.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LC.NUM);
        instructionSet[3] = uint256(uint160(_address));
        instructionSet[4] = uint(LC.EQ);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        rule.instructionSet = rule.instructionSet = instructionSet;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

    function _createEQRuleSafeTransferFrom(address _address) public returns(Rule memory){
        // Rule: _to == _address -> revert -> safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data)"
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LC.PLH, 0, LC.NUM, _amount, LC.GT, 0, 1
        uint256[] memory instructionSet = new uint256[](7);
        instructionSet[0] = uint(LC.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LC.NUM);
        instructionSet[3] = uint256(uint160(_address));
        instructionSet[4] = uint(LC.EQ);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        rule.instructionSet = rule.instructionSet = instructionSet;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

    function _createEQRuleTransferFrom(address _address) public returns(Rule memory){
        // Rule: _to == _address -> revert -> TransferFrom(address from, address to, uint256 tokenId)"
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LC.PLH, 0, LC.NUM, _amount, LC.GT, 0, 1
        uint256[] memory instructionSet = new uint256[](7);
        instructionSet[0] = uint(LC.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LC.NUM);
        instructionSet[3] = uint256(uint160(_address));
        instructionSet[4] = uint(LC.EQ);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        rule.instructionSet = rule.instructionSet = instructionSet;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }

}
