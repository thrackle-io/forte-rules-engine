/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "src/example/ERC721A/ExampleERC721A.sol";

abstract contract ERC721AUnitTestsCommon is RulesEngineCommon {
    ExampleERC721A userContract;
    string constant ERC721A_MINT_SIGNATURE = "mint(address,uint256)";
    string constant ERC721A_SAFE_TRANSFER_FROM_SIGNATURE = "safeTransferFrom(address,address,uint256)";
    string constant ERC721A_SAFE_BATCH_TRANSFER_FROM_SIGNATURE = "safeBatchTransferFrom(address,address,address,uint256[],bytes)";

    uint256 tokenId = 1;
    uint256 quantity = 2;
    uint256[] tokenIds = [tokenId, 2];

    function testERC721A_Mint_Unit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _setupRuleWithRevertSafeMint(ERC721A_MINT_SIGNATURE, pTypes);
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.mint(address(55), quantity);
    }

    function testERC721A_Mint_Unit_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        ParamTypes[] memory pTypes = new ParamTypes[](2);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        _setupRuleWithRevertSafeMint(ERC721A_MINT_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text); 
        userContract.mint(address(USER_ADDRESS), quantity);
    }

    function testERC721A_SafeTransferFrom_Unit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        userContract.mint(address(USER_ADDRESS), quantity);
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.UINT;
        _setupRuleWithRevertSafeTransferFrom(ERC721A_SAFE_TRANSFER_FROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        vm.expectRevert(abi.encodePacked(revert_text)); 
        userContract.safeTransferFrom(USER_ADDRESS, USER_ADDRESS_2, tokenId);
    }

    function testERC721A_SafeTransferFrom_Unit_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        userContract.mint(address(USER_ADDRESS_2), quantity);
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.UINT;
        _setupRuleWithRevertSafeTransferFrom(ERC721A_SAFE_TRANSFER_FROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS_2);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        userContract.safeTransferFrom(USER_ADDRESS_2, USER_ADDRESS, tokenId);
    }

    function testERC721A_SafeBatchTransferFrom_Unit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        userContract.mint(address(USER_ADDRESS_2), quantity);
        ParamTypes[] memory pTypes = new ParamTypes[](5);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.ADDR;
        pTypes[3] = ParamTypes.UINT;
        pTypes[4] = ParamTypes.BYTES;
        _setupRuleWithRevertSafeTransferFrom(ERC721A_SAFE_BATCH_TRANSFER_FROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS_2);
        vm.expectRevert(abi.encodePacked(revert_text)); 
        userContract.safeBatchTransferFrom(address(0), USER_ADDRESS_2, USER_ADDRESS, tokenIds, "");
    }

    function testERC721A_SafeBatchTransferFrom_Unit_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        userContract.mint(address(USER_ADDRESS), quantity);
        ParamTypes[] memory pTypes = new ParamTypes[](5);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.ADDR;
        pTypes[3] = ParamTypes.UINT;
        pTypes[4] = ParamTypes.BYTES;
        _setupRuleWithRevertSafeTransferFrom(ERC721A_SAFE_BATCH_TRANSFER_FROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        userContract.safeBatchTransferFrom(address(0), USER_ADDRESS, USER_ADDRESS_2, tokenIds, "");
    }

    function testERC721A_Unit_Disabled_Policy() public ifDeploymentTestsEnabled endWithStopPrank {
        userContract.mint(address(USER_ADDRESS_2), quantity);
        ParamTypes[] memory pTypes = new ParamTypes[](5);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.ADDR;
        pTypes[2] = ParamTypes.ADDR;
        pTypes[3] = ParamTypes.UINT;
        pTypes[4] = ParamTypes.BYTES;
        // Expect revert while rule is enabled
        _setupRuleWithRevertSafeTransferFrom(ERC721A_SAFE_BATCH_TRANSFER_FROM_SIGNATURE, pTypes);
        vm.startPrank(USER_ADDRESS_2);
        vm.expectRevert(abi.encodePacked(revert_text)); 
        userContract.safeBatchTransferFrom(address(0), USER_ADDRESS_2, USER_ADDRESS, tokenIds, "");

        // Disable the policy and expect it to go through
        vm.startPrank(policyAdmin);
        RulesEnginePolicyFacet(address(red)).disablePolicy(1);
        assertTrue(RulesEnginePolicyFacet(address(red)).isDisabledPolicy(1));
        vm.startPrank(USER_ADDRESS_2);
        userContract.safeBatchTransferFrom(address(0), USER_ADDRESS_2, USER_ADDRESS, tokenIds, "");
    }
    
    function _setupRuleWithRevertSafeMint(string memory _functionSignature, ParamTypes[] memory pTypes) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables{
        // if the address equals the mint to address, then emit event, else revert
        uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicyOpen();

        _addCallingFunctionToPolicy(
            policyIds[0], 
            bytes4(keccak256(bytes(_functionSignature))), 
            pTypes,
            _functionSignature  
        );

        Rule memory rule =  _createEQRuleSafeMint(USER_ADDRESS);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyIds[0], 0, rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _setupRuleWithRevertSafeTransferFrom(string memory _functionSignature, ParamTypes[] memory pTypes) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables{
        // if the address equals the mint to address, then emit event, else revert
        uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicyOpen();

        _addCallingFunctionToPolicy(
            policyIds[0], 
            bytes4(keccak256(bytes(_functionSignature))), 
            pTypes,
            _functionSignature);

        Rule memory rule =  _createEQRuleSafeTransferFrom(USER_ADDRESS);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyIds[0], 0, rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _setupRuleWithRevertTransferFrom(string memory _functionSignature, ParamTypes[] memory pTypes) public ifDeploymentTestsEnabled endWithStopPrank resetsGlobalVariables{
        // if the address equals the mint to address, then emit event, else revert
        uint256[] memory policyIds = new uint256[](1);
        
        policyIds[0] = _createBlankPolicyOpen();

        _addCallingFunctionToPolicy(
            policyIds[0], 
            bytes4(keccak256(bytes(_functionSignature))),
             pTypes,
             _functionSignature
        );

        Rule memory rule =  _createEQRuleTransferFrom(USER_ADDRESS);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects[0] = effectId_event;
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).updateRule(policyIds[0], 0, rule);

        ruleIds.push(new uint256[](1));
        ruleIds[0][0]= ruleId;
        _addRuleIdsToPolicyOpen(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(userContractAddress, policyIds);
    }

    function _createEQRuleSafeMint(address _address) public returns(Rule memory){
        // Rule: _to == _address -> revert -> safeMint(address _to)"
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        uint256[] memory instructionSet = new uint256[](7);
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LogicalOp.NUM);
        instructionSet[3] = uint256(uint160(_address));
        instructionSet[4] = uint(LogicalOp.EQ);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        rule.instructionSet = rule.instructionSet = instructionSet;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
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
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        uint256[] memory instructionSet = new uint256[](7);
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LogicalOp.NUM);
        instructionSet[3] = uint256(uint160(_address));
        instructionSet[4] = uint(LogicalOp.EQ);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        rule.instructionSet = rule.instructionSet = instructionSet;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
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
        // Instruction set: LogicalOp.PLH, 0, LogicalOp.NUM, _amount, LogicalOp.GT, 0, 1
        uint256[] memory instructionSet = new uint256[](7);
        instructionSet[0] = uint(LogicalOp.PLH);
        instructionSet[1] = 0;
        instructionSet[2] = uint(LogicalOp.NUM);
        instructionSet[3] = uint256(uint160(_address));
        instructionSet[4] = uint(LogicalOp.EQ);
        instructionSet[5] = 0;
        instructionSet[6] = 1;
        rule.instructionSet = rule.instructionSet = instructionSet;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 1;
        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        return rule;
    }
}