/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract effects is RulesEngineCommon {

/**
 *
 *
 * Execution tests for foreign calls within the rules engine 
 *
 *
 */


    /// Ensure that rule with a negative effect revert applied, that passes, will revert
    function testRulesEngine_Unit_CheckRules_WithExampleContract_Negative_Revert()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        _setupRuleWithRevert(address(userContract));
        vm.startSnapshotGas("CheckRules_Revert");
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.transfer(address(0x7654321), 5);
        uint256 gasUsed = vm.stopSnapshotGas();
    }

    /// Ensure that rule with a positive effect event applied, that passes, will emit the event
    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        _setupRuleWithPosEvent();
        vm.startSnapshotGas("CheckRules_Event");
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        userContract.transfer(address(0x7654321), 5);
        uint256 gasUsed = vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event_CustomParams_Uint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        bytes memory eventParam = abi.encode(uint256(100)); 
        _setupRuleWithPosEventParams(eventParam, ParamTypes.UINT);
        vm.startSnapshotGas("CheckRules_Event_CustomParams_Uint");
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, 100);
        userContract.transfer(address(0x7654321), 5);
        uint256 gasUsed = vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event_CustomParams_String()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        bytes memory eventParam = abi.encode(string("Test")); 
        _setupRuleWithPosEventParams(eventParam, ParamTypes.STR);
        vm.startSnapshotGas("CheckRules_Event_CustomParams_String");
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, string("test"));
        userContract.transfer(address(0x7654321), 5);
        uint256 gasUsed = vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event_CustomParams_Address()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        bytes memory eventParam = abi.encode(address(0x100)); 
        _setupRuleWithPosEventParams(eventParam, ParamTypes.ADDR);
        vm.startSnapshotGas("CheckRules_Event_CustomParams_Address");
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, address(0x100));
        userContract.transfer(address(0x7654321), 5);
        uint256 gasUsed = vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event_CustomParams_Bool()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        bytes memory eventParam = abi.encode(bool(true)); 
        _setupRuleWithPosEventParams(eventParam, ParamTypes.BOOL);
        vm.startSnapshotGas("CheckRules_Event_CustomParams_Bool");
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, true);
        userContract.transfer(address(0x7654321), 5);
        uint256 gasUsed = vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event_CustomParams_Bytes32()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        bytes memory eventParam = abi.encode(bytes32("Bytes32 Test")); 
        _setupRuleWithPosEventParams(eventParam, ParamTypes.BYTES);
        vm.startSnapshotGas("CheckRules_Event_CustomParams_Bytes32");
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, bytes32("Bytes32 Test"));
        userContract.transfer(address(0x7654321), 5);
        uint256 gasUsed = vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event_DynamicParams_Uint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        _setupRuleWithPosEventDynamicParamsFromCallingFunctionParams(ParamTypes.UINT);
        vm.startSnapshotGas("CheckRules_Event_DynamicParams_Uint");
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, 100);
        userContract.transfer(address(0x7654321), 100);
        uint256 gasUsed = vm.stopSnapshotGas();
    }


    function testRulesEngine_Unit_CheckRules_WithExampleContract_Positive_Event_DynamicParams_Address()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        _setupRuleWithPosEventDynamicParamsFromCallingFunctionParams(ParamTypes.ADDR);
        vm.startSnapshotGas("CheckRules_Event_DynamicParams_Address");
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, address(0x7654321));
        userContract.transfer(address(0x7654321), 100);
        uint256 gasUsed = vm.stopSnapshotGas();
    }

    // Ensure that a policy with multiple rules with positive events fire in the correct order
    function testRulesEngine_Unit_CheckPolicy_ExecuteRuleOrder()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        _setupPolicyWithMultipleRulesWithPosEvents();
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT2, event_text2);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT2, event_text2);
        userContract.transfer(address(0x7654321), 11);
    }

    /// Ensure that rule with a positive effect event applied, that passes, will emit the event
    function testRulesEngine_Unit_CheckRules_WithExampleContract_Multiple_Positive_Event()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        _setupRuleWith2PosEvent();
        vm.startSnapshotGas("CheckRules_Multiple_Positive_Event");
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT, event_text);
        vm.expectEmit(true, true, false, false);
        emit RulesEngineEvent(1, EVENTTEXT2, event_text2);
        userContract.transfer(address(0x7654321), 11);
        uint256 gasUsed = vm.stopSnapshotGas();
    }

}
