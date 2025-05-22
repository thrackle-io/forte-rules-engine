/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "src/example/ExampleUserContract.sol";
import {RulesEngineProcessorLib as ProcessorLib} from "src/engine/facets/RulesEngineProcessorLib.sol";
abstract contract RulesEngineInternalFunctionsUnitTests is RulesEngineCommon {

    ExampleUserContract userContractInternal;
    ExampleUserContractExtraParams userContractInternal2;

        ////////Encoding tests 

    function testRulesEngine_Unit_EncodingForeignCallUint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSig(uint256)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures 
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.UINT;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 0;
        bytes memory vals = abi.encode(1);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getDecodedIntOne(), 1);
    }
    function testRulesEngine_Unit_EncodingForeignCallTwoUint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSig(uint256,uint256)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures 
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](2);
        fc.parameterTypes[0] = PT.UINT;
        fc.parameterTypes[1] = PT.UINT;
        fc.typeSpecificIndices = new uint8[](2);
        fc.typeSpecificIndices[0] = 0;
        fc.typeSpecificIndices[1] = 1;
        bytes memory vals = abi.encode(1, 2);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getDecodedIntOne(), 1);
        assertEq(foreignCall.getDecodedIntTwo(), 2);
    }

    function testRulesEngine_Unit_EncodingForeignCallAddress()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSig(address)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures 
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.ADDR;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 0;
        bytes memory vals = abi.encode(address(0x1234567));
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getDecodedAddr(), address(0x1234567));
    }

    function testRulesEngine_Unit_EncodingForeignCallTwoAddress()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSig(address,address)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures 
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](2);
        fc.parameterTypes[0] = PT.ADDR;
        fc.parameterTypes[1] = PT.ADDR;
        fc.typeSpecificIndices = new uint8[](2);
        fc.typeSpecificIndices[0] = 0;
        fc.typeSpecificIndices[1] = 1;
        bytes memory vals = abi.encode(address(0x1234567), address(0x7654321));
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getDecodedAddr(), address(0x1234567));
        assertEq(foreignCall.getDecodedAddrTwo(), address(0x7654321));
    }   

    function testRulesEngine_Unit_EncodingForeignCallString()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSig(string)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.STR;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 0;
        bytes memory vals = abi.encode("test");
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getDecodedStrOne(), "test");
    }

    function testRulesEngine_Unit_EncodingForeignCallTwoString()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSig(string,string)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures 
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](2);
        fc.parameterTypes[0] = PT.STR;
        fc.parameterTypes[1] = PT.STR;
        fc.typeSpecificIndices = new uint8[](2);
        fc.typeSpecificIndices[0] = 0;
        fc.typeSpecificIndices[1] = 1;
        bytes memory vals = abi.encode("test", "superduper");
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getDecodedStrOne(), "test");
        assertEq(foreignCall.getDecodedStrTwo(), "superduper");
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayUint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithArray(uint256[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures 
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.STATIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 0;
        uint256[] memory array = new uint256[](5);
        array[0] = 1;
        array[1] = 2;
        array[2] = 3;
        array[3] = 4;
        array[4] = 5;
        bytes memory vals = abi.encode(array);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getInternalArrayUint()[0], 1);
        assertEq(foreignCall.getInternalArrayUint()[1], 2);
        assertEq(foreignCall.getInternalArrayUint()[2], 3);
        assertEq(foreignCall.getInternalArrayUint()[3], 4);
        assertEq(foreignCall.getInternalArrayUint()[4], 5);
    }

    function testRulesEngine_Unit_EncodingForeignCallTwoArrayUint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithArray(uint256[],uint256[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures 
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](2);
        fc.parameterTypes[0] = PT.STATIC_TYPE_ARRAY;
        fc.parameterTypes[1] = PT.STATIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](2);
        fc.typeSpecificIndices[0] = 0;
        fc.typeSpecificIndices[1] = 1;
        uint256[] memory array = new uint256[](5);
        array[0] = 1;
        array[1] = 2;
        array[2] = 3;
        array[3] = 4;
        array[4] = 5;
        uint256[] memory arrayTwo = new uint256[](5);
        arrayTwo[0] = 6;
        arrayTwo[1] = 7;
        arrayTwo[2] = 8;
        arrayTwo[3] = 9;
        arrayTwo[4] = 10;
        bytes memory vals = abi.encode(array, arrayTwo);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getInternalArrayUint()[0], 1);
        assertEq(foreignCall.getInternalArrayUint()[1], 2);
        assertEq(foreignCall.getInternalArrayUint()[2], 3);
        assertEq(foreignCall.getInternalArrayUint()[3], 4);
        assertEq(foreignCall.getInternalArrayUint()[4], 5);
        assertEq(foreignCall.getInternalArrayUint()[5], 6);
        assertEq(foreignCall.getInternalArrayUint()[6], 7);
        assertEq(foreignCall.getInternalArrayUint()[7], 8);
        assertEq(foreignCall.getInternalArrayUint()[8], 9);
        assertEq(foreignCall.getInternalArrayUint()[9], 10);
    }

    function testRulesEngine_Unit_EncodingForeignCallTwoArrayString()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithArray(string[],string[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures 
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](2);
        fc.parameterTypes[0] = PT.DYNAMIC_TYPE_ARRAY;
        fc.parameterTypes[1] = PT.DYNAMIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](2);
        fc.typeSpecificIndices[0] = 0;
        fc.typeSpecificIndices[1] = 1;
        string[] memory array = new string[](5);
        array[0] = "test";
        array[1] = "superduper";
        array[2] = "superduperduper";
        array[3] = "superduperduperduper";
        array[4] = "superduperduperduperduperduperduperduperduperduperduperduperlongstring";
        string[] memory arrayTwo = new string[](5);
        arrayTwo[0] = "muper";
        arrayTwo[1] = "muperduper";
        arrayTwo[2] = "muperduperduper";
        arrayTwo[3] = "muperduperduperduper";
        arrayTwo[4] = "muperduperduperduperduperduperduperduperduperduperduperduperlongstring";
        bytes memory vals = abi.encode(array, arrayTwo);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getInternalArrayStr()[0], "test");
        assertEq(foreignCall.getInternalArrayStr()[1], "superduper");
        assertEq(foreignCall.getInternalArrayStr()[2], "superduperduper");
        assertEq(foreignCall.getInternalArrayStr()[3], "superduperduperduper");
        assertEq(foreignCall.getInternalArrayStr()[4], "superduperduperduperduperduperduperduperduperduperduperduperlongstring");
        assertEq(foreignCall.getInternalArrayStr()[5], "muper");
        assertEq(foreignCall.getInternalArrayStr()[6], "muperduper");
        assertEq(foreignCall.getInternalArrayStr()[7], "muperduperduper");
        assertEq(foreignCall.getInternalArrayStr()[8], "muperduperduperduper");
        assertEq(foreignCall.getInternalArrayStr()[9], "muperduperduperduperduperduperduperduperduperduperduperduperlongstring");
    }


    function testRulesEngine_Unit_EncodingForeignCallArrayAddr()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithArray(address[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures 
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.STATIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 0;
        address[] memory array = new address[](5);
        array[0] = address(0x1234567);
        array[1] = address(0x7654321);
        array[2] = address(0x1111111);
        array[3] = address(0x2222222);
        array[4] = address(0x3333333);
        bytes memory vals = abi.encode(array);
        RulesEngineProcessorFacet(address(red))
            .evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getInternalArrayAddr()[0], address(0x1234567));
        assertEq(foreignCall.getInternalArrayAddr()[1], address(0x7654321));
        assertEq(foreignCall.getInternalArrayAddr()[2], address(0x1111111));
        assertEq(foreignCall.getInternalArrayAddr()[3], address(0x2222222));
        assertEq(foreignCall.getInternalArrayAddr()[4], address(0x3333333));
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayStr()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithArray(string[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures 
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.DYNAMIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 0;
        string[] memory array = new string[](5);
        array[0] = "test";
        array[1] = "superduper";
        array[2] = "superduperduper";
        array[3] = "superduperduperduper";
        array[4] = "superduperduperduperduperduperduperduperduperlongstring";
        bytes memory vals = abi.encode(array);
        RulesEngineProcessorFacet(address(red))
            .evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getInternalArrayStr()[0], "test");
        assertEq(foreignCall.getInternalArrayStr()[1], "superduper");
        assertEq(foreignCall.getInternalArrayStr()[2], "superduperduper");
        assertEq(foreignCall.getInternalArrayStr()[3], "superduperduperduper");
        assertEq(foreignCall.getInternalArrayStr()[4], "superduperduperduperduperduperduperduperduperlongstring");
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayBytes()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithArray(bytes[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures 
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.DYNAMIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 0;
        bytes[] memory array = new bytes[](5);
        array[0] = abi.encodeWithSelector(bytes4(keccak256(bytes("test(uint256)"))), 1);
        array[1] = abi.encodeWithSelector(bytes4(keccak256(bytes("superduper(uint256)"))), 2);
        array[2] = abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduper(uint256)"))), 3);
        array[3] = abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduperduper(uint256)"))), 4);
        array[4] = abi.encodeWithSelector(bytes4(keccak256(bytes("test(uint256,string,address)"))), 5, "superduperduperduperduperduperduperduperduperduperduperduperlongstring", address(0x1234567));
        bytes memory vals = abi.encode(array);
        RulesEngineProcessorFacet(address(red))
            .evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getInternalArrayBytes()[0], abi.encodeWithSelector(bytes4(keccak256(bytes("test(uint256)"))), 1));
        assertEq(foreignCall.getInternalArrayBytes()[1], abi.encodeWithSelector(bytes4(keccak256(bytes("superduper(uint256)"))), 2));
        assertEq(foreignCall.getInternalArrayBytes()[2], abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduper(uint256)"))), 3));
        assertEq(foreignCall.getInternalArrayBytes()[3], abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduperduper(uint256)"))), 4));
        assertEq(foreignCall.getInternalArrayBytes()[4], abi.encodeWithSelector(bytes4(keccak256(bytes("test(uint256,string,address)"))), 5, "superduperduperduperduperduperduperduperduperduperduperduperlongstring", address(0x1234567)));
    }

    function testRulesEngine_Unit_EncodingForeignCallBytes()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithBytes(bytes)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures 
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](1);
        fc.parameterTypes[0] = PT.BYTES;
        fc.typeSpecificIndices = new uint8[](1);
        fc.typeSpecificIndices[0] = 0;
        
        bytes memory vals = abi.encode(bytes("test"));
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getDecodedBytes(), bytes("test"));
    
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayMixedTypes_Complex()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithMultiArrays(uint256[],address[],string[],bytes[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures 
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](4);
        fc.parameterTypes[0] = PT.STATIC_TYPE_ARRAY;
        fc.parameterTypes[1] = PT.STATIC_TYPE_ARRAY;
        fc.parameterTypes[2] = PT.DYNAMIC_TYPE_ARRAY;
        fc.parameterTypes[3] = PT.DYNAMIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](4);
        fc.typeSpecificIndices[0] = 0;
        fc.typeSpecificIndices[1] = 1;
        fc.typeSpecificIndices[2] = 2;
        fc.typeSpecificIndices[3] = 3;
        uint256[] memory array1 = new uint256[](5);
        array1[0] = 1;
        array1[1] = 2;
        array1[2] = 3;
        array1[3] = 4;
        array1[4] = 5;

        address[] memory array2 = new address[](5);
        array2[0] = address(0x1234567);
        array2[1] = address(0x7654321);
        array2[2] = address(0x1111111);
        array2[3] = address(0x2222222);
        array2[4] = address(0x3333333);

        string[] memory array3 = new string[](5);
        array3[0] = "test";
        array3[1] = "superduper";
        array3[2] = "superduperduper";
        array3[3] = "superduperduperduper";
        array3[4] = "superduperduperduperduperduperduperduperduperduperduperduperlongstring";
        bytes[] memory array4 = new bytes[](5); 
        array4[0] = abi.encodeWithSelector(bytes4(keccak256(bytes("test(uint256)"))), 1);
        array4[1] = abi.encodeWithSelector(bytes4(keccak256(bytes("superduper(uint256)"))), 2);
        array4[2] = abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduper(uint256)"))), 3);
        array4[3] = abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduperduper(uint256)"))), 4);
        array4[4] = abi.encodeWithSelector(bytes4(keccak256(bytes("test(uint256,string,address)"))), 5, "superduperduperduperduperduperduperduperduperduperduperduperduperlongstring", address(0x1234567));
        bytes memory vals = abi.encode(array1, array2, array3, array4);

        RulesEngineProcessorFacet(address(red))
            .evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getInternalArrayUint()[0], 1);
        assertEq(foreignCall.getInternalArrayUint()[1], 2);
        assertEq(foreignCall.getInternalArrayUint()[2], 3);
        assertEq(foreignCall.getInternalArrayUint()[3], 4);
        assertEq(foreignCall.getInternalArrayUint()[4], 5);
        assertEq(foreignCall.getInternalArrayAddr()[0], address(0x1234567));
        assertEq(foreignCall.getInternalArrayAddr()[1], address(0x7654321));
        assertEq(foreignCall.getInternalArrayAddr()[2], address(0x1111111));
        assertEq(foreignCall.getInternalArrayAddr()[3], address(0x2222222));
        assertEq(foreignCall.getInternalArrayAddr()[4], address(0x3333333));
        assertEq(foreignCall.getInternalArrayStr()[0], "test");
        assertEq(foreignCall.getInternalArrayStr()[1], "superduper");
        assertEq(foreignCall.getInternalArrayStr()[2], "superduperduper");
        assertEq(foreignCall.getInternalArrayStr()[3], "superduperduperduper");
        assertEq(foreignCall.getInternalArrayStr()[4], "superduperduperduperduperduperduperduperduperduperduperduperlongstring");
        assertEq(foreignCall.getInternalArrayBytes()[0], abi.encodeWithSelector(bytes4(keccak256(bytes("test(uint256)"))), 1));
        assertEq(foreignCall.getInternalArrayBytes()[1], abi.encodeWithSelector(bytes4(keccak256(bytes("superduper(uint256)"))), 2));
        assertEq(foreignCall.getInternalArrayBytes()[2], abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduper(uint256)"))), 3));
        assertEq(foreignCall.getInternalArrayBytes()[3], abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduperduper(uint256)"))), 4));
        assertEq(foreignCall.getInternalArrayBytes()[4], abi.encodeWithSelector(bytes4(keccak256(bytes("test(uint256,string,address)"))), 5, "superduperduperduperduperduperduperduperduperduperduperduperduperlongstring", address(0x1234567)));
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayMixedTypes_Simple()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithMultiArrays(string[],uint256[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures 
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](2);
        fc.parameterTypes[0] = PT.DYNAMIC_TYPE_ARRAY;
        fc.parameterTypes[1] = PT.STATIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](2);
        fc.typeSpecificIndices[0] = 0;
        fc.typeSpecificIndices[1] = 1;
        string[] memory array3 = new string[](5);
        array3[0] = "test";
        array3[1] = "superduper";
        array3[2] = "superduperduper";
        array3[3] = "superduperduperduper";
        array3[4] = "superduperduperduperduperduperduperduperduperduperduperduperlongstring";
        uint256[] memory array1 = new uint256[](5);
        array1[0] = 1;
        array1[1] = 2;
        array1[2] = 3;
        array1[3] = 4;
        array1[4] = 5;
        bytes memory vals = abi.encode(array3, array1);
        RulesEngineProcessorFacet(address(red))
            .evaluateForeignCallForRule(fc, vals);
        assertEq(foreignCall.getInternalArrayStr()[0], "test");
        assertEq(foreignCall.getInternalArrayStr()[1], "superduper");
        assertEq(foreignCall.getInternalArrayStr()[2], "superduperduper");
        assertEq(foreignCall.getInternalArrayStr()[3], "superduperduperduper");
        assertEq(foreignCall.getInternalArrayStr()[4], "superduperduperduperduperduperduperduperduperduperduperduperlongstring");
        assertEq(foreignCall.getInternalArrayUint()[0], 1);
        assertEq(foreignCall.getInternalArrayUint()[1], 2);
        assertEq(foreignCall.getInternalArrayUint()[2], 3);
        assertEq(foreignCall.getInternalArrayUint()[3], 4);
        assertEq(foreignCall.getInternalArrayUint()[4], 5);
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayMixedTypes_ReverseOrderSimple()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSigWithMultiArrays(uint256[],string[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures 
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](2);
        fc.parameterTypes[0] = PT.STATIC_TYPE_ARRAY;
        fc.parameterTypes[1] = PT.DYNAMIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](2);
        fc.typeSpecificIndices[0] = 0;
        fc.typeSpecificIndices[1] = 1;
        uint256[] memory array1 = new uint256[](5);
        array1[0] = 1;
        array1[1] = 2;
        array1[2] = 3;
        array1[3] = 4;
        array1[4] = 5;
        string[] memory array3 = new string[](5);
        array3[0] = "test";
        array3[1] = "superduper";
        array3[2] = "superduperduper";
        array3[3] = "superduperduperduper";
        array3[4] = "superduperduperduperduperduperduperduperduperduperduperduperlongstring";

        bytes memory vals = abi.encode(array1, array3);

        RulesEngineProcessorFacet(address(red))
            .evaluateForeignCallForRule(fc, vals);
        
        assertEq(foreignCall.getInternalArrayUint()[0], 1);
        assertEq(foreignCall.getInternalArrayUint()[1], 2);
        assertEq(foreignCall.getInternalArrayUint()[2], 3);
        assertEq(foreignCall.getInternalArrayUint()[3], 4);
        assertEq(foreignCall.getInternalArrayUint()[4], 5);
        assertEq(foreignCall.getInternalArrayStr()[0], "test");
        assertEq(foreignCall.getInternalArrayStr()[1], "superduper");
        assertEq(foreignCall.getInternalArrayStr()[2], "superduperduper");
        assertEq(foreignCall.getInternalArrayStr()[3], "superduperduperduper");
        assertEq(foreignCall.getInternalArrayStr()[4], "superduperduperduperduperduperduperduperduperduperduperduperlongstring");
    }

    function testRulesEngine_Unit_EncodingForeignCallMixedTypes()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        string memory functionSig = "testSig(uint256,string,uint256,string,address)";
        //string memory functionSig = "testSig(string)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](5);
        fc.parameterTypes[0] = PT.UINT;
        fc.parameterTypes[1] = PT.STR;
        fc.parameterTypes[2] = PT.UINT;
        fc.parameterTypes[3] = PT.STR;
        fc.parameterTypes[4] = PT.ADDR;

        fc.typeSpecificIndices = new uint8[](5);
        fc.typeSpecificIndices[0] = 0;
        fc.typeSpecificIndices[1] = 1;
        fc.typeSpecificIndices[2] = 2;
        fc.typeSpecificIndices[3] = 3;
        fc.typeSpecificIndices[4] = 4;

        bytes memory vals = abi.encode(
            1, 
            "test", 
            2, 
            "superduperduperduperduperduperduperduperduperduperduperduperlongstring", 
            address(0x1234567)
        );

        ForeignCallReturnValue memory retVal = RulesEngineProcessorFacet(address(red))
            .evaluateForeignCallForRule(
                fc,
                vals
            );

        assertEq(foreignCall.getDecodedIntOne(), 1);
        assertEq(foreignCall.getDecodedIntTwo(), 2);
        assertEq(foreignCall.getDecodedStrOne(), "test");
        assertEq(
            foreignCall.getDecodedStrTwo(),
            "superduperduperduperduperduperduperduperduperduperduperduperlongstring"
        );
        assertEq(foreignCall.getDecodedAddr(), address(0x1234567));
        retVal;
    }

    function testRulesEngine_Unit_EvaluateForeignCallForRule_WithStringAndDynamicAndStaticArray()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        //ForeignCall Builder not used here to test the data structures 
        ForeignCall memory fc;
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        string memory functionSig = "testSigWithMultiArrays(string,uint256[],string[])";
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new PT[](3);
        fc.parameterTypes[0] = PT.STR;
        fc.parameterTypes[1] = PT.STATIC_TYPE_ARRAY;
        fc.parameterTypes[2] = PT.DYNAMIC_TYPE_ARRAY;
        fc.typeSpecificIndices = new uint8[](3);
        fc.typeSpecificIndices[0] = 2;
        fc.typeSpecificIndices[1] = 1;
        fc.typeSpecificIndices[2] = 0;

        string memory str = "superduperduperduperduperduperduperduperduperduperduperduperlongstring";
        uint256[] memory uintArray = new uint256[](5);
        uintArray[0] = 1;
        uintArray[1] = 2;
        uintArray[2] = 3;
        uintArray[3] = 4;
        uintArray[4] = 5;
        string[] memory strArray = new string[](5);
        strArray[0] = "test";
        strArray[1] = "superduper";
        strArray[2] = "superduperduper";
        strArray[3] = "superduperduperduper";
        strArray[4] = "superduperduperduperduperduperduperduperduperduperduperduperlongstring";
        bytes memory vals = abi.encode(strArray, uintArray, str);
        ForeignCallReturnValue memory retVal = RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals);
        retVal;
    }

    function testRulesEngine_Unit_EvaluateForeignCallForRule()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        ForeignCall memory fc;
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        string
            memory functionSig = "testSig(uint256,string,uint256,string,address)";

        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.foreignCallIndex = 0;
        fc.returnType = PT.BOOL;

        fc.parameterTypes = new PT[](5);
        fc.parameterTypes[0] = PT.UINT;
        fc.parameterTypes[1] = PT.STR;
        fc.parameterTypes[2] = PT.UINT;
        fc.parameterTypes[3] = PT.STR;
        fc.parameterTypes[4] = PT.ADDR;

        fc.typeSpecificIndices = new uint8[](5);
        fc.typeSpecificIndices[0] = 1;
        fc.typeSpecificIndices[1] = 0;
        fc.typeSpecificIndices[2] = 2;
        fc.typeSpecificIndices[3] = 3;
        fc.typeSpecificIndices[4] = 5;

        // rule signature function arguments (RS): string, uint256, uint256, string, uint256, string, address
        // foreign call function arguments (FC): uint256, string, uint256, string, address
        //
        // Mapping:
        // FC index: 0 1 2 3 4
        // RS index: 1 0 2 3 5

        // Build the rule signature function arguments structure

        bytes memory arguments = abi.encode("one", 2, 3, "four", 5, address(0x12345678));

        // Build the mapping between calling function arguments and foreign call arguments

        ForeignCallReturnValue memory retVal = RulesEngineProcessorFacet(
            address(red)
        ).evaluateForeignCallForRule(
                fc,
                arguments
            );
        console2.logBytes(retVal.value);
    }


    /// Test utility functions within ExampleUserContract.sol and RulesEngineRunRulesEngineProcessorFacet(address(red)).sol
    function testRulesEngine_Utils_UserContract_setRulesEngineAddress()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        userContractInternal.setRulesEngineAddress(address(red));
        assertTrue(userContractInternal.rulesEngineAddress() == address(red));
    }

    function testRulesEngine_Utils_uintToBool()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        bool success = ProcessorLib._ui2bool(1);
        assertTrue(success);
    }

    function testRulesEngine_Utils_BoolToUint()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        uint256 success = ProcessorLib._bool2ui(false);
        assertTrue(success == 0);
    }

    function testRulesEngine_Utils_UintToAddr()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        assertEq(ProcessorLib._ui2addr(uint256(uint160(address(0xD00d)))),address(0xD00d));
    }

    function testRulesEngine_Utils_UintToBytes()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        bytes memory b = "BYTES STRING OF SUFFICIENT LNGTH";
        assertEq(ProcessorLib._ui2bytes(uint256(abi.decode(b, (uint256)))),b);
    }
}
