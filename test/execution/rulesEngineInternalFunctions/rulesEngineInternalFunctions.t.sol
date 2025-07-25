/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "test/clientContractExamples/ExampleUserContract.sol";
import {RulesEngineProcessorLib as ProcessorLib} from "src/engine/facets/RulesEngineProcessorLib.sol";
abstract contract rulesEngineInternalFunctions is RulesEngineCommon {
    ExampleUserContract userContractInternal;
    ExampleUserContractExtraParams userContractInternal2;

    ////////Encoding tests

    function testRulesEngine_Unit_EncodingForeignCallUint() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSig(uint256)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.UINT;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        bytes memory vals = abi.encode(1);
        bytes[] memory retVals = new bytes[](0);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getDecodedIntOne(), 1);
    }

    function testRulesEngine_Unit_EncodingForeignCallUintWithRetVals() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSig(uint256)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.UINT;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 1;
        typeSpecificIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        bytes memory vals = abi.encode(1);
        bytes[] memory retVals = new bytes[](1);
        retVals[0] = abi.encode(4);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getDecodedIntOne(), 4);
    }

    function testRulesEngine_Unit_EncodingForeignCallTwoUint() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSig(uint256,uint256)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](2);
        fc.parameterTypes[0] = ParamTypes.UINT;
        fc.parameterTypes[1] = ParamTypes.UINT;
        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[1].index = 1;
        fc.encodedIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](2);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[1].index = 1;
        typeSpecificIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
        bytes memory vals = abi.encode(1, 2);
        bytes[] memory retVals = new bytes[](0);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getDecodedIntOne(), 1);
        assertEq(foreignCall.getDecodedIntTwo(), 2);
    }

    function testRulesEngine_Unit_EncodingForeignCallTwoUintWithRetVals() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSig(uint256,uint256)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](2);
        fc.parameterTypes[0] = ParamTypes.UINT;
        fc.parameterTypes[1] = ParamTypes.UINT;
        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        fc.encodedIndices[1].index = 2;
        fc.encodedIndices[1].eType = EncodedIndexType.FOREIGN_CALL;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](2);
        typeSpecificIndices[0].index = 1;
        typeSpecificIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        typeSpecificIndices[1].index = 2;
        typeSpecificIndices[1].eType = EncodedIndexType.FOREIGN_CALL;
        bytes memory vals = abi.encode(1, 2);
        bytes[] memory retVals = new bytes[](2);
        retVals[0] = abi.encode(4);
        retVals[1] = abi.encode(3);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getDecodedIntOne(), 4);
        assertEq(foreignCall.getDecodedIntTwo(), 3);
    }

    function testRulesEngine_Unit_EncodingForeignCallAddress() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSig(address)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.ADDR;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        bytes memory vals = abi.encode(address(0x1234567));
        bytes[] memory retVals = new bytes[](0);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getDecodedAddr(), address(0x1234567));
    }

    function testRulesEngine_Unit_EncodingForeignCallAddressWithRetVals() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSig(address)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.ADDR;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 1;
        typeSpecificIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        bytes memory vals = abi.encode(address(0x1234567));
        bytes[] memory retVals = new bytes[](1);
        retVals[0] = abi.encode(0x567890);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getDecodedAddr(), address(0x567890));
    }

    function testRulesEngine_Unit_EncodingForeignCallTwoAddress() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSig(address,address)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](2);
        fc.parameterTypes[0] = ParamTypes.ADDR;
        fc.parameterTypes[1] = ParamTypes.ADDR;
        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[1].index = 1;
        fc.encodedIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](2);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[1].index = 1;
        typeSpecificIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
        bytes memory vals = abi.encode(address(0x1234567), address(0x7654321));
        bytes[] memory retVals = new bytes[](0);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getDecodedAddr(), address(0x1234567));
        assertEq(foreignCall.getDecodedAddrTwo(), address(0x7654321));
    }

    function testRulesEngine_Unit_EncodingForeignCallTwoAddrWithRetVals() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSig(address,address)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](2);
        fc.parameterTypes[0] = ParamTypes.ADDR;
        fc.parameterTypes[1] = ParamTypes.ADDR;
        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        fc.encodedIndices[1].index = 2;
        fc.encodedIndices[1].eType = EncodedIndexType.FOREIGN_CALL;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](2);
        typeSpecificIndices[0].index = 1;
        typeSpecificIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        typeSpecificIndices[1].index = 2;
        typeSpecificIndices[1].eType = EncodedIndexType.FOREIGN_CALL;
        bytes memory vals = abi.encode(address(0x1234567), address(0x7654321));
        bytes[] memory retVals = new bytes[](2);
        retVals[0] = abi.encode(0x567890);
        retVals[1] = abi.encode(0x111111);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getDecodedAddr(), address(0x567890));
        assertEq(foreignCall.getDecodedAddrTwo(), address(0x111111));
    }

    function testRulesEngine_Unit_EncodingForeignCallString() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSig(string)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.STR;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        bytes memory vals = abi.encode("test");
        bytes[] memory retVals = new bytes[](0);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getDecodedStrOne(), "test");
    }

    function testRulesEngine_Unit_EncodingForeignCallStringWithRetVals() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSig(string)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.STR;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 1;
        typeSpecificIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        bytes memory vals = abi.encode("test");
        bytes[] memory retVals = new bytes[](1);
        retVals[0] = abi.encode("tset");
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getDecodedStrOne(), "tset");
    }

    function testRulesEngine_Unit_EncodingForeignCallTwoString() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSig(string,string)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](2);
        fc.parameterTypes[0] = ParamTypes.STR;
        fc.parameterTypes[1] = ParamTypes.STR;
        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[1].index = 1;
        fc.encodedIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](2);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[1].index = 1;
        typeSpecificIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
        bytes memory vals = abi.encode("test", "superduper");
        bytes[] memory retVals = new bytes[](0);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getDecodedStrOne(), "test");
        assertEq(foreignCall.getDecodedStrTwo(), "superduper");
    }

    function testRulesEngine_Unit_EncodingForeignCallTwoStringWithRetVals() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSig(string,string)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](2);
        fc.parameterTypes[0] = ParamTypes.STR;
        fc.parameterTypes[1] = ParamTypes.STR;
        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        fc.encodedIndices[1].index = 2;
        fc.encodedIndices[1].eType = EncodedIndexType.FOREIGN_CALL;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](2);
        typeSpecificIndices[0].index = 1;
        typeSpecificIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        typeSpecificIndices[1].index = 2;
        typeSpecificIndices[1].eType = EncodedIndexType.FOREIGN_CALL;
        bytes memory vals = abi.encode("test", "superduper");
        bytes[] memory retVals = new bytes[](2);
        retVals[0] = abi.encode("tset");
        retVals[1] = abi.encode("rupersuper");
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getDecodedStrOne(), "tset");
        assertEq(foreignCall.getDecodedStrTwo(), "rupersuper");
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayUint() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSigWithArray(uint256[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.STATIC_TYPE_ARRAY;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        uint256[] memory array = new uint256[](5);
        array[0] = 1;
        array[1] = 2;
        array[2] = 3;
        array[3] = 4;
        array[4] = 5;
        bytes memory vals = abi.encode(array);
        bytes[] memory retVals = new bytes[](0);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getInternalArrayUint()[0], 1);
        assertEq(foreignCall.getInternalArrayUint()[1], 2);
        assertEq(foreignCall.getInternalArrayUint()[2], 3);
        assertEq(foreignCall.getInternalArrayUint()[3], 4);
        assertEq(foreignCall.getInternalArrayUint()[4], 5);
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayUintWithRetVals() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSigWithArray(uint256[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.STATIC_TYPE_ARRAY;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 1;
        typeSpecificIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        uint256[] memory array = new uint256[](5);
        array[0] = 1;
        array[1] = 2;
        array[2] = 3;
        array[3] = 4;
        array[4] = 5;
        bytes memory vals = abi.encode(array);
        bytes[] memory retVals = new bytes[](1);
        uint256[] memory retArray = new uint256[](5);
        retArray[0] = 11;
        retArray[1] = 12;
        retArray[2] = 13;
        retArray[3] = 14;
        retArray[4] = 15;
        retVals[0] = abi.encode(retArray);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getInternalArrayUint()[0], 11);
        assertEq(foreignCall.getInternalArrayUint()[1], 12);
        assertEq(foreignCall.getInternalArrayUint()[2], 13);
        assertEq(foreignCall.getInternalArrayUint()[3], 14);
        assertEq(foreignCall.getInternalArrayUint()[4], 15);
    }

    function testRulesEngine_Unit_EncodingForeignCallTwoArrayUintWithRetVals() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSigWithArray(uint256[],uint256[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](2);
        fc.parameterTypes[0] = ParamTypes.STATIC_TYPE_ARRAY;
        fc.parameterTypes[1] = ParamTypes.STATIC_TYPE_ARRAY;
        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        fc.encodedIndices[1].index = 2;
        fc.encodedIndices[1].eType = EncodedIndexType.FOREIGN_CALL;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](2);
        typeSpecificIndices[0].index = 1;
        typeSpecificIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        typeSpecificIndices[1].index = 2;
        typeSpecificIndices[1].eType = EncodedIndexType.FOREIGN_CALL;
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
        bytes[] memory retVals = new bytes[](2);
        uint256[] memory retArray = new uint256[](5);
        retArray[0] = 11;
        retArray[1] = 12;
        retArray[2] = 13;
        retArray[3] = 14;
        retArray[4] = 15;
        uint256[] memory retArrayTwo = new uint256[](5);
        retArrayTwo[0] = 16;
        retArrayTwo[1] = 17;
        retArrayTwo[2] = 18;
        retArrayTwo[3] = 19;
        retArrayTwo[4] = 20;
        retVals[0] = abi.encode(retArray);
        retVals[1] = abi.encode(retArrayTwo);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getInternalArrayUint()[0], 11);
        assertEq(foreignCall.getInternalArrayUint()[1], 12);
        assertEq(foreignCall.getInternalArrayUint()[2], 13);
        assertEq(foreignCall.getInternalArrayUint()[3], 14);
        assertEq(foreignCall.getInternalArrayUint()[4], 15);
        assertEq(foreignCall.getInternalArrayUint()[5], 16);
        assertEq(foreignCall.getInternalArrayUint()[6], 17);
        assertEq(foreignCall.getInternalArrayUint()[7], 18);
        assertEq(foreignCall.getInternalArrayUint()[8], 19);
        assertEq(foreignCall.getInternalArrayUint()[9], 20);
    }

    function testRulesEngine_Unit_EncodingForeignCallTwoArrayUint() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSigWithArray(uint256[],uint256[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](2);
        fc.parameterTypes[0] = ParamTypes.STATIC_TYPE_ARRAY;
        fc.parameterTypes[1] = ParamTypes.STATIC_TYPE_ARRAY;
        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[1].index = 1;
        fc.encodedIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](2);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[1].index = 1;
        typeSpecificIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
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
        bytes[] memory retVals = new bytes[](0);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
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

    function testRulesEngine_Unit_EncodingForeignCallTwoArrayString() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSigWithArray(string[],string[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](2);
        fc.parameterTypes[0] = ParamTypes.DYNAMIC_TYPE_ARRAY;
        fc.parameterTypes[1] = ParamTypes.DYNAMIC_TYPE_ARRAY;
        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[1].index = 1;
        fc.encodedIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](2);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[1].index = 1;
        typeSpecificIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
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
        bytes[] memory retVals = new bytes[](0);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
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

    function testRulesEngine_Unit_EncodingForeignCallTwoArrayStringWithRetVals() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSigWithArray(string[],string[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](2);
        fc.parameterTypes[0] = ParamTypes.DYNAMIC_TYPE_ARRAY;
        fc.parameterTypes[1] = ParamTypes.DYNAMIC_TYPE_ARRAY;
        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        fc.encodedIndices[1].index = 2;
        fc.encodedIndices[1].eType = EncodedIndexType.FOREIGN_CALL;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](2);
        typeSpecificIndices[0].index = 1;
        typeSpecificIndices[0].eType = EncodedIndexType.FOREIGN_CALL;
        typeSpecificIndices[1].index = 2;
        typeSpecificIndices[1].eType = EncodedIndexType.FOREIGN_CALL;
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
        bytes[] memory retVals = new bytes[](2);
        string[] memory retArray = new string[](5);
        retArray[0] = "crank";
        retArray[1] = "crankitydankity";
        retArray[2] = "crankitydankitydankity";
        retArray[3] = "crankitydankitydankitydankity";
        retArray[4] = "crankitydankitydankitydankitydankity";
        retVals[0] = abi.encode(retArray);
        string[] memory retArrayTwo = new string[](5);
        retArrayTwo[0] = "dankity";
        retArrayTwo[1] = "dankitycrankity";
        retArrayTwo[2] = "dankitycrankitydankity";
        retArrayTwo[3] = "dankitycrankitydankitydankity";
        retArrayTwo[4] = "dankitycrankitydankitydankitydankity";
        retVals[1] = abi.encode(retArrayTwo);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getInternalArrayStr()[0], "crank");
        assertEq(foreignCall.getInternalArrayStr()[1], "crankitydankity");
        assertEq(foreignCall.getInternalArrayStr()[2], "crankitydankitydankity");
        assertEq(foreignCall.getInternalArrayStr()[3], "crankitydankitydankitydankity");
        assertEq(foreignCall.getInternalArrayStr()[4], "crankitydankitydankitydankitydankity");
        assertEq(foreignCall.getInternalArrayStr()[5], "dankity");
        assertEq(foreignCall.getInternalArrayStr()[6], "dankitycrankity");
        assertEq(foreignCall.getInternalArrayStr()[7], "dankitycrankitydankity");
        assertEq(foreignCall.getInternalArrayStr()[8], "dankitycrankitydankitydankity");
        assertEq(foreignCall.getInternalArrayStr()[9], "dankitycrankitydankitydankitydankity");
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayAddr() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSigWithArray(address[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.STATIC_TYPE_ARRAY;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        address[] memory array = new address[](5);
        array[0] = address(0x1234567);
        array[1] = address(0x7654321);
        array[2] = address(0x1111111);
        array[3] = address(0x2222222);
        array[4] = address(0x3333333);
        bytes memory vals = abi.encode(array);
        bytes[] memory retVals = new bytes[](0);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getInternalArrayAddr()[0], address(0x1234567));
        assertEq(foreignCall.getInternalArrayAddr()[1], address(0x7654321));
        assertEq(foreignCall.getInternalArrayAddr()[2], address(0x1111111));
        assertEq(foreignCall.getInternalArrayAddr()[3], address(0x2222222));
        assertEq(foreignCall.getInternalArrayAddr()[4], address(0x3333333));
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayStr() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSigWithArray(string[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.DYNAMIC_TYPE_ARRAY;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        string[] memory array = new string[](5);
        array[0] = "test";
        array[1] = "superduper";
        array[2] = "superduperduper";
        array[3] = "superduperduperduper";
        array[4] = "superduperduperduperduperduperduperduperduperlongstring";
        bytes memory vals = abi.encode(array);
        bytes[] memory retVals = new bytes[](0);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getInternalArrayStr()[0], "test");
        assertEq(foreignCall.getInternalArrayStr()[1], "superduper");
        assertEq(foreignCall.getInternalArrayStr()[2], "superduperduper");
        assertEq(foreignCall.getInternalArrayStr()[3], "superduperduperduper");
        assertEq(foreignCall.getInternalArrayStr()[4], "superduperduperduperduperduperduperduperduperlongstring");
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayBytes() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSigWithArray(bytes[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.DYNAMIC_TYPE_ARRAY;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        bytes[] memory array = new bytes[](5);
        array[0] = abi.encodeWithSelector(bytes4(keccak256(bytes("test(uint256)"))), 1);
        array[1] = abi.encodeWithSelector(bytes4(keccak256(bytes("superduper(uint256)"))), 2);
        array[2] = abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduper(uint256)"))), 3);
        array[3] = abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduperduper(uint256)"))), 4);
        array[4] = abi.encodeWithSelector(
            bytes4(keccak256(bytes("test(uint256,string,address)"))),
            5,
            "superduperduperduperduperduperduperduperduperduperduperduperlongstring",
            address(0x1234567)
        );
        bytes memory vals = abi.encode(array);
        bytes[] memory retVals = new bytes[](0);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getInternalArrayBytes()[0], abi.encodeWithSelector(bytes4(keccak256(bytes("test(uint256)"))), 1));
        assertEq(foreignCall.getInternalArrayBytes()[1], abi.encodeWithSelector(bytes4(keccak256(bytes("superduper(uint256)"))), 2));
        assertEq(foreignCall.getInternalArrayBytes()[2], abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduper(uint256)"))), 3));
        assertEq(
            foreignCall.getInternalArrayBytes()[3],
            abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduperduper(uint256)"))), 4)
        );
        assertEq(
            foreignCall.getInternalArrayBytes()[4],
            abi.encodeWithSelector(
                bytes4(keccak256(bytes("test(uint256,string,address)"))),
                5,
                "superduperduperduperduperduperduperduperduperduperduperduperlongstring",
                address(0x1234567)
            )
        );
    }

    function testRulesEngine_Unit_EncodingForeignCallBytes() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSigWithBytes(bytes)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](1);
        fc.parameterTypes[0] = ParamTypes.BYTES;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](1);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;

        bytes memory vals = abi.encode(bytes("test"));
        bytes[] memory retVals = new bytes[](0);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
        assertEq(foreignCall.getDecodedBytes(), bytes("test"));
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayMixedTypes_Complex() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSigWithMultiArrays(uint256[],address[],string[],bytes[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](4);
        fc.parameterTypes[0] = ParamTypes.STATIC_TYPE_ARRAY;
        fc.parameterTypes[1] = ParamTypes.STATIC_TYPE_ARRAY;
        fc.parameterTypes[2] = ParamTypes.DYNAMIC_TYPE_ARRAY;
        fc.parameterTypes[3] = ParamTypes.DYNAMIC_TYPE_ARRAY;
        fc.encodedIndices = new ForeignCallEncodedIndex[](4);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[1].index = 1;
        fc.encodedIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[2].index = 2;
        fc.encodedIndices[2].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[3].index = 3;
        fc.encodedIndices[3].eType = EncodedIndexType.ENCODED_VALUES;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](4);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[1].index = 0;
        typeSpecificIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[2].index = 0;
        typeSpecificIndices[2].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[3].index = 0;
        typeSpecificIndices[3].eType = EncodedIndexType.ENCODED_VALUES;
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
        array4[4] = abi.encodeWithSelector(
            bytes4(keccak256(bytes("test(uint256,string,address)"))),
            5,
            "superduperduperduperduperduperduperduperduperduperduperduperduperlongstring",
            address(0x1234567)
        );
        bytes memory vals = abi.encode(array1, array2, array3, array4);
        bytes[] memory retVals = new bytes[](0);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
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
        assertEq(
            foreignCall.getInternalArrayBytes()[3],
            abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduperduper(uint256)"))), 4)
        );
        assertEq(
            foreignCall.getInternalArrayBytes()[4],
            abi.encodeWithSelector(
                bytes4(keccak256(bytes("test(uint256,string,address)"))),
                5,
                "superduperduperduperduperduperduperduperduperduperduperduperduperlongstring",
                address(0x1234567)
            )
        );
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayMixedTypes_Complex_WithRetVals()
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
        fc.parameterTypes = new ParamTypes[](4);
        fc.parameterTypes[0] = ParamTypes.STATIC_TYPE_ARRAY;
        fc.parameterTypes[1] = ParamTypes.STATIC_TYPE_ARRAY;
        fc.parameterTypes[2] = ParamTypes.DYNAMIC_TYPE_ARRAY;
        fc.parameterTypes[3] = ParamTypes.DYNAMIC_TYPE_ARRAY;

        fc.encodedIndices = new ForeignCallEncodedIndex[](4);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[1].index = 1;
        fc.encodedIndices[1].eType = EncodedIndexType.FOREIGN_CALL;
        fc.encodedIndices[2].index = 1;
        fc.encodedIndices[2].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[3].index = 2;
        fc.encodedIndices[3].eType = EncodedIndexType.FOREIGN_CALL;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](4);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[1].index = 1;
        typeSpecificIndices[1].eType = EncodedIndexType.FOREIGN_CALL;
        typeSpecificIndices[2].index = 1;
        typeSpecificIndices[2].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[3].index = 2;
        typeSpecificIndices[3].eType = EncodedIndexType.FOREIGN_CALL;

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
        array4[4] = abi.encodeWithSelector(
            bytes4(keccak256(bytes("test(uint256,string,address)"))),
            5,
            "superduperduperduperduperduperduperduperduperduperduperduperduperlongstring",
            address(0x1234567)
        );
        bytes memory vals = abi.encode(array1, array3);
        bytes[] memory retVals = new bytes[](2);
        retVals[0] = abi.encode(array2);
        retVals[1] = abi.encode(array4);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
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
        assertEq(
            foreignCall.getInternalArrayBytes()[3],
            abi.encodeWithSelector(bytes4(keccak256(bytes("superduperduperduper(uint256)"))), 4)
        );
        assertEq(
            foreignCall.getInternalArrayBytes()[4],
            abi.encodeWithSelector(
                bytes4(keccak256(bytes("test(uint256,string,address)"))),
                5,
                "superduperduperduperduperduperduperduperduperduperduperduperduperlongstring",
                address(0x1234567)
            )
        );
    }

    function testRulesEngine_Unit_EncodingForeignCallArrayMixedTypes_Simple() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSigWithMultiArrays(string[],uint256[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](2);
        fc.parameterTypes[0] = ParamTypes.DYNAMIC_TYPE_ARRAY;
        fc.parameterTypes[1] = ParamTypes.STATIC_TYPE_ARRAY;

        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[1].index = 1;
        fc.encodedIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](2);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[1].index = 1;
        typeSpecificIndices[1].eType = EncodedIndexType.ENCODED_VALUES;

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
        bytes[] memory retVals = new bytes[](0);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);
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

    function testRulesEngine_Unit_EncodingForeignCallArrayMixedTypes_ReverseOrderSimple() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSigWithMultiArrays(uint256[],string[])";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        //ForeignCall Builder not used here to test the data structures
        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](2);
        fc.parameterTypes[0] = ParamTypes.STATIC_TYPE_ARRAY;
        fc.parameterTypes[1] = ParamTypes.DYNAMIC_TYPE_ARRAY;

        fc.encodedIndices = new ForeignCallEncodedIndex[](2);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[1].index = 1;
        fc.encodedIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](2);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[1].index = 1;
        typeSpecificIndices[1].eType = EncodedIndexType.ENCODED_VALUES;

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
        bytes[] memory retVals = new bytes[](0);
        RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(fc, vals, retVals, typeSpecificIndices, 1);

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

    function testRulesEngine_Unit_EncodingForeignCallMixedTypes() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory functionSig = "testSig(uint256,string,uint256,string,address)";
        //string memory functionSig = "testSig(string)";
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        ForeignCall memory fc;
        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.parameterTypes = new ParamTypes[](5);
        fc.parameterTypes[0] = ParamTypes.UINT;
        fc.parameterTypes[1] = ParamTypes.STR;
        fc.parameterTypes[2] = ParamTypes.UINT;
        fc.parameterTypes[3] = ParamTypes.STR;
        fc.parameterTypes[4] = ParamTypes.ADDR;

        fc.encodedIndices = new ForeignCallEncodedIndex[](5);
        fc.encodedIndices[0].index = 0;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[1].index = 1;
        fc.encodedIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[2].index = 2;
        fc.encodedIndices[2].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[3].index = 3;
        fc.encodedIndices[3].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[4].index = 4;
        fc.encodedIndices[4].eType = EncodedIndexType.ENCODED_VALUES;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](5);
        typeSpecificIndices[0].index = 0;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[1].index = 1;
        typeSpecificIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[2].index = 2;
        typeSpecificIndices[2].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[3].index = 3;
        typeSpecificIndices[3].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[4].index = 4;
        typeSpecificIndices[4].eType = EncodedIndexType.ENCODED_VALUES;

        bytes memory vals = abi.encode(
            1,
            "test",
            2,
            "superduperduperduperduperduperduperduperduperduperduperduperlongstring",
            address(0x1234567)
        );

        bytes[] memory retVals = new bytes[](0);
        ForeignCallReturnValue memory retVal = RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(
            fc,
            vals,
            retVals,
            typeSpecificIndices,
            1
        );

        assertEq(foreignCall.getDecodedIntOne(), 1);
        assertEq(foreignCall.getDecodedIntTwo(), 2);
        assertEq(foreignCall.getDecodedStrOne(), "test");
        assertEq(foreignCall.getDecodedStrTwo(), "superduperduperduperduperduperduperduperduperduperduperduperlongstring");
        assertEq(foreignCall.getDecodedAddr(), address(0x1234567));
        retVal;
    }

    function testRulesEngine_Unit_EvaluateForeignCallForRule() public ifDeploymentTestsEnabled endWithStopPrank {
        ForeignCall memory fc;
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        string memory functionSig = "testSig(uint256,string,uint256,string,address)";

        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.foreignCallIndex = 0;
        fc.returnType = ParamTypes.BOOL;

        fc.parameterTypes = new ParamTypes[](5);
        fc.parameterTypes[0] = ParamTypes.UINT;
        fc.parameterTypes[1] = ParamTypes.STR;
        fc.parameterTypes[2] = ParamTypes.UINT;
        fc.parameterTypes[3] = ParamTypes.STR;
        fc.parameterTypes[4] = ParamTypes.ADDR;

        fc.encodedIndices = new ForeignCallEncodedIndex[](5);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[1].index = 0;
        fc.encodedIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[2].index = 2;
        fc.encodedIndices[2].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[3].index = 3;
        fc.encodedIndices[3].eType = EncodedIndexType.ENCODED_VALUES;
        fc.encodedIndices[4].index = 5;
        fc.encodedIndices[4].eType = EncodedIndexType.ENCODED_VALUES;
        ForeignCallEncodedIndex[] memory typeSpecificIndices = new ForeignCallEncodedIndex[](5);
        typeSpecificIndices[0].index = 1;
        typeSpecificIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[1].index = 0;
        typeSpecificIndices[1].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[2].index = 2;
        typeSpecificIndices[2].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[3].index = 3;
        typeSpecificIndices[3].eType = EncodedIndexType.ENCODED_VALUES;
        typeSpecificIndices[4].index = 5;
        typeSpecificIndices[4].eType = EncodedIndexType.ENCODED_VALUES;

        // rule signature function arguments (RS): string, uint256, uint256, string, uint256, string, address
        // foreign call function arguments (FC): uint256, string, uint256, string, address
        //
        // Mapping:
        // FC index: 0 1 2 3 4
        // RS index: 1 0 2 3 5

        // Build the rule signature function arguments structure

        bytes memory arguments = abi.encode("one", 2, 3, "four", 5, address(0x12345678));
        bytes[] memory retVals = new bytes[](0);
        // Build the mapping between calling function arguments and foreign call arguments

        ForeignCallReturnValue memory retVal = RulesEngineProcessorFacet(address(red)).evaluateForeignCallForRule(
            fc,
            arguments,
            retVals,
            typeSpecificIndices,
            1
        );
        console2.logBytes(retVal.value);
    }

    // /// Test utility functions within ExampleUserContract.sol and RulesEngineRunRulesEngineProcessorFacet(address(red)).sol
    function testRulesEngine_Utils_UserContract_setRulesEngineAddress() public ifDeploymentTestsEnabled endWithStopPrank {
        userContractInternal.setRulesEngineAddress(address(red));
        assertTrue(userContractInternal.rulesEngineAddress() == address(red));
    }

    function testRulesEngine_Utils_uintToBool() public ifDeploymentTestsEnabled endWithStopPrank {
        bool success = ProcessorLib._uintToBool(1);
        assertTrue(success);
    }

    function testRulesEngine_Utils_BoolToUint() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256 success = ProcessorLib._boolToUint(false);
        assertTrue(success == 0);
    }

    function testRulesEngine_Utils_UintToAddr() public ifDeploymentTestsEnabled endWithStopPrank {
        assertEq(ProcessorLib._uintToAddr(uint256(uint160(address(0xD00d)))), address(0xD00d));
    }

    function testRulesEngine_Utils_UintToBytes() public ifDeploymentTestsEnabled endWithStopPrank {
        bytes memory b = "BYTES STRING OF SUFFICIENT LNGTH";
        assertEq(ProcessorLib._uintToBytes(uint256(abi.decode(b, (uint256)))), b);
    }

    function testRulesEngine_Utils_DynamicArrayExtractionStringArray() public ifDeploymentTestsEnabled endWithStopPrank {
        string[] memory arr = new string[](3);
        arr[0] = "deadbeefdeadbeef";
        arr[1] = "justshootme";
        arr[2] = "96quitebitterbeings";
        bytes memory b = abi.encode(arr);
        bytes
            memory extracted = hex"0000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000000106465616462656566646561646265656600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b6a75737473686f6f746d650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013393671756974656269747465726265696e677300000000000000000000000000";
        assertEq(ProcessorLib._extractDynamicArrayData(b), extracted);
    }

    function testRulesEngine_Utils_DynamicArrayExtractionUintArray() public ifDeploymentTestsEnabled endWithStopPrank {
        uint256[] memory arr = new uint256[](3);
        arr[0] = 1;
        arr[1] = 2;
        arr[2] = 3;
        bytes memory b = abi.encode(arr);
        bytes
            memory extracted = hex"0000000000000000000000000000000000000000000000000000000000000003000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003";
        assertEq(ProcessorLib._extractDynamicArrayData(b), extracted);
    }

    function testRulesEngine_Utils_StringExtraction() public ifDeploymentTestsEnabled endWithStopPrank {
        string memory str = "superduperduperduperduperduperduperduperduperduperduperduperlongstring";
        bytes memory b = abi.encode(str);
        bytes
            memory extracted = hex"00000000000000000000000000000000000000000000000000000000000000467375706572647570657264757065726475706572647570657264757065726475706572647570657264757065726475706572647570657264757065726c6f6e67737472696e670000000000000000000000000000000000000000000000000000";
        assertEq(ProcessorLib._extractStringData(b), extracted);
    }

    function testRulesEngine_Utils_VersionCheck() public ifDeploymentTestsEnabled endWithStopPrank {
        assertEq(RulesEngineProcessorFacet(address(red)).version(), "v1.0.0");
    }
}
