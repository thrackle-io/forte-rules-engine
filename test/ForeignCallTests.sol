/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "lib/forge-std/src/Test.sol";
import "src/utils/FCEncodingLib.sol";
import "src/RulesEngineStructures.sol";


contract ForeignCallTests is Test {

    function test_getFCAddress() public pure {
        RulesStorageStructure.ForeignCallReturnValue memory retVal;
        retVal.pType = RulesStorageStructure.PT.ADDR;
        retVal.value = abi.encode(address(1));
        address addr = FCEncodingLib.getFCAddress(retVal);
        assertEq(addr, address(1));
    }

    function test_getFCAddress_wrongType() public {
        RulesStorageStructure.ForeignCallReturnValue memory retVal;
        retVal.pType = RulesStorageStructure.PT.UINT;
        retVal.value = abi.encode(uint256(1));
        vm.expectRevert();
        FCEncodingLib.getFCAddress(retVal);
    }

    function test_getFCString() public pure {
        RulesStorageStructure.ForeignCallReturnValue memory retVal;
        retVal.pType = RulesStorageStructure.PT.STR;
        retVal.value = abi.encode("hello");
        string memory str = FCEncodingLib.getFCString(retVal);
        assertEq(str, "hello");
    }

    function test_getFCString_negative() public {
        RulesStorageStructure.ForeignCallReturnValue memory retVal;
        retVal.pType = RulesStorageStructure.PT.UINT;
        retVal.value = abi.encode(uint256(1));
        vm.expectRevert();
        FCEncodingLib.getFCString(retVal);
    }

    function test_getFCUint() public pure {
        RulesStorageStructure.ForeignCallReturnValue memory retVal;
        retVal.pType = RulesStorageStructure.PT.UINT;
        retVal.value = abi.encode(uint256(1));
        uint256 uintVal = FCEncodingLib.getFCUint(retVal);
        assertEq(uintVal, 1);
    }

    function test_getFCUint_negative() public {
        RulesStorageStructure.ForeignCallReturnValue memory retVal;
        retVal.pType = RulesStorageStructure.PT.STR;
        retVal.value = abi.encode("hello");
        vm.expectRevert();
        FCEncodingLib.getFCUint(retVal);
    }

    function test_getFCBool() public pure {
        RulesStorageStructure.ForeignCallReturnValue memory retVal;
        retVal.pType = RulesStorageStructure.PT.BOOL;
        retVal.value = abi.encode(true);
        bool boolVal = FCEncodingLib.getFCBool(retVal);
        assertEq(boolVal, true);
    }

    function test_getFCBool_negative() public {
        RulesStorageStructure.ForeignCallReturnValue memory retVal;
        retVal.pType = RulesStorageStructure.PT.UINT;
        retVal.value = abi.encode(uint256(1));
        vm.expectRevert();
        FCEncodingLib.getFCBool(retVal);
    }
}
