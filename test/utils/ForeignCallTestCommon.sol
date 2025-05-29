/// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.13;


import {console} from "forge-std/src/console.sol";
/**
 * @title Example contract for testing the Foreign Call Encoding
 * @author @mpetersoCode55 
 */
contract ForeignCallTestContract {

    uint256 decodedIntOne;
    uint256 decondedIntTwo;
    string decodedStrOne;
    string decodedStrTwo;
    bytes decodedBytes;
    address decodedAddr;
    address decodedAddrTwo;
    uint256 internalValue;
    uint256[] internalArrayUint;
    address[] internalArrayAddr;
    string[] internalArrayStr;
    bytes[] internalArrayBytes;


    function testSig(uint256 encodedIntOne, string memory encodedStrOne, uint256 encodedIntTwo, string memory encodedStrTwo, address encodedAddr) public returns (bool) {
        decodedIntOne = encodedIntOne;
        decondedIntTwo = encodedIntTwo;
        decodedStrOne = encodedStrOne;
        decodedStrTwo = encodedStrTwo;
        decodedAddr = encodedAddr;
        if(encodedIntOne == 1 && encodedIntTwo == 3 && keccak256(bytes(encodedStrOne)) == keccak256("two")) {
            return true;
        } else {
            return false;
        }
    }

    function testSig(uint256 encodedIntOne, uint256 encodedIntTwo) public returns (bool) {
        decodedIntOne = encodedIntOne;
        decondedIntTwo = encodedIntTwo;
        return true;
    }

    function testSig(address encodedAddr, address encodedAddrTwo) public returns (bool) {
        decodedAddr = encodedAddr;
        decodedAddrTwo = encodedAddrTwo;
        return true;
    }

    function testSig(string memory encodedStrOne, string memory encodedStrTwo) public returns (bool) {
        decodedStrOne = encodedStrOne;
        decodedStrTwo = encodedStrTwo;
        return true;
    }

    function testSig(uint256 encodedIntOne) public returns (bool) {
        decodedIntOne = encodedIntOne;
        return true;
    }

    function testSig(address encodedAddr) public returns (bool) {
        decodedAddr = encodedAddr;
        return true;
    }

    function testSig(address encodedAddr, uint256 encodedInt) public returns (bool) {
        decodedAddr = encodedAddr;
        decodedIntOne = encodedInt;
        return true;
    }

    function testSig(string memory encodedStr) public returns (bool) {
        decodedStrOne = encodedStr;
        return true;
    }

    function testSigWithArray(uint256[] memory encodedArray) public returns (bool) {
        for(uint256 i = 0; i < encodedArray.length; i++) {
            internalArrayUint.push(encodedArray[i]);
        }
        return true;
    }

    function testSigWithArray(uint256[] memory encodedArray, uint256[] memory encodedArrayTwo) public returns (bool) {
        for(uint256 i = 0; i < encodedArray.length; i++) {
            internalArrayUint.push(encodedArray[i]);
        }
        for(uint256 i = 0; i < encodedArrayTwo.length; i++) {
            internalArrayUint.push(encodedArrayTwo[i]);
        }
        return true;
    }

    function testSigWithArray(address[] memory encodedArray) public returns (bool) {
        for(uint256 i = 0; i < encodedArray.length; i++) {
            internalArrayAddr.push(encodedArray[i]);
        }
        return true;
    }

    function testSigWithArray(string[] memory encodedArray) public returns (bool) {
        for(uint256 i = 0; i < encodedArray.length; i++) {
            internalArrayStr.push(encodedArray[i]);
        }
        return true;
    }

    function testSigWithArray(string[] memory encodedArray, string[] memory encodedArrayTwo) public returns (bool) {
        for(uint256 i = 0; i < encodedArray.length; i++) {
            internalArrayStr.push(encodedArray[i]);
        }
        for(uint256 i = 0; i < encodedArrayTwo.length; i++) {
            internalArrayStr.push(encodedArrayTwo[i]);
        }
        return true;
    }

    function testSigWithArray(bytes[] memory encodedArray) public returns (bool) {
        for(uint256 i = 0; i < encodedArray.length; i++) {
            internalArrayBytes.push(encodedArray[i]);
        }
        return true;
    }

    function testSigWithBytes(bytes memory encodedBytes) public returns (bool) {
        decodedBytes = encodedBytes;
        return true;
    }

    function testSigWithMultiArrays(string memory str, uint256[] memory uintArray, string[] memory strArray) public returns (bool) {
        decodedStrOne = str;
        for(uint256 i = 0; i < uintArray.length; i++) {
            internalArrayUint.push(uintArray[i]);
        }
        for(uint256 i = 0; i < strArray.length; i++) {
            internalArrayStr.push(strArray[i]);
        }
        return true;
    }

    function testSigWithMultiArrays(uint256[] memory encodedArrayUint, address[] memory encodedArrayAddr, string[] memory encodedArrayStr, bytes[] memory encodedArrayBytes) public returns (bool) {
        for(uint256 i = 0; i < encodedArrayUint.length; i++) {
            internalArrayUint.push(encodedArrayUint[i]);
        }
        for(uint256 i = 0; i < encodedArrayAddr.length; i++) {
            internalArrayAddr.push(encodedArrayAddr[i]);
        }
        for(uint256 i = 0; i < encodedArrayStr.length; i++) {
            internalArrayStr.push(encodedArrayStr[i]);
        }
        for(uint256 i = 0; i < encodedArrayBytes.length; i++) {
            internalArrayBytes.push(encodedArrayBytes[i]);
        }
        return true;
    }

    function testSigWithMultiArrays(uint256[] memory encodedArrayUint, string[] memory encodedArrayStr) public returns (bool) {
        for (uint i = 0; i < encodedArrayUint.length; i++ ){
            internalArrayUint.push(encodedArrayUint[i]);
        }
        for (uint i = 0; i < encodedArrayStr.length; i++ ){
            internalArrayStr.push(encodedArrayStr[i]);
        }
        return true;
    }

    function testSigWithMultiArrays(string[] memory encodedArrayStr, uint256[] memory encodedArrayUint) public returns (bool) {
        for (uint i = 0; i < encodedArrayUint.length; i++ ){
            internalArrayUint.push(encodedArrayUint[i]);
        }
        for (uint i = 0; i < encodedArrayStr.length; i++ ){
            internalArrayStr.push(encodedArrayStr[i]);
        }
        return true;
    }

    function simpleCheck(uint256 value) public returns (uint256) {
        internalValue = value;
        return value;
    }

    function square(uint256 value) public pure returns (uint256) {
        return value * value;
    }

    function getInternalValue() public view returns (uint256) {
        return internalValue;
    }

    function getDecodedIntOne() public view returns (uint256) {
        return decodedIntOne;
    }

    function getDecodedIntTwo() public view returns (uint256) {
        return decondedIntTwo;
    }

    function getDecodedStrOne() public view returns (string memory) {
        return decodedStrOne;
    }

    function getDecodedStrTwo() public view returns (string memory) {
        return decodedStrTwo;
    }

    function getDecodedBytes() public view returns (bytes memory) {
        return decodedBytes;
    }

    function getDecodedAddr() public view returns (address) {
        return decodedAddr;
    }

    function getInternalArrayUint() public view returns (uint256[] memory) {
        return internalArrayUint;
    }

    function getInternalArrayAddr() public view returns (address[] memory) {
        return internalArrayAddr;
    }

    function getInternalArrayStr() public view returns (string[] memory) {
        return internalArrayStr;
    }

    function getInternalArrayBytes() public view returns (bytes[] memory) {
        return internalArrayBytes;
    }

    function getDecodedAddrTwo() public view returns (address) {
        return decodedAddrTwo;
    }

}

contract ForeignCallTestContractOFAC {
    mapping(address => bool) public onTheNaughtyList;
    mapping(address => bool) public approvedList; 
    function addToNaughtyList(address addr) public {
        onTheNaughtyList[addr] = true;
    }

    function getNaughty(address addr) public view returns(bool) {
        return onTheNaughtyList[addr];
    }

    function addToApprovedList(address addr) public {
        approvedList[addr] = true;
    }

    function getApproved(address addr) public view returns(bool) {
        return approvedList[addr];
    }
}
