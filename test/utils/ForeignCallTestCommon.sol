// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

/**
 * @title Example contract for testing the Foreign Call Encoding
 * @author @mpetersoCode55 
 */
contract ForeignCallTestContract {

    uint256 decodedIntOne;
    uint256 decondedIntTwo;
    string decodedStrOne;
    string decodedStrTwo;
    address decodedAddr;   
    uint256 internalValue;

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

    function simpleCheck(uint256 value) public returns (uint256) {
        internalValue = value;
        return value;
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

    function getDecodedAddr() public view returns (address) {
        return decodedAddr;
    }

}

contract ForeignCallTestContractOFAC {
    mapping(address => bool) public onTheNaughtyList;
    function addToNaughtyList(address addr) public {
        onTheNaughtyList[addr] = true;
    }

    function getNaughty(address addr) public returns(bool) {
        return onTheNaughtyList[addr];
    }
}
