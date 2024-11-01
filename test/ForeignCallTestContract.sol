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

    function testSig(uint256 encodedIntOne, string memory encodedStrOne, uint256 encodedIntTwo, string memory encodedStrTwo, address encodedAddr) public {
        decodedIntOne = encodedIntOne;
        decondedIntTwo = encodedIntTwo;
        decodedStrOne = encodedStrOne;
        decodedStrTwo = encodedStrTwo;
        decodedAddr = encodedAddr;
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