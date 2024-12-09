// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;
/// This contract only exists for testing purposes. It is here to test diamond upgrades. It is named "Sample" instead
/// of "Test" because naming it "Test" causes problems with Foundry testing.
struct SampleStorage {
    uint256 v1;
}

library SampleLib {
    bytes32 constant SAMPLE_STORAGE_POSITION = keccak256("sample.storage");

    /// @notice Return the storage struct for reading and writing.
    /// @return storageStruct The sample  storage struct.
    function s() internal pure returns (SampleStorage storage storageStruct) {
        bytes32 position = SAMPLE_STORAGE_POSITION;
        assembly {
            storageStruct.slot := position
        }
    }

    function sampleFunction() internal pure returns (string memory) {
        return "good";
    }
}
