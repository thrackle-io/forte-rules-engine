// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;
/// This contract only exists for testing purposes. It is here to test diamond upgrades. It is named "Sample" instead
/// of "Test" because naming it "Test" causes problems with Foundry testing.
import {ERC173} from "diamond-std/implementations/ERC173/ERC173.sol";
import {ERC173Lib} from "diamond-std/implementations/ERC173/ERC173Lib.sol";
import {SampleLib} from "./SampleLib.sol";

contract SampleFacet is ERC173 {
    function sampleFunction() external view onlyOwner returns (string memory) {
        return SampleLib.sampleFunction();
    }
}
