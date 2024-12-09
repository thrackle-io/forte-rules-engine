// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "diamond-std/implementations/ERC173/IERC173.sol";

import {ERC173} from "./ERC173.sol";
import {ERC173Lib} from "./ERC173Lib.sol";

contract ERC173Facet is IERC173, ERC173 {
    /// @inheritdoc IERC173
    function owner() external view returns (address) {
        return ERC173Lib.s().owner;
    }

    /// @inheritdoc IERC173
    function transferOwnership(address newOwner) external onlyOwner {
        ERC173Lib.s().owner = newOwner;

        emit OwnershipTransferred(msg.sender, newOwner);
    }
}
