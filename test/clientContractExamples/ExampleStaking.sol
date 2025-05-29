/// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "@openzeppelin/token/ERC20/IERC20.sol";


contract ExampleStaking {
    
    function dummyStake(address erc20, uint256 erc20Amount) public {
        IERC20(erc20).transferFrom(msg.sender, address(this), erc20Amount);
    }

    function dummyUnStake(address erc20, uint256 erc20Amount) public {
        IERC20(erc20).transfer(msg.sender, erc20Amount);
    }

}
