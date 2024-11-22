/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";


contract ExampleStaking {
    
    function dummyStake(address erc20, uint256 erc20Amount) public {
        IERC20(erc20).transferFrom(msg.sender, address(this), erc20Amount);
    }

    function dummyUnStake(address erc20, uint256 erc20Amount) public {
        IERC20(erc20).transfer(msg.sender, erc20Amount);
    }

}
