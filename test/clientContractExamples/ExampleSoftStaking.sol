/// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;


import "lib/openzeppelin-contracts/contracts/token/ERC721/ERC721.sol";
import {ERC721Burnable} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721Burnable.sol";
import {ERC721Enumerable} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import "lib/openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";

contract MyToken is ERC721, ERC721Enumerable, ERC721Burnable, Ownable, ReentrancyGuard {
    event tokenStaked(); 
    event tokenUnstaked();

    mapping(uint256 => bool) isTokenIDStaked; 

    constructor(address initialOwner)
        ERC721("MyToken", "MTK")
        Ownable(initialOwner)
    {}

    function _baseURI() internal pure override returns (string memory) {
        return "http://TestURI.io";
    }

    function safeMint(address to, uint256 tokenId) public onlyOwner {
        _safeMint(to, tokenId);
    }

    // The following functions are overrides required by Solidity.

    function _update(address to, uint256 tokenId, address auth)
        internal
        override(ERC721, ERC721Enumerable)
        returns (address)
    {
        require(isTokenIDStaked[tokenId] == false);
        return super._update(to, tokenId, auth);
    }

    function _increaseBalance(address account, uint128 value)
        internal
        override(ERC721, ERC721Enumerable)
    {
        super._increaseBalance(account, value);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC721, ERC721Enumerable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function softStake(uint256 _tokenId) public {
        require(msg.sender == ownerOf(_tokenId));
        isTokenIDStaked[_tokenId] = true; 
        emit tokenStaked();  
    }

    function softUnstake(uint256 _tokenId) public {
        require(msg.sender == ownerOf(_tokenId));
        isTokenIDStaked[_tokenId] = false; 
        emit tokenUnstaked();  
    }
}
