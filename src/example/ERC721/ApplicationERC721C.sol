// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "../../token/ERC721/ProtocolERC721C.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title ApplicationERC721
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett
 * @notice This is an example implementation of the protocol ERC721 where minting is free and open to anybody.
 */

contract ApplicationERC721C is ProtocolERC721C {
    using Counters for Counters.Counter;
    Counters.Counter private _tokenIdCounter;

    /**
     * @dev Constructor sets the name, symbol and base URI of NFT along with the App Manager and Handler Address
     * @param _name Name of NFT
     * @param _symbol Symbol for the NFT
     * @param _appManagerAddress Address of App Manager
     * @param _baseUri URI for the base token
     */
    constructor(string memory _name, string memory _symbol, address _appManagerAddress, string memory _baseUri) ProtocolERC721C(_name, _symbol, _appManagerAddress, _baseUri) {}

    /**
     * @dev Function mints a new token to anybody. Don't enabled this function if you are not sure about what you're doing.
     * @notice This allows EVERYBODY TO MINT FOR FREE.
     * @param to Address of recipient
     */
    function safeMint(address to) public payable override whenNotPaused {
        uint256 tokenId = _tokenIdCounter.current();
        _tokenIdCounter.increment();
        _safeMint(to, tokenId);
    }
}