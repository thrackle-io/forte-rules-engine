// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721Burnable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "src/client/token/ProtocolTokenCommon.sol";
import "src/protocol/economic/AppAdministratorOrOwnerOnly.sol";
import "src/client/token/handler/diamond/IHandlerDiamond.sol";

/**
 * @title Protocol ERC721 Base Contract
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett
 * @notice This is a base contract for all test ERC721s
 */

contract UtilProtocolERC721 is ERC721Burnable, ERC721URIStorage, ERC721Enumerable, ProtocolTokenCommon, AppAdministratorOrOwnerOnly, ReentrancyGuard {
    using Counters for Counters.Counter;
    Counters.Counter internal _tokenIdCounter;

    /// Base Contract URI
    string public baseUri;

    /**
     * @dev Constructor sets the name, symbol and base URI of NFT along with the App Manager Address
     * @param _nameProto Name of NFT
     * @param _symbolProto Symbol for the NFT
     * @param _appManagerAddress Address of App Manager
     * @param _baseUri URI for the base token
     */
    constructor(string memory _nameProto, string memory _symbolProto, address _appManagerAddress, string memory _baseUri) ERC721(_nameProto, _symbolProto) {
        if (_appManagerAddress == address(0)) revert ZeroAddress();
        appManagerAddress = _appManagerAddress;
        appManager = IAppManager(_appManagerAddress);
        setBaseURI(_baseUri);
    }

    /********** setters and getters for rules  **********/
    /**
     * @dev Function to return baseUri for contract
     * @return baseUri URI link to NFT metadata
     */
    function _baseURI() internal view override returns (string memory) {
        return baseUri;
    }

    /**
     * @dev Function to set URI for contract.
     * @notice this is called in the constructor and can be called to update URI metadata pointer
     * @param _baseUri URI to the metadata file(s) for the contract
     */
    function setBaseURI(string memory _baseUri) public virtual appAdministratorOrOwnerOnly(appManagerAddress) {
        baseUri = _baseUri;
    }

    /**
     * @dev Function to set URI for specific token
     * @param tokenId Id of token to update
     * @return tokenURI new URI for token Id
     */
    function tokenURI(uint256 tokenId) public view virtual override(ERC721, ERC721URIStorage) returns (string memory) {
        return ERC721URIStorage.tokenURI(tokenId);
    }

    /**
     * @dev Function mints new a new token to caller with tokenId incremented by 1 from previous minted token.
     * @notice Add appAdministratorOnly modifier to restrict minting privilages
     * Function is payable for child contracts to override with priced mint function.
     * @param to Address of recipient
     */
    function safeMint(address to) public payable virtual appAdministratorOrOwnerOnly(appManagerAddress) {
        uint256 tokenId = _tokenIdCounter.current();
        _tokenIdCounter.increment();
        _safeMint(to, tokenId);
    }

    /**
     * @dev Function called before any token transfers to confirm transfer is within rules of the protocol
     * @param from sender address
     * @param to recipient address
     * @param tokenId Id of token to be transferred
     * @param batchSize the amount of NFTs to mint in batch. If a value greater than 1 is given, tokenId will
     * represent the first id to start the batch.
     */
    function _beforeTokenTransfer(address from, address to, uint256 tokenId, uint256 batchSize) internal nonReentrant override(ERC721, ERC721Enumerable) {
        // Rule Processor Module Check
        if (handlerAddress != address(0)) require(IHandlerDiamond(handlerAddress).checkAllRules(from == address(0) ? 0 : balanceOf(from), to == address(0) ? 0 : balanceOf(to), from, to, _msgSender(), tokenId));
        // Disabling this finding, it is a false positive. A reentrancy lock modifier has been 
        // applied to this function
        // slither-disable-next-line reentrancy-benign
        super._beforeTokenTransfer(from, to, tokenId, batchSize);
    }

    /// The following functions are overrides required by Solidity.
    /**
     * @dev Function to burn or remove token from circulation
     * @param tokenId Id of token to be burned
     */
    function _burn(uint256 tokenId) internal override(ERC721, ERC721URIStorage) {
        super._burn(tokenId);
    }

    /**
     * @dev Function to withdraw Ether sent to contract
     * @dev AppAdministratorOnly modifier uses appManagerAddress. Only Addresses asigned as AppAdministrator can call function.
     */
    function withdraw() public payable virtual appAdministratorOnly(appManagerAddress) {
        // Disabling this finding as a false positive. The address is not arbitrary, the funciton modifier guarantees 
        // it is a App Admin.
        // slither-disable-next-line arbitrary-send-eth
        (bool success, ) = payable(msg.sender).call{value: address(this).balance}("");
        require(success);
    }

    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) public view override(ERC721, ERC721Enumerable, ERC721URIStorage) returns (bool) {
        return ERC721Enumerable.supportsInterface(interfaceId) || ERC721URIStorage.supportsInterface(interfaceId) || super.supportsInterface(interfaceId);
    }

    /**
     * @dev This function returns the handler address
     * @return handlerAddress
     */
    function getHandlerAddress() external view override returns (address) {
        return handlerAddress;
    }
}
