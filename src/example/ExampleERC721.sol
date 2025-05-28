// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import "@openzeppelin/token/ERC721/ERC721.sol";
import "@openzeppelin/utils/ReentrancyGuard.sol";
import "@openzeppelin/token/ERC721/extensions/ERC721Burnable.sol";
import "src/client/RulesEngineClientERC721.sol";

/**
 * @title Example ERC721
 * @dev This contract is an example implementation of an ERC721 token integrated with the Rules Engine. It extends the 
 *      OpenZeppelin ERC721 and ERC721Burnable contracts and includes additional functionality for interacting with the 
 *      Rules Engine. The contract ensures compliance with policies defined in the Rules Engine for minting, transferring, 
 *      and transferring tokens on behalf of others. It also includes a withdrawal function for Ether stored in the contract.
 * @notice This contract demonstrates how to integrate the Rules Engine with an ERC721 token for policy enforcement.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract ExampleERC721 is ERC721, ReentrancyGuard, ERC721Burnable, RulesEngineClientERC721 {

    /// Base Contract URI
    string public baseUri;
    uint256 public counter;

    /**
     * @notice Constructor for the Example ERC721 token.
     * @dev Initializes the token with a name and symbol.
     * @param _name The name of the token.
     * @param _symbol The symbol of the token.
     */
     // slither-disable-next-line shadowing-local
    constructor(string memory _name, string memory _symbol) ERC721(_name, _symbol) {}

    /**
     * @notice Mints a new token to the specified address.
     * @dev The token ID is incremented by 1 from the previous minted token. This function is payable to allow child 
     *      contracts to override it with a priced mint function.
     * @param to The address of the recipient.
     */
    function safeMint(address to) public payable virtual checksPoliciesERC721SafeMintAfter(to) {
        uint256 tokenId = counter;
        ++counter;
        _safeMint(to, tokenId);
    }

    /**
     * @notice Safely transfers a token from one address to another.
     * @dev This function overrides the {ERC721-safeTransferFrom} function and interacts with the Rules Engine to ensure 
     *      compliance with transfer policies. It includes additional checks for policy compliance.
     * @param from The address of the current token owner.
     * @param to The address of the recipient.
     * @param tokenId The ID of the token to transfer.
     * @param data Additional data to pass to the recipient contract.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public override checksPoliciesERC721SafeTransferFromBefore(from, to, tokenId, data) {
        super.safeTransferFrom(from, to, tokenId, data);
    }

    /**
     * @notice Transfers a token from one address to another.
     * @dev This function overrides the {ERC721-transferFrom} function and interacts with the Rules Engine to ensure 
     *      compliance with transfer policies. It includes additional checks for policy compliance.
     * @param from The address of the current token owner.
     * @param to The address of the recipient.
     * @param tokenId The ID of the token to transfer.
     */
    function transferFrom(address from, address to, uint256 tokenId) public override checksPoliciesERC721TransferFromBefore(from, to, tokenId) {
        super.transferFrom(from, to, tokenId);
    }

    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) public view override(ERC721) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    /**
     * @notice Withdraws Ether stored in the contract.
     * @dev This function allows only App Administrators to withdraw Ether. It uses the appManagerAddress to enforce 
     *      access control. The function is payable to allow flexibility in child contracts.
     */
    function withdraw() public payable virtual {
        // Disabling this finding as a false positive. The address is not arbitrary, the funciton modifier guarantees 
        // it is a App Admin.
        // slither-disable-next-line arbitrary-send-eth
        (bool success, ) = payable(msg.sender).call{value: address(this).balance}("");
        require(success);
    }
}
