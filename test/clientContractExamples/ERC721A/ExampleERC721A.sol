// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import "test/clientContractExamples/ERC721A/ERC721A.sol";
import "src/client/RulesEngineClientERC721A.sol";

contract ExampleERC721A is ERC721A, RulesEngineClientERC721A {
    /**
     * @notice Constructor for the Example ERC721A token.
     * @dev Initializes the token with a name and symbol.
     * @param name The name of the token.
     * @param symbol The symbol of the token.
     */
    constructor(string memory name, string memory symbol) ERC721A(name, symbol) {}

    /**
     * @notice Mints new tokens to the specified address.
     * @param to The address of the recipient.
     * @param quantity The number of tokens to mint.
     */
    function mint(address to, uint256 quantity) public payable virtual checksPoliciesERC721AMintAfter(to, quantity) {
        _mint(to, quantity);
    }

    /**
     * @notice Safely transfers a token from one address to another.
     * @dev This function overrides the {ERC721A-safeTransferFrom} function and interacts with the Rules Engine to ensure 
     *      compliance with transfer policies. It includes additional checks for policy compliance.
     * @param from The address of the current token owner.
     * @param to The address of the recipient.
     * @param tokenId The ID of the token to transfer.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId) public payable override checksPoliciesERC721ASafeTransferFromBefore(from, to, tokenId) {
        super.safeTransferFrom(from, to, tokenId);
    }

    /**
     * @notice Safely transfers tokenIds from one address to another.
     * @param by The approved address.
     * @param from The sending address.
     * @param to The receiving address.
     * @param tokenIds The token identifiers.
     * @param data Generic data to pass along with the transfer.
     */
    function safeBatchTransferFrom(
        address by,
        address from,
        address to,
        uint256[] memory tokenIds,
        bytes memory data
    ) public virtual checksPoliciesERC721ASafeBatchTransferFromBefore(by, from, to, tokenIds, data) {
        _safeBatchTransferFrom(by, from, to, tokenIds, data);
    }
}