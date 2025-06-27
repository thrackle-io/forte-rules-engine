// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import "@openzeppelin/token/ERC1155/ERC1155.sol";
import "@openzeppelin/utils/ReentrancyGuard.sol";
import "@openzeppelin/token/ERC1155/extensions/ERC1155Burnable.sol";
import "src/client/RulesEngineClientERC1155.sol";

/**
 * @title Example ERC1155
 * @dev This contract is an example implementation of an ERC1155 token integrated with the Rules Engine. It extends the 
 *      OpenZeppelin ERC1155 and ERC1155Burnable contracts and includes additional functionality for interacting with the 
 *      Rules Engine. The contract ensures compliance with policies defined in the Rules Engine for minting, transferring, 
 *      and transferring tokens on behalf of others. It also includes a withdrawal function for Ether stored in the contract.
 * @notice This contract demonstrates how to integrate the Rules Engine with an ERC1155 token for policy enforcement.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract ExampleERC1155 is ERC1155, ReentrancyGuard, ERC1155Burnable, RulesEngineClientERC1155 {

    /**
     * @notice Constructor for the Example ERC1155 token.
     * @dev Initializes the token with a base uri.
     * @param _uri The base uri of the token.
     */
     // slither-disable-next-line shadowing-local
    constructor(string memory _uri) ERC1155(_uri) {}

    /**
     * @notice Mints new tokens to the specified address.
     * @param to The address of the recipient.
     * @param tokenId The ID of the token to transfer.
     * @param value The value of tokenId being transfered.
     * @param data Additional data to pass to the recipient contract.
     */
    function mint(address to, uint256 tokenId, uint256 value, bytes memory data) public payable virtual checksPoliciesERC1155MintAfter(to, tokenId, value, data) {
        super._mint(to, tokenId, value, data);
    }

    /**
     * @notice Mints new tokens to the specified address.
     * @param to The address of the recipient.
     * @param tokenIds The IDs of the tokens to transfer.
     * @param values The values of tokenIds being transfered.
     * @param data Additional data to pass to the recipient contract.
     */
    function mintBatch(address to, uint256[] memory tokenIds, uint256[] memory values, bytes memory data) public payable virtual checksPoliciesERC1155BatchMintAfter(to, tokenIds, values, data) {
        super._mintBatch(to, tokenIds, values, data);
    }

    /**
     * @notice Safely transfers a token from one address to another.
     * @dev This function overrides the {ERC1155-safeTransferFrom} function and interacts with the Rules Engine to ensure 
     *      compliance with transfer policies. It includes additional checks for policy compliance.
     * @param from The address of the current token owner.
     * @param to The address of the recipient.
     * @param tokenId The ID of the token to transfer.
     * @param value The value of tokenId being transfered.
     * @param data Additional data to pass to the recipient contract.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId, uint256 value, bytes memory data) public override checksPoliciesERC1155SafeTransferFromBefore(from, to, tokenId, value, data) {
        super.safeTransferFrom(from, to, tokenId, value, data);
    }

    /**
     * @notice Safely transfers a token from one address to another.
     * @dev This function overrides the {ERC1155-safeTransferFrom} function and interacts with the Rules Engine to ensure 
     *      compliance with transfer policies. It includes additional checks for policy compliance.
     * @param from The address of the current token owner.
     * @param to The address of the recipient.
     * @param tokenIds The IDs of the tokens to transfer.
     * @param values The values of tokenIds being transfered.
     * @param data Additional data to pass to the recipient contract.
     */
    function safeBatchTransferFrom(address from, address to, uint256[] memory tokenIds, uint256[] memory values, bytes memory data) public override checksPoliciesERC1155SafeBatchTransferFromBefore(from, to, tokenIds, values, data) {
        super.safeBatchTransferFrom(from, to, tokenIds, values, data);
    }

    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) public view override(ERC1155) returns (bool) {
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
