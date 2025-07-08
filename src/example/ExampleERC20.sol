// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import "@openzeppelin/token/ERC20/ERC20.sol";
import "@openzeppelin/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/utils/ReentrancyGuard.sol";
import "src/client/RulesEngineClientERC20.sol";

/**
 * @title Example ERC20
 * @dev This contract is an example implementation of an ERC20 token integrated with the Rules Engine. It extends the
 *      OpenZeppelin ERC20 and ERC20Burnable contracts and includes additional functionality for interacting with the
 *      Rules Engine. The contract ensures compliance with policies defined in the Rules Engine for minting, transferring,
 *      and transferring tokens on behalf of others.
 * @notice This contract demonstrates how to integrate the Rules Engine with an ERC20 token for policy enforcement.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract ExampleERC20 is ERC20, ERC20Burnable, ReentrancyGuard, RulesEngineClientERC20 {
    /**
     * @notice Constructor for the Example ERC20 token.
     * @dev Initializes the token with a name and symbol.
     * @param _name The name of the token.
     * @param _symbol The symbol of the token.
     */
    constructor(string memory _name, string memory _symbol) ERC20(_name, _symbol) {}

    /**
     * @notice Mints new tokens to a specified address.
     * @dev This function interacts with the Rules Engine to ensure compliance with minting policies.
     * @param to The recipient address.
     * @param amount The number of tokens to mint.
     */
    function mint(
        address to,
        uint256 amount
    ) public virtual checksPoliciesERC20MintBefore(to, amount, balanceOf(msg.sender), balanceOf(to), block.timestamp) {
        _mint(to, amount);
    }

    /**
     * @notice Transfers tokens to a specified address.
     * @dev This function overrides the {IERC20-transfer} function and interacts with the Rules Engine to ensure compliance
     *      with transfer policies. It includes a reentrancy guard to prevent reentrancy attacks.
     * @param to The recipient address.
     * @param amount The number of tokens to transfer.
     * @return bool True if the transfer is successful, false otherwise.
     */
    // Disabling this finding, it is a false positive. A reentrancy lock modifier has been
    // applied to this function
    // slither-disable-start reentrancy-events
    // slither-disable-start reentrancy-no-eth
    function transfer(
        address to,
        uint256 amount
    )
        public
        virtual
        override
        nonReentrant
        checksPoliciesERC20TransferBefore(to, amount, balanceOf(msg.sender), balanceOf(to), block.timestamp)
        returns (bool)
    {
        address owner = _msgSender();
        _transfer(owner, to, amount);
        return true;
    }

    /**
     * @notice Transfers tokens on behalf of another address.
     * @dev This function overrides the {IERC20-transferFrom} function and interacts with the Rules Engine to ensure compliance
     *      with transfer policies. It includes a reentrancy guard to prevent reentrancy attacks.
     * @param from The address to transfer tokens from.
     * @param to The recipient address.
     * @param amount The number of tokens to transfer.
     * @return bool True if the transfer is successful, false otherwise.
     */
    function transferFrom(
        address from,
        address to,
        uint256 amount
    )
        public
        virtual
        override
        nonReentrant
        checksPoliciesERC20TransferFromBefore(from, to, amount, balanceOf(msg.sender), balanceOf(to), block.timestamp)
        returns (bool)
    {
        address spender = _msgSender();
        _spendAllowance(from, spender, amount);
        _transfer(from, to, amount);
        return true;
    }
}
