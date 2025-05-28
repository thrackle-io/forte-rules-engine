// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import "@openzeppelin/token/ERC20/ERC20.sol";
import "@openzeppelin/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/utils/ReentrancyGuard.sol";
import "src/client/RulesEngineClientERC20.sol";

/**
 * @title Example ERC20
 * @author @ShaneDuncan602
 * @notice This is an example implementation for ERC20
 */
contract ExampleERC20Pause is ERC20, ERC20Burnable, ReentrancyGuard, RulesEngineClientERC20 {
    uint256 pauseTimestamp; 

    /**
     * @dev Constructor sets params
     * @param _name Name of the token
     * @param _symbol Symbol of the token
     */
    constructor(string memory _name, string memory _symbol) ERC20(_name, _symbol) {}

    /**
     * @dev Function mints new tokens.
     * @param to recipient address
     * @param amount number of tokens to mint
     */
    function mint(address to, uint256 amount) public virtual  {
        _mint(to, amount);
    }

    /**
     * @dev This is overridden from {IERC20-transfer}. It handles all interactions with the rules engine
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - the caller must have a balance of at least `amount`.
     */
    // Disabling this finding, it is a false positive. A reentrancy lock modifier has been
    // applied to this function
    // slither-disable-start reentrancy-events
    // slither-disable-start reentrancy-no-eth
    function transfer(
        address to,
        uint256 amount
    ) public virtual override nonReentrant returns (bool) {
        address owner = _msgSender();
        _transfer(owner, to, amount);
        return true;
    }

    /**
     * @dev This is overridden from {IERC20-transferFrom}. It handles all interactions with the rules engine.
     *
     * Emits an {Approval} event indicating the updated allowance. This is not
     * required by the EIP. See the note at the beginning of {ERC20}.
     *
     * NOTE: Does not update the allowance if the current allowance
     * is the maximum `uint256`.
     *
     * Requirements:
     *
     * - `from` and `to` cannot be the zero address.
     * - `from` must have a balance of at least `amount`.
     * - the caller must have allowance for ``from``'s tokens of at least
     * `amount`.
     */
    function transferFrom(address from, address to, uint256 amount) public virtual override nonReentrant returns (bool) {
        require(block.timestamp > pauseTimestamp, "Transfers paused"); 
        address spender = _msgSender();
        _spendAllowance(from, spender, amount);       
        _transfer(from, to, amount);
        return true;
    }

    function setPauseTime(uint256 _pauseTimestamp) public {
        pauseTimestamp = _pauseTimestamp; 
    }
}
