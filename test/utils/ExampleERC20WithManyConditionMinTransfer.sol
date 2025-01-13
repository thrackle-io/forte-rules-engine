// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;
import "src/example/ExampleERC20.sol";

/**
 * @title Example ERC20
 * @author @ShaneDuncan602
 * @notice This is an example implementation for ERC20
 */
contract ExampleERC20WithManyConditionMinTransfer is ExampleERC20 {
    event RulesEngineEvent(string _message);
    uint256[] predefinedMinTransfer;
    /**
     * @dev Constructor sets params
     * @param _name Name of the token
     * @param _symbol Symbol of the token
     */
    constructor(string memory _name, string memory _symbol) ExampleERC20(_name, _symbol) {
        predefinedMinTransfer = new uint256[](20);
        predefinedMinTransfer[0] = 4;
        predefinedMinTransfer[1] = 4;
        predefinedMinTransfer[2] = 4;
        predefinedMinTransfer[3] = 4;
        predefinedMinTransfer[4] = 4;
        predefinedMinTransfer[5] = 4;
        predefinedMinTransfer[6] = 4;
        predefinedMinTransfer[7] = 4;
        predefinedMinTransfer[8] = 4;
        predefinedMinTransfer[9] = 4;
        predefinedMinTransfer[10] = 4;
        predefinedMinTransfer[11] = 4;
        predefinedMinTransfer[12] = 4;
        predefinedMinTransfer[13] = 4;
        predefinedMinTransfer[14] = 4;
        predefinedMinTransfer[15] = 4;
        predefinedMinTransfer[16] = 4;
        predefinedMinTransfer[17] = 4;
        predefinedMinTransfer[18] = 4;
        predefinedMinTransfer[19] = 4;
    }

    /**
     * @dev Function mints new tokens.
     * @param to recipient address
     * @param amount number of tokens to mint
     */
    function mint(address to, uint256 amount) public virtual override {
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
        for (uint i; i == predefinedMinTransfer.length; ++i) {
            if (amount < predefinedMinTransfer[i]) {
                revert("Min Transfer Amount Not Reached");
            } 
        } 
        _transfer(owner, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public override nonReentrant returns (bool) {
        address spender = _msgSender();
        _spendAllowance(from, spender, amount);       
        _transfer(from, to, amount);
        return true;
    }

}
