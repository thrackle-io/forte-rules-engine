// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;
import "src/example/ExampleERC20.sol";
import "test/utils/ForeignCallTestCommon.sol";

/**
 * @title Example ERC20
 * @author @ShaneDuncan602
 * @notice This is an example implementation for ERC20
 */
contract ExampleERC20WithDenyList is ExampleERC20 {
    event RulesEngineEvent(string _message);
    ForeignCallTestContractOFAC fc;
    uint256 predefinedMinTransfer;
    /**
     * @dev Constructor sets params
     * @param _name Name of the token
     * @param _symbol Symbol of the token
     */
    constructor(string memory _name, string memory _symbol) ExampleERC20(_name, _symbol) {
        predefinedMinTransfer = 4;
        fc = new ForeignCallTestContractOFAC();
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
        bool isOnDenyList = fc.onTheNaughtyList(to);
        if (isOnDenyList) {
            revert("To Address is denied");
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

    function addToDenyList(address _to) public {
        fc.addToNaughtyList(_to);
    }

}
