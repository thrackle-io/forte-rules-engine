// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/protocol/economic/ruleProcessor/RuleProcessorDiamondImports.sol";

/**
 * @title Access Level Processor Facet
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev This contract implements rules to be checked by am Application Handler.
 * @notice Implements Access Level Rule Checks. Access Level rules are measured in
 * in terms of USD with 18 decimals of precision.
 */
contract ApplicationAccessLevelProcessorFacet is IInputErrors, IRuleProcessorErrors, IAccessLevelErrors {
    using RuleProcessorCommonLib for uint64;
    using RuleProcessorCommonLib for uint32;
    using RuleProcessorCommonLib for uint8; 
    
    /**
     * @dev Check if transaction passes Account Max Value By AccessLevel rule.
     * @param _ruleId Rule Identifier for rule arguments
     * @param _accessLevel the Access Level of the account
     * @param _balance account's beginning balance in USD with 18 decimals of precision
     * @param _amountToTransfer total USD amount to be transferred with 18 decimals of precision
     */
    function checkAccountMaxValueByAccessLevel(uint32 _ruleId, uint8 _accessLevel, uint128 _balance, uint128 _amountToTransfer) external view {
        uint48 max = getAccountMaxValueByAccessLevel(_ruleId, _accessLevel);
        /// max has to be multiplied by 10 ** 18 to take decimals in token pricing into account
        if (_amountToTransfer + _balance > (uint256(max) * (10 ** 18))) revert OverMaxValueByAccessLevel();
    }

    /**
     * @dev Function to get the Account Max Value By Access Level rule in the rule set that belongs to the Access Level
     * @param _index position of rule in array
     * @param _accessLevel AccessLevel Level to check
     * @return balanceAmount balance allowed for access level
     */
    function getAccountMaxValueByAccessLevel(uint32 _index, uint8 _accessLevel) public view returns (uint48) {
        RuleS.AccountMaxValueByAccessLevelS storage data = Storage.accountMaxValueByAccessLevelStorage();
        if (_index >= data.accountMaxValueByAccessLevelIndex) revert IndexOutOfRange();
        return data.accountMaxValueByAccessLevelRules[_index][_accessLevel];
    }

    /**
     * @dev Function to get total Account Max Value By Access Level rules
     * @return Total length of array
     */
    function getTotalAccountMaxValueByAccessLevel() public view returns (uint32) {
        RuleS.AccountMaxValueByAccessLevelS storage data = Storage.accountMaxValueByAccessLevelStorage();
        return data.accountMaxValueByAccessLevelIndex;
    }

    /**
     * @dev Check if transaction passes Account Max Value Out By Access Level rule.
     * @param _ruleId Rule Identifier for rule arguments
     * @param _accessLevel the Access Level of the account
     * @param _usdWithdrawalTotal account's total amount withdrawn in USD with 18 decimals of precision
     * @param _usdAmountTransferring total USD amount to be transferred with 18 decimals of precision
     */
    function checkAccountMaxValueOutByAccessLevel(uint32 _ruleId, uint8 _accessLevel, uint128 _usdWithdrawalTotal, uint128 _usdAmountTransferring) external view returns (uint128) {
        uint48 max = getAccountMaxValueOutByAccessLevel(_ruleId, _accessLevel);
        /// max has to be multiplied by 10 ** 18 to take decimals in token pricing into account
        if (_usdAmountTransferring + _usdWithdrawalTotal > (uint256(max) * (10 ** 18))) revert OverMaxValueOutByAccessLevel();
        else _usdWithdrawalTotal += _usdAmountTransferring;
        return _usdWithdrawalTotal;
    }

    /**
     * @dev Rule that checks if the value received from specific address exceeds the limit size in USD for a specific access level
     * @notice that these ranges are set by ranges.
     * @param _ruleId to check against.
     * @param _accessLevel access level of the sending account
     * @param _usdTotalReceived the amount, in USD, of previously received assets
     * @param _from sending address
     * @param _usdAmountTransferring total value of the transfer
     * @return Sending account's new total received.
     */
    function checkAccountMaxReceivedByAccessLevel(uint32 _ruleId, uint8 _accessLevel, uint128 _usdTotalReceived, address _from, uint128 _usdAmountTransferring) external view returns (uint128) {
        (uint48 max, bool applicable) = getAccountMaxReceivedByAccessLevel(_ruleId, _accessLevel, _from);
        /// max has to be multiplied by 10 ** 18 to take decimals in token pricing into account
        if (applicable){
            if ((_usdAmountTransferring + _usdTotalReceived) > (uint256(max) * (10 ** 18))) revert OverMaxReceivedByAccessLevel();
            else _usdTotalReceived += _usdAmountTransferring;
        } 
        return _usdTotalReceived;
    }

    /**
     * @dev Function to get the Account Max Value Out By Access Level rule in the rule set that belongs to the Access Level
     * @param _index position of rule in array
     * @param _accessLevel AccessLevel Level to check
     * @return balanceAmount balance allowed for access level
     */
    function getAccountMaxValueOutByAccessLevel(uint32 _index, uint8 _accessLevel) public view returns (uint48) {
        RuleS.AccountMaxValueOutByAccessLevelS storage data = Storage.accountMaxValueOutByAccessLevelStorage();
        if (_index >= data.accountMaxValueOutByAccessLevelIndex) revert IndexOutOfRange();
        return data.accountMaxValueOutByAccessLevelRules[_index][_accessLevel];
    }

    /**
     * @dev Function to get total Account Max Value Out By Access Level rules
     * @return Total number of access level withdrawal rules
     */
    function getTotalAccountMaxValueOutByAccessLevel() external view returns (uint32) {
        RuleS.AccountMaxValueOutByAccessLevelS storage data = Storage.accountMaxValueOutByAccessLevelStorage();
        return data.accountMaxValueOutByAccessLevelIndex;
    }

    /**
     * @dev Check if transaction passes Account Deny For No Access Level rule.This has no stored rule as there are no additional variables needed.
     * @param _accessLevel the Access Level of the account
     */
    function checkAccountDenyForNoAccessLevel(uint8 _accessLevel) external pure {
        if (_accessLevel == 0) {
            revert NotAllowedForAccessLevel();
        }
    }


     /**
     * @dev Function to get the Account Max Received By Access Level rule in the rule set that belongs to the Access Level
     * @param _index position of rule in array
     * @param _accessLevel AccessLevel Level to check
     * @param _sender sender of the token
     * @return balanceAmount balance allowed for access level
     */
    function getAccountMaxReceivedByAccessLevel(uint32 _index, uint8 _accessLevel, address _sender) internal view returns (uint48, bool applicable) {
        RuleS.AccountMaxReceivedByAccessLevelS storage data = Storage.accountMaxReceivedByAccessLevelStorage();
        if (data.accountMaxReceivedByAccessLevelRules[_index].sender == _sender){
            applicable = true;
            if (_index >= data.accountMaxReceivedByAccessLevelIndex) revert IndexOutOfRange();
        }
        return (data.accountMaxReceivedByAccessLevelRules[_index].accountMaxReceivedLimits[_accessLevel], applicable);
    }

    /**
     * @dev Function to get the Account Max Received By Access Level rule in the rule set that belongs to the Access Level
     * @param _index position of rule in array
     * @param _accessLevel AccessLevel Level to check
     * @return balanceAmount balance allowed for access level
     */
    function getAccountMaxReceivedByAccessLevel(uint32 _index, uint8 _accessLevel) public view returns (uint48) {
        RuleS.AccountMaxReceivedByAccessLevelS storage data = Storage.accountMaxReceivedByAccessLevelStorage();
        if (_index >= data.accountMaxReceivedByAccessLevelIndex) revert IndexOutOfRange();
        return data.accountMaxReceivedByAccessLevelRules[_index].accountMaxReceivedLimits[_accessLevel];
    }

    /**
     * @dev Function to get total Account Max Received By Access Level rules
     * @return Total number of access level withdrawal rules
     */
    function getTotalAccountMaxReceivedByAccessLevel() external view returns (uint32) {
        RuleS.AccountMaxReceivedByAccessLevelS storage data = Storage.accountMaxReceivedByAccessLevelStorage();
        return data.accountMaxReceivedByAccessLevelIndex;
    }
}
