// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/protocol/economic/ruleProcessor/RuleProcessorDiamondImports.sol";
import "src/common/IOracle.sol";
import {Rule} from "src/client/token/handler/common/DataStructures.sol";

/**
 * @title ERC20 Handler Facet
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev Facet in charge of the logic to check token rules compliance
 * @notice Implements Token Fee Rules on Accounts.
 */
contract ERC20RuleProcessorFacet is IInputErrors, IRuleProcessorErrors, IERC20Errors {
    using RuleProcessorCommonLib for uint64;
    using RuleProcessorCommonLib for uint32;
    using RuleProcessorCommonLib for int256;

    uint256 constant _VOLUME_MULTIPLIER = 10 ** 8;
    uint256 constant _BASIS_POINT = 10000;

    /**
     * @dev Check if transaction passes Token Min Tx Size rule.
     * @param _ruleId Rule Identifier for rule arguments
     * @param amountToTransfer total number of tokens to be transferred
     */
    function checkTokenMinTxSize(uint32 _ruleId, uint256 amountToTransfer) external view {
        NonTaggedRules.TokenMinTxSize memory rule = getTokenMinTxSize(_ruleId);
        if (rule.minSize > amountToTransfer) revert UnderMinTxSize();
    }

    /**
     * @dev Function to get Token Min Tx Size rules by index
     * @param _index position of rule in array
     * @return Rule at index
     */
    function getTokenMinTxSize(uint32 _index) public view returns (NonTaggedRules.TokenMinTxSize memory) {
        _index.checkRuleExistence(getTotalTokenMinTxSize());
        RuleS.TokenMinTxSizeS storage data = Storage.tokenMinTxSizePosition();
        return data.tokenMinTxSizeRules[_index];
    }

    /**
     * @dev Function to get total Token Min Tx Size rules
     * @return Total length of array
     */
    function getTotalTokenMinTxSize() public view returns (uint32) {
        RuleS.TokenMinTxSizeS storage data = Storage.tokenMinTxSizePosition();
        return data.tokenMinTxSizeIndex;
    }

    /**
     * @dev This function receives an array of rule ids, which it uses to get the oracle details, then calls the oracle to determine permissions.
     * @param _rules Rule Id Array
     * @param _address user address to be checked
     */
    function checkAccountApproveDenyOracles(Rule[] memory _rules, address _address) external view {
        for (uint256 accountApproveDenyOracleIndex; accountApproveDenyOracleIndex < _rules.length; ++accountApproveDenyOracleIndex) {
            if (_rules[accountApproveDenyOracleIndex].active) checkAccountApproveDenyOracle(_rules[accountApproveDenyOracleIndex].ruleId, _address);
        }
    }

    /**
     * @dev This function receives a rule id, which it uses to get the oracle details, then calls the oracle to determine permissions.
     * @param _ruleId Rule Id
     * @param _address user address to be checked
     */
    function checkAccountApproveDenyOracle(uint32 _ruleId, address _address) internal view {
        NonTaggedRules.AccountApproveDenyOracle memory oracleRule = getAccountApproveDenyOracle(_ruleId);
        uint256 oType = oracleRule.oracleType;
        address oracleAddress = oracleRule.oracleAddress;
        if (oType == uint(ORACLE_TYPE.APPROVED_LIST)) {
            /// If Approve List Oracle rule active, address(0) is exempt to allow for burning
            if (_address != address(0)) {
                // slither-disable-next-line calls-loop
                if (!IOracle(oracleAddress).isApproved(_address)) {
                    revert AddressNotApproved();
                }
            }
        } else if (oType == uint(ORACLE_TYPE.DENIED_LIST)) {
            // slither-disable-next-line calls-loop
            if (IOracle(oracleAddress).isDenied(_address)) {
                revert AddressIsDenied();
            }
        } else {
            revert OracleTypeInvalid();
        }
    }

    /**
     * @dev Function get Account Approve Deny Oracle Rule by index
     * @param _index Position of rule in storage
     * @return AccountApproveDenyOracle at index
     */
    function getAccountApproveDenyOracle(uint32 _index) public view returns (NonTaggedRules.AccountApproveDenyOracle memory) {
        _index.checkRuleExistence(getTotalAccountApproveDenyOracle());
        RuleS.AccountApproveDenyOracleS storage data = Storage.accountApproveDenyOracleStorage();
        return data.accountApproveDenyOracleRules[_index];
    }

    /**
     * @dev Function get total Account Approve Deny Oracle rules
     * @return total accountApproveDenyOracleRules array length
     */
    function getTotalAccountApproveDenyOracle() public view returns (uint32) {
        RuleS.AccountApproveDenyOracleS storage data = Storage.accountApproveDenyOracleStorage();
        return data.accountApproveDenyOracleIndex;
    }

    /**
     * @dev This function receives an array of rule ids, which it uses to get the oracle details, then calls the oracle to determine permissions.
     * @param _rules Rule Id Array
     * @param _toAddress user address to be checked
     * @param _fromAddress user address to be checked
     */
    function checkAccountApproveDenyOraclesFlexible(Rule[] memory _rules, address _toAddress, address _fromAddress) external view {
        for (uint256 accountApproveDenyOracleFlexibleIndex; accountApproveDenyOracleFlexibleIndex < _rules.length; ++accountApproveDenyOracleFlexibleIndex) {
            if (_rules[accountApproveDenyOracleFlexibleIndex].active) checkAccountApproveDenyOracleFlexible(_rules[accountApproveDenyOracleFlexibleIndex].ruleId, _toAddress, _fromAddress);
        }
    }

    /**
     * @dev This function receives a rule id, which it uses to get the oracle details, then calls the oracle to determine permissions.
     * @param _ruleId Rule Id
     * @param _toAddress to address to be checked
     * @param _fromAddress to address to be checked
     */
    function checkAccountApproveDenyOracleFlexible(uint32 _ruleId, address _toAddress, address _fromAddress) internal view {
        NonTaggedRules.AccountApproveDenyOracleFlexible memory oracleRuleFlexible = getAccountApproveDenyOracleFlexible(_ruleId);
        uint256 oType = oracleRuleFlexible.oracleType;
        address oracleAddress = oracleRuleFlexible.oracleAddress;
        uint8 _addressCheckToggle = oracleRuleFlexible.addressToggle; 
        if (oType == uint(ORACLE_TYPE.APPROVED_LIST)) {
            _isAddressApproved(oracleAddress, _toAddress, _fromAddress, _addressCheckToggle); 
        } else if (oType == uint(ORACLE_TYPE.DENIED_LIST)) {
            _isAddressDenied(oracleAddress, _toAddress, _fromAddress, _addressCheckToggle);
        } else {
            revert OracleTypeInvalid();
        }
    }

    /**
     * @dev Function to check if the address(es) is in the approve oracle
     * @param _oracleAddress address of the approve oracle
     * @param _toAddress to address to be checked
     * @param _fromAddress to address to be checked
     * @param _addressCheckToggle toggle the address to be checked: 0 = Both to and from Address, 1 = to address only, 2 = from address only, 3 = Either to or from address.
     */
    function _isAddressApproved(address _oracleAddress, address _toAddress, address _fromAddress, uint8 _addressCheckToggle) internal view {
        if (_addressCheckToggle == 0){
            // check both to and from addresses are approved 
            // slither-disable-next-line calls-loop
            if (!(IOracle(_oracleAddress).isApproved(_toAddress) && IOracle(_oracleAddress).isApproved(_fromAddress))) {
                revert AddressNotApproved();
            }
        } else if (_addressCheckToggle == 1){
            // check only the to address is approved
            // slither-disable-next-line calls-loop
            if (!IOracle(_oracleAddress).isApproved(_toAddress)) {
                revert AddressNotApproved();
            }
        } else if (_addressCheckToggle == 2){
            // check only the from address is approved
            // slither-disable-next-line calls-loop
            if (!IOracle(_oracleAddress).isApproved(_fromAddress)) {
                revert AddressNotApproved();
            }
        } else {
            // check if either to or from addresses are in the approve oracle 
            // slither-disable-next-line calls-loop
            if (!(IOracle(_oracleAddress).isApproved(_toAddress) || IOracle(_oracleAddress).isApproved(_fromAddress))) {
                revert AddressNotApproved();
            }
        }
    }

    /**
     * @dev Function to check if the address(es) is in the denied oracle
     * @param _oracleAddress address of the denied oracle
     * @param _toAddress to address to be checked
     * @param _fromAddress to address to be checked
     * @param _addressCheckToggle toggle the address to be checked: 0 = Both to and from Address, 1 = to address only, 2 = from address only, 3 = Either to or from address.
     */
    function _isAddressDenied(address _oracleAddress, address _toAddress, address _fromAddress, uint8 _addressCheckToggle) internal view {
        if (_addressCheckToggle == 0){
            // check both to and from addresses are denied 
            // slither-disable-next-line calls-loop
            if (IOracle(_oracleAddress).isDenied(_toAddress) && IOracle(_oracleAddress).isDenied(_fromAddress)) {
                revert AddressIsDenied();
            }
        } else if (_addressCheckToggle == 1){
            // check only the to address is denied
            // slither-disable-next-line calls-loop
            if (IOracle(_oracleAddress).isDenied(_toAddress)) {
                revert AddressIsDenied();
            }
        } else if (_addressCheckToggle == 2){
            // check only the from address is denied
            // slither-disable-next-line calls-loop
            if (IOracle(_oracleAddress).isDenied(_fromAddress)) {
                revert AddressIsDenied();
            }
        } else {
            // check that neither to or from address is in the denied oracle 
            // slither-disable-next-line calls-loop
            if (IOracle(_oracleAddress).isDenied(_toAddress) || IOracle(_oracleAddress).isDenied(_fromAddress)) {
                revert AddressIsDenied();
            }
        }
    }

    /**
     * @dev Function get Account Approve Deny Oracle Flexible Rule by index
     * @param _index Position of rule in storage
     * @return AccountApproveDenyOracleFlexible at index
     */
    function getAccountApproveDenyOracleFlexible(uint32 _index) public view returns (NonTaggedRules.AccountApproveDenyOracleFlexible memory) {
        _index.checkRuleExistence(getTotalAccountApproveDenyOracleFlexible());
        RuleS.AccountApproveDenyOracleFlexibleS storage data = Storage.accountApproveDenyOracleFlexibleStorage();
        return data.accountApproveDenyOracleFlexibleRules[_index];
    }

    /**
     * @dev Function get total Account Approve Deny Oracle Flexible rules
     * @return total accountApproveDenyOracleFlexibleRules array length
     */
    function getTotalAccountApproveDenyOracleFlexible() public view returns (uint32) {
        RuleS.AccountApproveDenyOracleFlexibleS storage data = Storage.accountApproveDenyOracleFlexibleStorage();
        return data.accountApproveDenyOracleFlexibleIndex;
    }

    /**
     * @dev Rule checks if the Token Max Trading Volume rule will be violated.
     * @notice If the totalSupply value is set in the rule, it is set as the circulating supply. Otherwise, this function uses the ERC20 totalSupply sent from handler.
     * @param _ruleId Rule identifier for rule arguments
     * @param _volume token's trading volume thus far
     * @param _amount Number of tokens to be transferred from this account
     * @param _supply Number of tokens in supply
     * @param _lastTransferTime the time of the last transfer
     * @return _volume new accumulated volume
     */
    function checkTokenMaxTradingVolume(uint32 _ruleId, uint256 _volume, uint256 _supply, uint256 _amount, uint64 _lastTransferTime) external view returns (uint256) {
        NonTaggedRules.TokenMaxTradingVolume memory rule = getTokenMaxTradingVolume(_ruleId);
        if (rule.startTime.isRuleActive()) {
            _volume = rule.startTime.isWithinPeriod(rule.period, _lastTransferTime) ? _volume + _amount : _amount;
            /// if the totalSupply value is set in the rule, use that as the circulating supply. Otherwise, use the ERC20 totalSupply(sent from handler)
            if (rule.totalSupply != 0) {
                _supply = rule.totalSupply;
            }
            if (_supply > 0){
                if ((_volume * _BASIS_POINT) / _supply >= uint(rule.max)) {
                    revert OverMaxTradingVolume();
                }
            }
        }
        return _volume;
    }

    /**
     * @dev Function get Token Max Trading Volume by index
     * @param _index position of rule in array
     * @return TokenMaxTradingVolume rule at index position
     */
    function getTokenMaxTradingVolume(uint32 _index) public view returns (NonTaggedRules.TokenMaxTradingVolume memory) {
        _index.checkRuleExistence(getTotalTokenMaxTradingVolume());
        RuleS.TokenMaxTradingVolumeS storage data = Storage.tokenMaxTradingVolumeStorage();
        return data.tokenMaxTradingVolumeRules[_index];
    }

    /**
     * @dev Function to get total Token Max Trading Volume rules
     * @return Total length of array
     */
    function getTotalTokenMaxTradingVolume() public view returns (uint32) {
        RuleS.TokenMaxTradingVolumeS storage data = Storage.tokenMaxTradingVolumeStorage();
        return data.tokenMaxTradingVolumeIndex;
    }

    /**
     * @dev Rule checks if the Token Max Supply Volatility rule will be violated.
     * @notice If the totalSupply value is set in the rule, it is set as the circulating supply. Otherwise, this function uses the ERC20 totalSupply sent from handler.
     * @param _ruleId Rule identifier for rule arguments
     * @param _volumeTotalForPeriod token's trading volume for the period
     * @param _tokenTotalSupply the total supply from token tallies
     * @param _supply token total supply value
     * @param _amount amount in the current transfer
     * @param _lastSupplyUpdateTime the last timestamp the supply was updated
     * @return _volumeTotalForPeriod properly adjusted total for the current period
     * @return _tokenTotalSupply properly adjusted token total supply. This is necessary because if the token's total supply is used it skews results within the period
     */
    function checkTokenMaxSupplyVolatility(
        uint32 _ruleId,
        int256 _volumeTotalForPeriod,
        uint256 _tokenTotalSupply,
        uint256 _supply,
        int256 _amount,
        uint64 _lastSupplyUpdateTime
    ) external view returns (int256, uint256) {
        int256 volatility;
        NonTaggedRules.TokenMaxSupplyVolatility memory rule = getTokenMaxSupplyVolatility(_ruleId);
        if (rule.startTime.isRuleActive()) {
            if (rule.totalSupply != 0) {
                _supply = rule.totalSupply;
            }
            /// Account for the very first period
            if (_tokenTotalSupply == 0) _tokenTotalSupply = _supply;
            if (rule.startTime.isWithinPeriod(rule.period, _lastSupplyUpdateTime)) {
                _volumeTotalForPeriod += _amount;
                /// The _tokenTotalSupply is not modified during the rule period.
                /// It needs to stay the same value as what it was at the beginning of the period to keep consistent results since mints/burns change totalSupply in the token.
            } else {
                _volumeTotalForPeriod = _amount;
                /// Update total supply of token when outside of rule period
                _tokenTotalSupply = _supply;
            }
            volatility = _volumeTotalForPeriod.calculateVolatility(_VOLUME_MULTIPLIER, _tokenTotalSupply);
            // Disabling the next finding, the multiplication here is used purely to get the absolute value
            // slither-disable-next-line divide-before-multiply
            if (volatility < 0) volatility = volatility * -1;
            if (uint256(volatility) > uint(rule.max) * _BASIS_POINT) {
                revert OverMaxSupplyVolatility();
            }
        }
        return (_volumeTotalForPeriod, _tokenTotalSupply);
    }

    /**
     * @dev Function to get Token Max Supply Volatility rule by index
     * @param _index position of rule in array
     * @return tokenMaxSupplyVolatility Rule
     */
    function getTokenMaxSupplyVolatility(uint32 _index) public view returns (NonTaggedRules.TokenMaxSupplyVolatility memory) {
        _index.checkRuleExistence(getTotalTokenMaxSupplyVolatility());
        RuleS.TokenMaxSupplyVolatilityS storage data = Storage.tokenMaxSupplyVolatilityStorage();
        return data.tokenMaxSupplyVolatilityRules[_index];
    }

    /**
     * @dev Function to get total Token Max Supply Volatility rules
     * @return tokenMaxSupplyVolatility Rules total length of array
     */
    function getTotalTokenMaxSupplyVolatility() public view returns (uint32) {
        RuleS.TokenMaxSupplyVolatilityS storage data = Storage.tokenMaxSupplyVolatilityStorage();
        return data.tokenMaxSupplyVolatilityIndex;
    }

    /**
     * @dev Function receives a rule id, retrieves the rule data and checks if the Token Max Buy Sell Volume Rule passes
     * @param ruleId id of the rule to be checked
     * @param currentTotalSupply total supply value passed in by the handler. This is for ERC20 tokens with a fixed total supply.
     * @param amountToTransfer total number of tokens to be transferred in transaction.
     * @param lastTransactionTime time of the most recent purchase from AMM. This starts the check if current transaction is within a purchase window.
     * @param totalWithinPeriod total amount of tokens sold within current period
     */
    function checkTokenMaxBuySellVolume(uint32 ruleId, uint256 currentTotalSupply, uint256 amountToTransfer, uint64 lastTransactionTime, uint256 totalWithinPeriod) external view returns (uint256) {
        uint256 totalForPeriod;
        NonTaggedRules.TokenMaxBuySellVolume memory rule = getTokenMaxBuySellVolume(ruleId);
        totalForPeriod = rule.startTime.isWithinPeriod(rule.period, lastTransactionTime) ? amountToTransfer + totalWithinPeriod : amountToTransfer;
        uint256 totalSupply = rule.totalSupply == 0 ? currentTotalSupply : rule.totalSupply;
        uint16 percentOfTotalSupply = 0;
        if (totalSupply > 0){
            percentOfTotalSupply = uint16(((totalForPeriod) * _BASIS_POINT) / totalSupply);
        }
        if (percentOfTotalSupply >= rule.tokenPercentage) revert OverMaxVolume();
        return totalForPeriod;
    }

    /**
     * @dev Function get Token Max Buy Sell Volume by index
     * @param _index position of rule in array
     * @return tokenMaxSellVolumeRules rule at index position
     */
    function getTokenMaxBuySellVolume(uint32 _index) public view returns (NonTaggedRules.TokenMaxBuySellVolume memory) {
        _index.checkRuleExistence(getTotalTokenMaxBuySellVolume());
        RuleS.TokenMaxBuySellVolumeS storage data = Storage.accountMaxBuySellVolumeStorage();
        return data.tokenMaxBuySellVolumeRules[_index];
    }

    /**
     * @dev Function to get total Token Max Buy Sell Volume rules
     * @return Total length of array
     */
    function getTotalTokenMaxBuySellVolume() public view returns (uint32) {
        RuleS.TokenMaxBuySellVolumeS storage data = Storage.accountMaxBuySellVolumeStorage();
        return data.tokenMaxBuySellVolumeIndex;
    }
}
