// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/Context.sol";
import "src/protocol/economic/RuleAdministratorOnly.sol";
import "src/protocol/economic/AppAdministratorOnly.sol";
import "src/protocol/economic/ruleProcessor/RuleProcessorDiamondImports.sol";

/**
 * @title Rule Data Facet
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev setters and getters for non tagged token specific rules
 * @notice This contract sets and gets the Rules for the protocol
 */
contract RuleDataFacet is Context, RuleAdministratorOnly, IEconomicEvents, IInputErrors, ITagInputErrors, IZeroAddressError, IAppRuleInputErrors {
    using RuleProcessorCommonLib for uint64;
    using RuleProcessorCommonLib for uint32;
    uint16 constant MAX_TOKEN_PERCENTAGE = 9999;
    uint16 constant MAX_PERCENTAGE = 10000;
    uint24 constant MAX_VOLUME_PERCENTAGE = 100000;

    /**
     * Note that no update method is implemented for rules. Since reutilization of
     * rules is encouraged, it is preferred to add an extra rule to the
     * set instead of modifying an existing one.
     */

    /**
     * @dev Function to add a Token Max Buy Sell Volume rule
     * @param _appManagerAddr Address of App Manager
     * @param _supplyPercentage Percentage of Tokens allowed for transaction
     * @param _period Time period that transactions are accumulated (in hours)
     * @param _totalSupply total supply of tokens (0 if using total supply from the token contract)
     * @param _startTime start timestamp for the rule
     * @return ruleId position of new rule in array
     */
    function addTokenMaxBuySellVolume(
        address _appManagerAddr,
        uint16 _supplyPercentage,
        uint16 _period,
        uint256 _totalSupply,
        uint64 _startTime
    ) external ruleAdministratorOnly(_appManagerAddr) returns (uint32) {
        if (_appManagerAddr == address(0)) revert ZeroAddress();
        if (_supplyPercentage > MAX_TOKEN_PERCENTAGE) revert ValueOutOfRange(_supplyPercentage);
        if (_period == 0 || _supplyPercentage == 0) revert ZeroValueNotPermited();
        _startTime.validateTimestamp();
        RuleS.TokenMaxBuySellVolumeS storage data = Storage.accountMaxBuySellVolumeStorage();
        NonTaggedRules.TokenMaxBuySellVolume memory rule = NonTaggedRules.TokenMaxBuySellVolume(_supplyPercentage, _period, _totalSupply, _startTime);
        uint32 ruleId = data.tokenMaxBuySellVolumeIndex;
        data.tokenMaxBuySellVolumeRules[ruleId] = rule;
        emit AD1467_ProtocolRuleCreated(TOKEN_MAX_BUY_SELL_VOLUME, ruleId, new bytes32[](0));
        ++data.tokenMaxBuySellVolumeIndex;
        return ruleId;
    }

    /**
     * @dev Function to add a Token Purchase Fee By Volume rule
     * @param _appManagerAddr Address of App Manager
     * @param _volume Maximum allowed volume
     * @param _rateIncreased Amount rate increased
     * @return ruleId position of new rule in array
     */
    function addPurchaseFeeByVolumeRule(address _appManagerAddr, uint256 _volume, uint16 _rateIncreased) external ruleAdministratorOnly(_appManagerAddr) returns (uint32) {
        if (_appManagerAddr == address(0)) revert ZeroAddress();
        if (_volume == 0 || _rateIncreased == 0) revert ZeroValueNotPermited();
        if (_rateIncreased > MAX_PERCENTAGE) revert ValueOutOfRange(_rateIncreased);
        RuleS.PurchaseFeeByVolRuleS storage data = Storage.purchaseFeeByVolumeStorage();
        NonTaggedRules.TokenPurchaseFeeByVolume memory rule = NonTaggedRules.TokenPurchaseFeeByVolume(_volume, _rateIncreased);
        uint32 ruleId = data.purchaseFeeByVolumeRuleIndex;
        data.purchaseFeeByVolumeRules[ruleId] = rule;
        emit AD1467_ProtocolRuleCreated(BUY_FEE_BY_VOLUME, ruleId, new bytes32[](0));
        ++data.purchaseFeeByVolumeRuleIndex;
        return ruleId;
    }

    /**
     * @dev Function get Token PurchaseFeeByVolume Rule by index
     * @param _index position of rule in array
     * @return TokenPurchaseFeeByVolume rule at index position
     */
    function getPurchaseFeeByVolumeRule(uint32 _index) external view returns (NonTaggedRules.TokenPurchaseFeeByVolume memory) {
        // check one of the required non zero values to check for existence, if not, revert
        _index.checkRuleExistence(getTotalTokenPurchaseFeeByVolumeRules());
        RuleS.PurchaseFeeByVolRuleS storage data = Storage.purchaseFeeByVolumeStorage();
        return data.purchaseFeeByVolumeRules[_index];
    }

    /**
     * @dev Function to get total Token Purchase Percentage
     * @return Total length of array
     */
    function getTotalTokenPurchaseFeeByVolumeRules() public view returns (uint32) {
        RuleS.PurchaseFeeByVolRuleS storage data = Storage.purchaseFeeByVolumeStorage();
        return data.purchaseFeeByVolumeRuleIndex;
    }

    /**
     * @dev Function to add a Token Max Price Volatility rule
     * @param _appManagerAddr Address of App Manager
     * @param _max Maximum allowed volume
     * @param _period period in hours for the rule
     * @param _hoursFrozen freeze period hours
     * @return ruleId position of new rule in array
     */
    function addTokenMaxPriceVolatility(
        address _appManagerAddr,
        uint16 _max,
        uint16 _period,
        uint16 _hoursFrozen,
        uint256 _totalSupply
    ) external ruleAdministratorOnly(_appManagerAddr) returns (uint32) {
        if (_appManagerAddr == address(0)) revert ZeroAddress();
        if (_max == 0 || _period == 0 || _hoursFrozen == 0) revert ZeroValueNotPermited();
        RuleS.TokenMaxPriceVolatilityS storage data = Storage.tokenMaxPriceVolatilityStorage();
        NonTaggedRules.TokenMaxPriceVolatility memory rule = NonTaggedRules.TokenMaxPriceVolatility(_max, _period, _hoursFrozen, _totalSupply);
        uint32 ruleId = data.tokenMaxPriceVolatilityIndex;
        data.tokenMaxPriceVolatilityRules[ruleId] = rule;
        emit AD1467_ProtocolRuleCreated(TOKEN_VOLATILITY, ruleId, new bytes32[](0));
        ++data.tokenMaxPriceVolatilityIndex;
        return ruleId;
    }

    /**
     * @dev Function get Token Volatility Rule by index
     * @param _index position of rule in array
     * @return tokenMaxPriceVolatilityRules rule at index position
     */
    function getTokenMaxPriceVolatility(uint32 _index) external view returns (NonTaggedRules.TokenMaxPriceVolatility memory) {
        // check one of the required non zero values to check for existence, if not, revert
        _index.checkRuleExistence(getTotalTokenMaxPriceVolatility());
        RuleS.TokenMaxPriceVolatilityS storage data = Storage.tokenMaxPriceVolatilityStorage();
        return data.tokenMaxPriceVolatilityRules[_index];
    }

    /**
     * @dev Function to get total Volatility rules
     * @return Total length of array
     */
    function getTotalTokenMaxPriceVolatility() public view returns (uint32) {
        RuleS.TokenMaxPriceVolatilityS storage data = Storage.tokenMaxPriceVolatilityStorage();
        return data.tokenMaxPriceVolatilityIndex;
    }

    /**
     * @dev Function to add a Token max trading Volume rules
     * @param _appManagerAddr Address of App Manager
     * @param _maxPercentage Maximum allowed volume percentage (this is 4 digits to allow 2 decimal places)
     * @param _hoursPerPeriod hours that define a period
     * @param _startTime Timestamp to start the rule
     * @param _totalSupply Circulating supply value to use in calculations. If not specified, defaults to ERC20 totalSupply
     * @return ruleId position of new rule in array
     */
    function addTokenMaxTradingVolume(
        address _appManagerAddr,
        uint24 _maxPercentage,
        uint16 _hoursPerPeriod,
        uint64 _startTime,
        uint256 _totalSupply
    ) external ruleAdministratorOnly(_appManagerAddr) returns (uint32) {
        if (_appManagerAddr == address(0)) revert ZeroAddress();
        if (_maxPercentage > MAX_VOLUME_PERCENTAGE) revert ValueOutOfRange(_maxPercentage);
        if (_maxPercentage == 0 || _hoursPerPeriod == 0) revert ZeroValueNotPermited();
        _startTime.validateTimestamp();
        RuleS.TokenMaxTradingVolumeS storage data = Storage.tokenMaxTradingVolumeStorage();
        NonTaggedRules.TokenMaxTradingVolume memory rule = NonTaggedRules.TokenMaxTradingVolume(_maxPercentage, _hoursPerPeriod, _startTime, _totalSupply);
        uint32 ruleId = data.tokenMaxTradingVolumeIndex;
        data.tokenMaxTradingVolumeRules[ruleId] = rule;
        emit AD1467_ProtocolRuleCreated(TOKEN_MAX_TRADING_VOLUME, ruleId, new bytes32[](0));
        ++data.tokenMaxTradingVolumeIndex;
        return ruleId;
    }

    /**
     * @dev Function to add Token Min Tx Size rules
     * @param _appManagerAddr Address of App Manager
     * @param _minSize Mimimum amount of tokens required for transfer
     * @return ruleId position of new rule in array
     */
    function addTokenMinTxSize(address _appManagerAddr, uint256 _minSize) external ruleAdministratorOnly(_appManagerAddr) returns (uint32) {
        if (_appManagerAddr == address(0)) revert ZeroAddress();
        if (_minSize == 0) revert ZeroValueNotPermited();
        RuleS.TokenMinTxSizeS storage data = Storage.tokenMinTxSizePosition();
        NonTaggedRules.TokenMinTxSize memory rule = NonTaggedRules.TokenMinTxSize(_minSize);
        uint32 ruleId = data.tokenMinTxSizeIndex;
        data.tokenMinTxSizeRules[ruleId] = rule;
        emit AD1467_ProtocolRuleCreated(TOKEN_MIN_TX_SIZE, ruleId, new bytes32[](0));
        ++data.tokenMinTxSizeIndex;
        return ruleId;
    }


    /**
     * @dev Function Token Max Supply Volatility rules
     * @param _appManagerAddr Address of App Manager
     * @param _maxPercentage Maximum amount of change allowed. This is not capped and will allow for values greater than 100%.
     * Since there is no cap for _maxPercentage this could allow burning of full totalSupply() if over 100% (10000).
     * @param _period Allowed hours per period
     * @param _startTime Unix timestamp for the _period to start counting.
     * @param _totalSupply this is an optional parameter. If 0, the toalSupply will be calculated dyamically. If not zero, this is  
     * going to be the locked value to calculate the rule 
     * @return ruleId position of new rule in array
     */
    function addTokenMaxSupplyVolatility(
        address _appManagerAddr,
        uint16 _maxPercentage,
        uint16 _period,
        uint64 _startTime,
        uint256 _totalSupply
    ) external ruleAdministratorOnly(_appManagerAddr) returns (uint32) {
        if (_maxPercentage == 0 || _period == 0) revert ZeroValueNotPermited();
        _startTime.validateTimestamp();
        RuleS.TokenMaxSupplyVolatilityS storage data = Storage.tokenMaxSupplyVolatilityStorage();
        NonTaggedRules.TokenMaxSupplyVolatility memory rule = NonTaggedRules.TokenMaxSupplyVolatility(_maxPercentage, _period, _startTime, _totalSupply);
        uint32 ruleId = data.tokenMaxSupplyVolatilityIndex;
        data.tokenMaxSupplyVolatilityRules[ruleId] = rule;
        emit AD1467_ProtocolRuleCreated(TOKEN_MAX_SUPPLY_VOLATILITY, ruleId, new bytes32[](0));
        ++data.tokenMaxSupplyVolatilityIndex;
        return ruleId;
    }

    /**
     * @dev Function add an Account Approve/Deny Oracle rule
     * @param _appManagerAddr Address of App Manager
     * @param _type type of Oracle Rule --> 0 = restricted; 1 = allowed
     * @param _oracleAddress Address of Oracle
     * @return ruleId position of rule in storage
     */
    function addAccountApproveDenyOracle(address _appManagerAddr, uint8 _type, address _oracleAddress) external ruleAdministratorOnly(_appManagerAddr) returns (uint32) {
        if (_appManagerAddr == address(0)) revert ZeroAddress();
        if (_oracleAddress == address(0)) revert ZeroAddress();
        if (_type > 1) revert InvalidOracleType(_type);
        RuleS.AccountApproveDenyOracleS storage data = Storage.accountApproveDenyOracleStorage();
        NonTaggedRules.AccountApproveDenyOracle memory rule = NonTaggedRules.AccountApproveDenyOracle(_type, _oracleAddress);
        uint32 ruleId = data.accountApproveDenyOracleIndex;
        data.accountApproveDenyOracleRules[ruleId] = rule;
        emit AD1467_ProtocolRuleCreated(ACCOUNT_APPROVE_DENY_ORACLE, ruleId, new bytes32[](0));
        ++data.accountApproveDenyOracleIndex;
        return ruleId;
    }

    /**
     * @dev Function add an Account Approve Deny Oracle Flexible rule
     * @param _appManagerAddr Address of App Manager
     * @param _type type of Oracle Rule --> 0 = restricted; 1 = allowed
     * @param _addressToggle toggle the address to be checked: 0 = Both to and from Address, 1 = to address only, 2 = from address only, 3 = Either to or from address.
     * @param _oracleAddress Address of Oracle
     * @return ruleId position of rule in storage
     */
    function addAccountApproveDenyOracleFlexible(address _appManagerAddr, uint8 _type, uint8 _addressToggle, address _oracleAddress) external ruleAdministratorOnly(_appManagerAddr) returns (uint32) {
        if (_appManagerAddr == address(0)) revert ZeroAddress();
        if (_oracleAddress == address(0)) revert ZeroAddress();
        if (_type > 1) revert InvalidOracleType(_type);
        if (_addressToggle > 3) revert InvalidRuleInput(); 
        RuleS.AccountApproveDenyOracleFlexibleS storage data = Storage.accountApproveDenyOracleFlexibleStorage();
        NonTaggedRules.AccountApproveDenyOracleFlexible memory rule = NonTaggedRules.AccountApproveDenyOracleFlexible(_type, _addressToggle, _oracleAddress);
        uint32 ruleId = data.accountApproveDenyOracleFlexibleIndex;
        data.accountApproveDenyOracleFlexibleRules[ruleId] = rule;
        emit AD1467_ProtocolRuleCreated(ACCOUNT_APPROVE_DENY_ORACLE_FLEXIBLE, ruleId, new bytes32[](0));
        ++data.accountApproveDenyOracleFlexibleIndex;
        return ruleId;
    }

    /**
     * @dev Function add an Min Hold Time rule
     * @param _appManagerAddr Address of App Manager
     * @param _minHoldtime minimum number of full hours a token must be held. 
     * @return ruleId position of rule in storage
     */
    function addTokenMinHoldTime(address _appManagerAddr, uint32 _minHoldtime) external ruleAdministratorOnly(_appManagerAddr) returns (uint32) {
        if (_appManagerAddr == address(0)) revert ZeroAddress();
        if (_minHoldtime == 0) revert ZeroValueNotPermited();
        if (_minHoldtime > 43830) revert PeriodExceeds5Years();
        RuleS.TokenMinHoldTimeS storage data = Storage.tokenMinHoldTimeStorage();
        NonTaggedRules.TokenMinHoldTime memory rule = NonTaggedRules.TokenMinHoldTime(_minHoldtime);
        uint32 ruleId = data.tokenMinHoldTimeIndex;
        data.tokenMinHoldTimeRules[ruleId] = rule;
        emit AD1467_ProtocolRuleCreated(TOKEN_MIN_HOLD_TIME, ruleId, new bytes32[](0));
        ++data.tokenMinHoldTimeIndex;
        return ruleId;
    }

}