// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/protocol/economic/ruleProcessor/RuleProcessorDiamondImports.sol";
import "src/protocol/economic/RuleAdministratorOnly.sol";

/**
 * @title Application Rules Storage Facet
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev Setters and getters for Application level Rules
 * @notice This contract sets and gets the App Rules for the protocol
 */

contract AppRuleDataFacet is Context, RuleAdministratorOnly, IEconomicEvents, IInputErrors, IAppRuleInputErrors, IRiskInputErrors {
    using RuleProcessorCommonLib for uint64;
    using RuleProcessorCommonLib for uint32;
    using RuleProcessorCommonLib for uint8;
    uint8 constant MAX_ACCESSLEVELS = 5;
    uint8 constant MAX_RISKSCORE = 99;

    //*********************** AccessLevel Rules ********************************************** */
    /**
     * @dev Function add an Account Max Value By Access Level rule
     * @dev Function has RuleAdministratorOnly Modifier and takes AppManager Address Param
     * @param _appManagerAddr Address of App Manager
     * @param _maxValues Balance restrictions for each 5 levels from level 0 to 4 in whole USD.
     * @notice The position within the array matters. Position 0 represents access level 0,
     * and position 4 represents level 4.
     * @return position of new rule in array
     */
    function addAccountMaxValueByAccessLevel(address _appManagerAddr, uint48[] calldata _maxValues) external ruleAdministratorOnly(_appManagerAddr) returns (uint32) {
        RuleS.AccountMaxValueByAccessLevelS storage data = Storage.accountMaxValueByAccessLevelStorage();
        uint32 index = data.accountMaxValueByAccessLevelIndex;
        if (_maxValues.length != MAX_ACCESSLEVELS) revert AccessLevelRulesShouldHave5Levels(uint8(_maxValues.length));
        uint256 length = _maxValues.length;
        for (uint256 i = 1; i < length; ++i) {
            if (_maxValues[i] < _maxValues[i - 1]) revert WrongArrayOrder();
        }
        for (uint8 i; i < length; ++i) {
            data.accountMaxValueByAccessLevelRules[index][i] = _maxValues[i];
        }
        ++data.accountMaxValueByAccessLevelIndex;
        emit AD1467_ProtocolRuleCreated(ACC_MAX_VALUE_BY_ACCESS_LEVEL, index, new bytes32[](0));
        return index;
    }

    /**
     * @dev Function add an Account Max Value Out By Access Level rule
     * @dev Function has ruleAdministratorOnly Modifier and takes AppManager Address Param
     * @param _appManagerAddr Address of App Manager
     * @param _withdrawalAmounts withdrawal amount restrictions for each 5 levels from level 0 to 4 in whole USD.
     * @notice The position within the array matters. Position 0 represents access level 0,
     * and position 4 represents level 4.
     * @return position of new rule in array
     */
    function addAccountMaxValueOutByAccessLevel(address _appManagerAddr, uint48[] calldata _withdrawalAmounts) external ruleAdministratorOnly(_appManagerAddr) returns (uint32) {
        RuleS.AccountMaxValueOutByAccessLevelS storage data = Storage.accountMaxValueOutByAccessLevelStorage();
        uint32 index = data.accountMaxValueOutByAccessLevelIndex;
        if (_withdrawalAmounts.length != MAX_ACCESSLEVELS) revert AccessLevelRulesShouldHave5Levels(uint8(_withdrawalAmounts.length));
        uint256 length = _withdrawalAmounts.length;
        for (uint256 i = 1; i < length; ++i) {
            if (_withdrawalAmounts[i] < _withdrawalAmounts[i - 1]) revert WrongArrayOrder();
        }
        for (uint8 i; i < length; ++i) {
            data.accountMaxValueOutByAccessLevelRules[index][i] = _withdrawalAmounts[i];
        }
        ++data.accountMaxValueOutByAccessLevelIndex;
        emit AD1467_ProtocolRuleCreated(ACC_MAX_VALUE_OUT_ACCESS_LEVEL, index, new bytes32[](0));
        return index;
    }

    //***********************  Risk Rules  ******************************* */

    //***********************  Max Tx Size Per Period By Risk Rule  ******************************* */
    /**
     * @dev Function add an Account Max Transaction Value By Risk Score rule
     * @dev Function has ruleAdministratorOnly Modifier and takes AppManager Address Param
     * @param _appManagerAddr Address of App Manager
     * @param _maxValue array of max-tx-size allowed within period (whole USD max values --no cents)
     * Each value in the array represents max USD value transacted within _period, and its positions
     * indicate what range of risk scores it applies to. A value of 1000 here means $1000.00 USD.
     * @param _riskScore array of risk score ceilings that define each range. Risk scores are inclusive.
     * @param _period amount of hours that each period lasts for. 0 if no period is desired.
     * @param _startTime start timestamp for the rule
     * @return position of new rule in array
     * @notice _maxValue size must be equal to _riskScore.
     * This means that the positioning of the arrays is ascendant in terms of risk scores,
     * and descendant in the size of transactions. (i.e. if highest risk scores is 99, the last balanceLimit
     * will apply to all risk scores of 100.)
     * eg.
     * risk scores      balances         resultant logic
     * -----------      --------         ---------------
     *                                   0-24  =   NO LIMIT
     *    25              500            25-49 =   500
     *    50              250            50-74 =   250
     *    75              100            75-99 =   100
     */
    function addAccountMaxTxValueByRiskScore(
        address _appManagerAddr,
        uint48[] calldata _maxValue,
        uint8[] calldata _riskScore,
        uint16 _period,
        uint64 _startTime
    ) external ruleAdministratorOnly(_appManagerAddr) returns (uint32) {
        if (_maxValue.length != _riskScore.length) revert InputArraysSizesNotValid();
        // since all the arrays must have matching lengths, it is only necessary to check for one of them being empty.
        if (_maxValue.length == 0) revert InvalidRuleInput();
        if (_riskScore[_riskScore.length - 1] > MAX_RISKSCORE) revert RiskLevelCannotExceed99();
        uint256 length = _maxValue.length;
        for (uint256 i = 1; i < length; ++i) {
            if (_riskScore[i] <= _riskScore[i - 1]) revert WrongArrayOrder();
            if (_maxValue[i] > _maxValue[i - 1]) revert WrongArrayOrder();
        }
        _startTime.validateTimestamp();
        RuleS.AccountMaxTxValueByRiskScoreS storage data = Storage.accountMaxTxValueByRiskScoreStorage();
        uint32 ruleId = data.accountMaxTxValueByRiskScoreIndex;
        ApplicationRuleStorage.AccountMaxTxValueByRiskScore memory rule = ApplicationRuleStorage.AccountMaxTxValueByRiskScore(_maxValue, _riskScore, _period, _startTime);
        data.accountMaxTxValueByRiskScoreRules[ruleId] = rule;
        ++data.accountMaxTxValueByRiskScoreIndex;
        emit AD1467_ProtocolRuleCreated(ACC_MAX_TX_VALUE_BY_RISK_SCORE, ruleId, new bytes32[](0));
        return ruleId;
    }

    /**
     * @dev Function to add new AccountMaxValueByRiskScore Rules
     * @dev Function has ruleAdministratorOnly Modifier and takes AppManager Address Param
     * @param _appManagerAddr Address of App Manager
     * @param _riskScores User Risk Score Array
     * @param _maxValue Account Max Value Limit in whole USD for each score range. It corresponds to the _riskScores
     * array. A value of 1000 in this arrays will be interpreted as $1000.00 USD.
     * @return position of new rule in array
     * @notice _maxValue size must be equal to _riskScore.
     * The positioning of the arrays is ascendant in terms of risk score,
     * and descendant in the size of transactions. (i.e. if highest risk score is 99, the last balanceLimit
     * will apply to all risk scores of 100.)
     * eg.
     * risk scores      balances         resultant logic
     * -----------      --------         ---------------
     *                                   0-24  =   NO LIMIT
     *    25              500            25-49 =   500
     *    50              250            50-74 =   250
     *    75              100            75-99 =   100
     */
    function addAccountMaxValueByRiskScore(address _appManagerAddr, uint8[] calldata _riskScores, uint48[] calldata _maxValue) external ruleAdministratorOnly(_appManagerAddr) returns (uint32) {
        if (_maxValue.length != _riskScores.length) revert InputArraysSizesNotValid();
        if (_maxValue.length == 0) revert InvalidRuleInput();
        if (_riskScores[_riskScores.length - 1] > MAX_RISKSCORE) revert RiskLevelCannotExceed99();
        uint256 length = _maxValue.length;
        for (uint256 i = 1; i < length; ++i) {
            if (_riskScores[i] <= _riskScores[i - 1]) revert WrongArrayOrder();
            if (_maxValue[i] > _maxValue[i - 1]) revert WrongArrayOrder();
        }
        return _addAccountMaxValueByRiskScore(_riskScores, _maxValue);
    }

    /**
     * @dev Internal Function to avoid stack too deep error
     * @param _riskScores Account Risk Score
     * @param _maxValue Account Max Value Limit for each Score in USD (no cents). It corresponds to the _riskScores array.
     * A value of 1000 in this arrays will be interpreted as $1000.00 USD.
     * @return position of new rule in array
     */
    function _addAccountMaxValueByRiskScore(uint8[] calldata _riskScores, uint48[] calldata _maxValue) internal returns (uint32) {
        RuleS.AccountMaxValueByRiskScoreS storage data = Storage.accountMaxValueByRiskScoreStorage();
        uint32 ruleId = data.accountMaxValueByRiskScoreIndex;
        ApplicationRuleStorage.AccountMaxValueByRiskScore memory rule = ApplicationRuleStorage.AccountMaxValueByRiskScore(_riskScores, _maxValue);
        data.accountMaxValueByRiskScoreRules[ruleId] = rule;
        ++data.accountMaxValueByRiskScoreIndex;
        emit AD1467_ProtocolRuleCreated(ACC_MAX_VALUE_BY_RISK_SCORE, ruleId, new bytes32[](0));
        return ruleId;
    }

    /**
     * @dev Function add an Account Max Received By Access Level rule
     * @dev Function has ruleAdministratorOnly Modifier and takes AppManager Address Param
     * @param _appManagerAddr Address of App Manager
     * @param _receivedAmounts received amounts allowed for each 5 levels from level 0 to 4 in whole USD.
     * @notice The position within the array matters. Position 0 represents access level 0,
     * and position 4 represents level 4.
     * @return position of new rule in array
     */
    function addAccountMaxReceivedByAccessLevel(address _appManagerAddr, uint48[] calldata _receivedAmounts, address _fromAddress) external ruleAdministratorOnly(_appManagerAddr) returns (uint32) {
        RuleS.AccountMaxReceivedByAccessLevelS storage data = Storage.accountMaxReceivedByAccessLevelStorage();
        uint32 index = data.accountMaxReceivedByAccessLevelIndex;
        if (_receivedAmounts.length != MAX_ACCESSLEVELS) revert AccessLevelRulesShouldHave5Levels(uint8(_receivedAmounts.length));
        uint256 length = _receivedAmounts.length;
        for (uint256 i = 1; i < length; ++i) {
            if (_receivedAmounts[i] < _receivedAmounts[i - 1]) revert WrongArrayOrder();
        }
        for (uint8 i; i < length; ++i) {
            data.accountMaxReceivedByAccessLevelRules[index].accountMaxReceivedLimits[i] = _receivedAmounts[i];
        }
        data.accountMaxReceivedByAccessLevelRules[index].sender = _fromAddress;
        ++data.accountMaxReceivedByAccessLevelIndex;
        emit AD1467_ProtocolRuleCreated(ACC_MAX_RECEIVED_ACCESS_LEVEL, index, new bytes32[](0));
        return index;
    }

}
