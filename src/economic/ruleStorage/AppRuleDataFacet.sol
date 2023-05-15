// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import {RuleStoragePositionLib as Storage} from "./RuleStoragePositionLib.sol";
import {IApplicationRules as AppRules} from "./RuleDataInterfaces.sol";
import {IRuleStorage as RuleS} from "./IRuleStorage.sol";
import {IEconomicEvents} from "../../interfaces/IEvents.sol";
import "../AppAdministratorOnly.sol";
import "./RuleCodeData.sol";

/**
 * @title App Rules Facet
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev Setters and getters for App Rules
 * @notice This contract sets and gets the App Rules for the protocol
 */

contract AppRuleDataFacet is Context, AppAdministratorOnly, IEconomicEvents {
    error IndexOutOfRange();
    error WrongArrayOrder();
    error InputArraysSizesNotValid();
    error InvalidHourOfTheDay();
    error BalanceAmountsShouldHave5Levels(uint8 inputLevels);
    error RiskLevelCannotExceed99();

    //*********************** AccessLevel Rule ********************************************** */
    /**
     * @dev Function add a AccessLevel Balance rule
     * @dev Function has AppAdministratorOnly Modifier and takes AppManager Address Param
     * @param _appManagerAddr Address of App Manager
     * @param _balanceAmounts Balance restrictions for each 5 levels from level 0 to 4 in whole USD.
     * @notice that position within the array matters. Posotion 0 represents access levellevel 0,
     * and position 4 represents level 4.
     * @return position of new rule in array
     */
    function addAccessLevelBalanceRule(address _appManagerAddr, uint48[] calldata _balanceAmounts) external appAdministratorOnly(_appManagerAddr) returns (uint32) {
        RuleS.AccessLevelRuleS storage data = Storage.accessStorage();
        uint32 index = data.accessRuleIndex;
        if (_balanceAmounts.length != 5) revert BalanceAmountsShouldHave5Levels(uint8(_balanceAmounts.length));
        for (uint i = 1; i < _balanceAmounts.length; ) {
            if (_balanceAmounts[i] < _balanceAmounts[i - 1]) revert WrongArrayOrder();
            unchecked {
                ++i;
            }
        }
        for (uint8 i; i < _balanceAmounts.length; ) {
            data.accessRulesPerToken[index][i] = _balanceAmounts[i];
            unchecked {
                ++i;
            }
        }
        ++data.accessRuleIndex;
        emit ProtocolRuleCreated(BALANCE_BY_AccessLevel, index);
        return index;
    }

    /**
     * @dev Function to get the AccessLevel Balance rule in the rule set that belongs to an AccessLevel Level
     * @param _index position of rule in array
     * @param _accessLevel AccessLevel Level to check
     * @return balanceAmount balance allowed for access levellevel
     */
    function getAccessLevelBalanceRule(uint32 _index, uint8 _accessLevel) external view returns (uint48) {
        RuleS.AccessLevelRuleS storage data = Storage.accessStorage();
        if (_index >= data.accessRuleIndex) revert IndexOutOfRange();
        return data.accessRulesPerToken[_index][_accessLevel];
    }

    /**
     * @dev Function to get total AccessLevel Balance rules
     * @return Total length of array
     */
    function getTotalAccessLevelBalanceRules() external view returns (uint32) {
        RuleS.AccessLevelRuleS storage data = Storage.accessStorage();
        return data.accessRuleIndex;
    }

    //***********************  Risk Rules  ******************************* */

    //***********************  Max Tx Size Per Period By Risk Rule  ******************************* */
    /**
     * @dev Function add a Max Tx Size Per Period By Risk rule
     * @dev Function has AppAdministratorOnly Modifier and takes AppManager Address Param
     * @param _appManagerAddr Address of App Manager
     * @param _maxSize array of max-tx-size allowed within period (whole USD max values --no cents)
     * Each value in the array represents max USD value transacted within _period, and its positions
     * indicate what range of risk levels it applies to. A value of 1000 here means $1000.00 USD.
     * @param _riskLevel array of risk-level ceilings that define each range. Risk levels are inclusive.
     * @param _period amount of hours that each period lasts for.
     * @param _startingTime between 00 and 23 representing the time of the day that the
     * rule starts taking effect. The rule will always start in a date in the past.
     * @return position of new rule in array
     * @notice _maxSize size must be equal to _riskLevel + 1 since the _maxSize must
     * specify the maximum tx size for anything between the highest risk score and 100
     * which should be specified in the last position of the _riskLevel. This also
     * means that the positioning of the arrays is ascendant in terms of risk levels, and
     * descendant in the size of transactions. (i.e. if highest risk level is 99, the last balanceLimit
     * will apply to all risk scores of 100.)
     */
    function addMaxTxSizePerPeriodByRiskRule(
        address _appManagerAddr,
        uint48[] calldata _maxSize,
        uint8[] calldata _riskLevel,
        uint8 _period,
        uint8 _startingTime
    ) external appAdministratorOnly(_appManagerAddr) returns (uint32) {
        /// Validation block
        if (_maxSize.length != _riskLevel.length + 1) revert InputArraysSizesNotValid();
        if (_riskLevel[_riskLevel.length - 1] > 99) revert RiskLevelCannotExceed99();
        for (uint256 i = 1; i < _riskLevel.length; ) {
            if (_riskLevel[i] <= _riskLevel[i - 1]) revert WrongArrayOrder();
            unchecked {
                ++i;
            }
        }
        for (uint256 i = 1; i < _maxSize.length; ) {
            if (_maxSize[i] > _maxSize[i - 1]) revert WrongArrayOrder();
            unchecked {
                ++i;
            }
        }
        if (_startingTime > 23) revert InvalidHourOfTheDay();

        /// before creating the rule, we convert the starting time from hour of the day to timestamp date
        uint64 startingDate = uint64(block.timestamp - (block.timestamp % (1 days)) - 1 days + uint256(_startingTime) * (1 hours));

        /// We create the rule now
        RuleS.TxSizePerPeriodToRiskRuleS storage data = Storage.txSizePerPeriodToRiskStorage();
        uint32 ruleId = data.txSizePerPeriodToRiskRuleIndex;
        AppRules.TxSizePerPeriodToRiskRule memory rule = AppRules.TxSizePerPeriodToRiskRule(_maxSize, _riskLevel, _period, startingDate);
        data.txSizePerPeriodToRiskRule[ruleId] = rule;
        ++data.txSizePerPeriodToRiskRuleIndex;
        emit ProtocolRuleCreated(MAX_TX_PER_PERIOD, ruleId);
        return ruleId;
    }

    /**
     * @dev Function to get the Max Tx Size Per Period By Risk rule.
     * @param _index position of rule in array
     * @return a touple of arrays, a uint8 and a uint64. The first array will be the _maxSize, the second
     * will be the _riskLevel, the uint8 will be the period, and the last value will be the starting date.
     */
    function getMaxTxSizePerPeriodRule(uint32 _index) external view returns (AppRules.TxSizePerPeriodToRiskRule memory) {
        RuleS.TxSizePerPeriodToRiskRuleS storage data = Storage.txSizePerPeriodToRiskStorage();
        if (_index >= data.txSizePerPeriodToRiskRuleIndex) revert IndexOutOfRange();
        return data.txSizePerPeriodToRiskRule[_index];
    }

    /**
     * @dev Function to get total Max Tx Size Per Period By Risk rules
     * @return Total length of array
     */
    function getTotalMaxTxSizePerPeriodRules() external view returns (uint32) {
        RuleS.TxSizePerPeriodToRiskRuleS storage data = Storage.txSizePerPeriodToRiskStorage();
        return data.txSizePerPeriodToRiskRuleIndex;
    }

    /**
     * @dev Function to add new AccountBalanceByRiskScore Rules
     * @dev Function has AppAdministratorOnly Modifier and takes AppManager Address Param
     * @param _appManagerAddr Address of App Manager
     * @param _riskScores User Risk Level Array
     * @param _balanceLimits Account Balance Limit in whole USD for each score range. It corresponds to the _riskScores
     * array and is +1 longer than _riskScores. A value of 1000 in this arrays will be interpreted as $1000.00 USD.
     * @return position of new rule in array
     * @notice _maxSize size must be equal to _riskLevel + 1 since the _maxSize must
     * specify the maximum tx size for anything between the highest risk score and 100
     * which should be specified in the last position of the _riskLevel. This also
     * means that the positioning of the arrays is ascendant in terms of risk levels, and
     * descendant in the size of transactions. (i.e. if highest risk level is 99, the last balanceLimit
     * will apply to all risk scores of 100.)
     */
    function addAccountBalanceByRiskScore(address _appManagerAddr, uint8[] calldata _riskScores, uint48[] calldata _balanceLimits) external appAdministratorOnly(_appManagerAddr) returns (uint32) {
        if (_balanceLimits.length != _riskScores.length + 1) revert InputArraysSizesNotValid();
        if (_riskScores[_riskScores.length - 1] > 99) revert RiskLevelCannotExceed99();
        for (uint i = 1; i < _riskScores.length; ) {
            if (_riskScores[i] <= _riskScores[i - 1]) revert WrongArrayOrder();
            unchecked {
                ++i;
            }
        }
        for (uint i = 1; i < _balanceLimits.length; ) {
            if (_balanceLimits[i] > _balanceLimits[i - 1]) revert WrongArrayOrder();
            unchecked {
                ++i;
            }
        }
        return _addAccountBalanceByRiskScore(_riskScores, _balanceLimits);
    }

    /**
     * @dev internal Function to avoid stack too deep error
     * @param _riskScores Account Risk Level
     * @param _balanceLimits Account Balance Limit for each Score in USD (no cents). It corresponds to the _riskScores array.
     * A value of 1000 in this arrays will be interpreted as $1000.00 USD.
     * @return position of new rule in array
     */
    function _addAccountBalanceByRiskScore(uint8[] calldata _riskScores, uint48[] calldata _balanceLimits) internal returns (uint32) {
        RuleS.AccountBalanceToRiskRuleS storage data = Storage.accountBalanceToRiskStorage();
        uint32 ruleId = data.balanceToRiskRuleIndex;
        AppRules.AccountBalanceToRiskRule memory rule = AppRules.AccountBalanceToRiskRule(_riskScores, _balanceLimits);
        data.balanceToRiskRule[ruleId] = rule;
        ++data.balanceToRiskRuleIndex;
        emit ProtocolRuleCreated(BALANCE_BY_RISK, ruleId);
        return ruleId;
    }

    /**
     * @dev Function to get the TransactionLimit in the rule set that belongs to an risk score
     * @param _index position of rule in array
     * @return balanceAmount balance allowed for access levellevel
     */
    function getAccountBalanceByRiskScore(uint32 _index) external view returns (AppRules.AccountBalanceToRiskRule memory) {
        RuleS.AccountBalanceToRiskRuleS storage data = Storage.accountBalanceToRiskStorage();
        if (_index >= data.balanceToRiskRuleIndex) revert IndexOutOfRange();
        return data.balanceToRiskRule[_index];
    }

    /**
     * @dev Function to get total Transaction Limit by Risk Score rules
     * @return Total length of array
     */
    function getTotalAccountBalanceByRiskScoreRules() external view returns (uint32) {
        RuleS.AccountBalanceToRiskRuleS storage data = Storage.accountBalanceToRiskStorage();
        return data.balanceToRiskRuleIndex;
    }
}
