// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "forge-std/console.sol";
import "src/protocol/economic/ruleProcessor/RuleProcessorDiamondImports.sol";
import "src/client/application/data/PauseRule.sol";
import "src/client/application/IAppManager.sol";
import {TaggedRuleDataFacet} from "src/protocol/economic/ruleProcessor/TaggedRuleDataFacet.sol";
import {RuleDataFacet} from "src/protocol/economic/ruleProcessor/RuleDataFacet.sol";
import {AppRuleDataFacet} from "src/protocol/economic/ruleProcessor/AppRuleDataFacet.sol";

/**
 * @title Rule Application Validation Facet Contract
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev Facet in charge of the logic to check rule existence
 * @notice Check that a rule in fact exists.
 */
contract RuleApplicationValidationFacet is ERC173 {
    using RuleProcessorCommonLib for uint32;

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAccountMinMaxTokenBalanceERC721(ActionTypes[] memory _actions, uint32 _ruleId) external view {
        _ruleId.checkRuleExistence(getTotalAccountMinMaxTokenBalance());
        require(areActionsEnabledInRule(ACCOUNT_MIN_MAX_TOKEN_BALANCE, _actions), "Action Validation Failed");
    }

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAccountMinMaxTokenBalance(ActionTypes[] memory _actions, uint32 _ruleId) external view {
        _ruleId.checkRuleExistence(getTotalAccountMinMaxTokenBalance());
        require(areActionsEnabledInRule(ACCOUNT_MIN_MAX_TOKEN_BALANCE, _actions), "Action Validation Failed");
    }

    /**
     * @dev Function gets total AccountMinMaxTokenBalance rules
     * @return Total length of array
     */
    function getTotalAccountMinMaxTokenBalance() internal view returns (uint32) {
        RuleS.AccountMinMaxTokenBalanceS storage data = Storage.accountMinMaxTokenBalanceStorage();
        return data.accountMinMaxTokenBalanceIndex;
    }

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateTokenMaxDailyTrades(ActionTypes[] memory _actions, uint32 _ruleId) external view {
        _ruleId.checkRuleExistence(getTotalTokenMaxDailyTradesRules());
        require(areActionsEnabledInRule(TOKEN_MAX_DAILY_TRADES, _actions), "Action Validation Failed");
    }

    /**
     * @dev Function gets total tokenMaxDailyTrades rules
     * @return Total length of array
     */
    function getTotalTokenMaxDailyTradesRules() internal view returns (uint32) {
        RuleS.TokenMaxDailyTradesS storage data = Storage.TokenMaxDailyTradesStorage();
        return data.tokenMaxDailyTradesIndex;
    }

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAccountMaxTradeSize(ActionTypes[] memory _actions, uint32 _ruleId) external view {
        _ruleId.checkRuleExistence(getTotalAccountMaxTradeSize());
        require(areActionsEnabledInRule(ACCOUNT_MAX_TRADE_SIZE, _actions), "Action Validation Failed");
    }

    /**
     * @dev Function to get total account max trade size rules
     * @return Total length of array
     */
    function getTotalAccountMaxTradeSize() internal view returns (uint32) {
        RuleS.AccountMaxTradeSizeS storage data = Storage.accountMaxTradeSizeStorage();
        return data.accountMaxTradeSizeIndex;
    }

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateTokenMinTxSize(ActionTypes[] memory _actions, uint32 _ruleId) external view {
        _ruleId.checkRuleExistence(getTotalTokenMinTxSize());
        require(areActionsEnabledInRule(TOKEN_MIN_TX_SIZE, _actions), "Action Validation Failed");
    }

    /**
     * @dev Function to get total Token Min Tx Size rules
     * @return Total length of array
     */
    function getTotalTokenMinTxSize() internal view returns (uint32) {
        RuleS.TokenMinTxSizeS storage data = Storage.tokenMinTxSizePosition();
        return data.tokenMinTxSizeIndex;
    }

    function validateTokenMinHoldTime(ActionTypes[] memory _actions, uint32 _ruleId) external view {
        _ruleId.checkRuleExistence(getTotalTokenMinHoldTime());
        require(areActionsEnabledInRule(TOKEN_MIN_HOLD_TIME, _actions), "Action Validation Failed");
    }

    function getTotalTokenMinHoldTime() internal view returns (uint32) {
        RuleS.TokenMinHoldTimeS storage data = Storage.tokenMinHoldTimeStorage();
        return data.tokenMinHoldTimeIndex;
    }

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAccountApproveDenyOracle(ActionTypes[] memory _actions, uint32 _ruleId) external view {
        _ruleId.checkRuleExistence(getTotalAccountApproveDenyOracle());
        require(areActionsEnabledInRule(ACCOUNT_APPROVE_DENY_ORACLE, _actions), "Action Validation Failed");
    }

    /**
     * @dev Function get total Account Approve Deny Oracle rules
     * @return total accountApproveDenyOracleRules array length
     */
    function getTotalAccountApproveDenyOracle() internal view returns (uint32) {
        RuleS.AccountApproveDenyOracleS storage data = Storage.accountApproveDenyOracleStorage();
        return data.accountApproveDenyOracleIndex;
    }

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAccountApproveDenyOracleFlexible(ActionTypes[] memory _actions, uint32 _ruleId) external view {
        _ruleId.checkRuleExistence(getTotalAccountApproveDenyOracleFlexible());
        require(areActionsEnabledInRule(ACCOUNT_APPROVE_DENY_ORACLE_FLEXIBLE, _actions), "Action Validation Failed");
    }

    /**
     * @dev Function get total Account Approve Deny Oracle Flexible rules
     * @return total accountApproveDenyOracleFlexibleRules array length
     */
    function getTotalAccountApproveDenyOracleFlexible() internal view returns (uint32) {
        RuleS.AccountApproveDenyOracleFlexibleS storage data = Storage.accountApproveDenyOracleFlexibleStorage();
        return data.accountApproveDenyOracleFlexibleIndex;
    }

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateTokenMaxBuySellVolume(ActionTypes[] memory _actions, uint32 _ruleId) external view {
        _ruleId.checkRuleExistence(getTotalTokenMaxBuySellVolume());
        require(areActionsEnabledInRule(TOKEN_MAX_BUY_SELL_VOLUME, _actions), "Action Validation Failed");
    }

    /**
     * @dev Function to get total Token Max Buy Sell Volume
     * @return Total length of array
     */
    function getTotalTokenMaxBuySellVolume() internal view returns (uint32) {
        RuleS.TokenMaxBuySellVolumeS storage data = Storage.accountMaxBuySellVolumeStorage();
        return data.tokenMaxBuySellVolumeIndex;
    }

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateTokenMaxTradingVolume(ActionTypes[] memory _actions, uint32 _ruleId) external view {
        _ruleId.checkRuleExistence(getTotalTokenMaxTradingVolume());
        require(areActionsEnabledInRule(TOKEN_MAX_TRADING_VOLUME, _actions), "Action Validation Failed");
    }

    /**
     * @dev Function to get total Token Max Trading Volume
     * @return Total length of array
     */
    function getTotalTokenMaxTradingVolume() internal view returns (uint32) {
        RuleS.TokenMaxTradingVolumeS storage data = Storage.tokenMaxTradingVolumeStorage();
        return data.tokenMaxTradingVolumeIndex;
    }

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateTokenMaxSupplyVolatility(ActionTypes[] memory _actions, uint32 _ruleId) external view {
        _ruleId.checkRuleExistence(getTotalTokenMaxSupplyVolatility());
        require(areActionsEnabledInRule(TOKEN_MAX_SUPPLY_VOLATILITY, _actions), "Action Validation Failed");
    }

    /**
     * @dev Function to get total Token Max Supply Volitility rules
     * @return tokenMaxSupplyVolatilityRules total length of array
     */
    function getTotalTokenMaxSupplyVolatility() internal view returns (uint32) {
        RuleS.TokenMaxSupplyVolatilityS storage data = Storage.tokenMaxSupplyVolatilityStorage();
        return data.tokenMaxSupplyVolatilityIndex;
    }

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAccountMaxValueByRiskScore(ActionTypes[] memory _actions, uint32 _ruleId) external view {
        _ruleId.checkRuleExistence(getTotalAccountMaxValueByRiskScore());
        require(areActionsEnabledInRule(ACC_MAX_VALUE_BY_RISK_SCORE, _actions), "Action Validation Failed");
    }

    /**
     * @dev Function to get total Account Max Value by Risk Score rules
     * @return Total length of array
     */
    function getTotalAccountMaxValueByRiskScore() internal view returns (uint32) {
        RuleS.AccountMaxValueByRiskScoreS storage data = Storage.accountMaxValueByRiskScoreStorage();
        return data.accountMaxValueByRiskScoreIndex;
    }

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAccountMaxTxValueByRiskScore(ActionTypes[] memory _actions, uint32 _ruleId) external view {
        _ruleId.checkRuleExistence(getTotalAccountMaxTxValueByRiskScore());
        require(areActionsEnabledInRule(ACC_MAX_TX_VALUE_BY_RISK_SCORE, _actions), "Action Validation Failed");
    }

    /**
     * @dev Function to get total Account Max Transaction Value by Risk rules
     * @return Total length of array
     */
    function getTotalAccountMaxTxValueByRiskScore() internal view returns (uint32) {
        RuleS.AccountMaxTxValueByRiskScoreS storage data = Storage.accountMaxTxValueByRiskScoreStorage();
        return data.accountMaxTxValueByRiskScoreIndex;
    }

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAccountMaxValueByAccessLevel(ActionTypes[] memory _actions, uint32 _ruleId) external view {
        _ruleId.checkRuleExistence(getTotalAccountMaxValueByAccessLevel());
        require(areActionsEnabledInRule(ACC_MAX_VALUE_BY_ACCESS_LEVEL, _actions), "Action Validation Failed");
    }

    /**
     * @dev Function to get total Account Max Value By Access Level rules
     * @return Total length of array
     */
    function getTotalAccountMaxValueByAccessLevel() internal view returns (uint32) {
        RuleS.AccountMaxValueByAccessLevelS storage data = Storage.accountMaxValueByAccessLevelStorage();
        return data.accountMaxValueByAccessLevelIndex;
    }

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAccountMaxValueOutByAccessLevel(ActionTypes[] memory _actions, uint32 _ruleId) external view {
        _ruleId.checkRuleExistence(getTotalAccountMaxValueOutByAccessLevel());
        require(areActionsEnabledInRule(ACC_MAX_VALUE_OUT_ACCESS_LEVEL, _actions), "Action Validation Failed");
    }

    /**
     * @dev Function to get total Account Max Value Out By Access Level rules
     * @return Total number of access level withdrawal rules
     */
    function getTotalAccountMaxValueOutByAccessLevel() internal view returns (uint32) {
        RuleS.AccountMaxValueOutByAccessLevelS storage data = Storage.accountMaxValueOutByAccessLevelStorage();
        return data.accountMaxValueOutByAccessLevelIndex;
    }

    /**
     * @dev Function to check if the action type is enabled for the rule 
     * @param _rule the bytes32 rule code pointer in storage 
     * @param _actions ActionTypes array to be checked if type is enabled 
     */
    function areActionsEnabledInRule(bytes32 _rule, ActionTypes[] memory _actions) public view returns (bool allEnabled) {
        allEnabled = true;
        RuleS.EnabledActions storage data = Storage.enabledActions();
        for (uint i; i < _actions.length; ++i) {
            if (!data.isActionEnabled[_rule][_actions[i]]) {
                allEnabled = false;
                break;
            }
        }
    }

    /**
     * @dev Function to enable the action type for the rule 
     * @param _rule the bytes32 rule code pointer in storage 
     * @param _actions ActionTypes array to be enabled 
     */
    function enabledActionsInRule(bytes32 _rule, ActionTypes[] memory _actions) external onlyOwner {
        RuleS.EnabledActions storage data = Storage.enabledActions();
        for (uint i; i < _actions.length; ++i) data.isActionEnabled[_rule][_actions[i]] = true;
    }

    /**
     * @dev Function to disable the action type for the rule 
     * @param _rule the bytes32 rule code pointer in storage 
     * @param _actions ActionTypes array to be disable 
     */
    function disableActionsInRule(bytes32 _rule, ActionTypes[] memory _actions) external onlyOwner {
        RuleS.EnabledActions storage data = Storage.enabledActions();
        for (uint i; i < _actions.length; ++i) data.isActionEnabled[_rule][_actions[i]] = false;
    }
}
