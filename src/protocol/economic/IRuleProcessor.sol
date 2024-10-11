// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/**
 * @title IRuleProcessor Interface
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev the light version of the Rule Processor for an efficient
 * import into the other contracts for calls to the checkAllRules function.
 * This is only used internally by the protocol.
 */

import {Rule} from "src/client/token/handler/common/DataStructures.sol";
import "src/common/ActionEnum.sol";

interface IRuleProcessor {
    /**
     * @dev Check the AccountMinMaxTokenBalance rule. This rule ensures that both the to and from accounts do not
     * exceed the max balance or go below the min balance.
     * @param ruleId Uint value of the ruleId storage pointer for applicable rule.
     * @param balanceFrom Token balance of the sender address
     * @param balanceTo Token balance of the recipient address
     * @param amount total number of tokens to be transferred
     * @param toTags tags applied via App Manager to recipient address
     * @param fromTags tags applied via App Manager to sender address
     */
    function checkAccountMinMaxTokenBalance(uint32 ruleId, uint256 balanceFrom, uint256 balanceTo, uint256 amount, bytes32[] calldata toTags, bytes32[] calldata fromTags) external view;

    /**
     * @dev Check the AccountMinTokenBalance half of the AccountMinMaxTokenBalance rule. This rule ensures that the from account does not
     * exceed the min balance.
     * @param ruleId Uint value of the ruleId storage pointer for applicable rule.
     * @param balanceFrom Token balance of the sender address
     * @param amount total number of tokens to be transferred
     * @param fromTags tags applied via App Manager to sender address
     */
    function checkAccountMinTokenBalance(uint256 balanceFrom, bytes32[] memory fromTags, uint256 amount, uint32 ruleId) external view;

    /**
     * @dev Check the AccountMaxTokenBalance half of the AccountMinMaxTokenBalance rule. This rule ensures that the to account does not
     * exceed the max balance.
     * @param ruleId Uint value of the ruleId storage pointer for applicable rule.
     * @param balanceTo Token balance of the recipient address
     * @param amount total number of tokens to be transferred
     * @param toTags tags applied via App Manager to recipient address
     */
    function checkAccountMaxTokenBalance(uint256 balanceTo, bytes32[] memory toTags, uint256 amount, uint32 ruleId) external view;


    /**
     * @dev Check the TokenMinTxSize rule. This rule ensures accounts cannot transfer less than
     * the specified amount.
     * @param ruleId Uint value of the ruleId storage pointer for applicable rule.
     * @param amount total number of tokens to be transferred
     */
    function checkTokenMinTxSize(uint32 ruleId, uint256 amount) external view;

    /**
     * @dev Check the MinMaxAccountBalanceERC721 rule. This rule ensures accounts cannot exceed or drop below specified account balances via account tags.
     * @param ruleId Uint value of the ruleId storage pointer for applicable rule.
     * @param balanceFrom Token balance of the sender address
     * @param balanceTo Token balance of the recipient address
     * @param toTags tags applied via App Manager to recipient address
     * @param fromTags tags applied via App Manager to sender address
     */
    function checkMinMaxAccountBalanceERC721(uint32 ruleId, uint256 balanceFrom, uint256 balanceTo, bytes32[] memory toTags, bytes32[] memory fromTags) external view;

    /**
     * @dev This function receives an array of rule ids, which it uses to get the oracle details, then calls the oracle to determine permissions.
     * @param _rules Rule Id Array
     * @param _address user address to be checked
     */
    function checkAccountApproveDenyOracles(Rule[] memory _rules, address _address) external view;

    /**
     * @dev This function receives an array of rule ids, which it uses to get the oracle details, then calls the oracle to determine permissions.
     * @param _rules Rule Id Array
     * @param _toAddress receiver address to be checked
     * @param _fromAddress sender address to be checked
     */
    function checkAccountApproveDenyOraclesFlexible(Rule[] memory _rules, address _toAddress, address _fromAddress) external view;

    /**
     * @dev Check if transaction passes Balance by AccessLevel rule.
     * @param _ruleId Rule Identifier for rule arguments
     * @param _accessLevel the Access Level of the account
     * @param _balance account's beginning balance
     * @param _amountToTransfer total number of tokens to be transferred
     */
    function checkBalanceByAccessLevelPasses(uint32 _ruleId, uint8 _accessLevel, uint256 _balance, uint256 _amountToTransfer) external view;

    /**
     * @dev Rule checks if recipient balance + amount exceeded max amount for that action type during rule period, prevent transactions for that action for freeze period
     * @param ruleId Rule identifier for rule arguments
     * @param transactedInPeriod Number of tokens transacted during Period
     * @param amount Number of tokens to be transferred
     * @param toTags Account tags applied to sender via App Manager
     * @param lastTransactionTime block.timestamp of most recent transaction transaction from sender for action type.
     * @return cumulativeTotal total amount of tokens bought or sold within Trade period.
     * @notice If the rule applies to all users, it checks blank tag only. Otherwise loop through
     * tags and check for specific application. This was done in a minimal way to allow for
     * modifications later while not duplicating rule check logic.
     */
    function checkAccountMaxTradeSize(uint32 ruleId, uint256 transactedInPeriod, uint256 amount, bytes32[] memory toTags, uint64 lastTransactionTime) external view returns (uint256);

    /**
     * @dev Check the minimum/maximum rule through the AMM Swap
     * @param ruleIdToken0 Uint value of the ruleId storage pointer for applicable rule.
     * @param ruleIdToken1 Uint value of the ruleId storage pointer for applicable rule.
     * @param tokenBalance0 Token balance of the token being swapped
     * @param tokenBalance1 Token balance of the received token
     * @param amountIn total number of tokens to be swapped
     * @param amountOut total number of tokens to be received
     * @param fromTags tags applied via App Manager to sender address
     */
    function checkAccountMinMaxTokenBalanceAMM(
        uint32 ruleIdToken0,
        uint32 ruleIdToken1,
        uint256 tokenBalance0,
        uint256 tokenBalance1,
        uint256 amountIn,
        uint256 amountOut,
        bytes32[] calldata fromTags
    ) external view;

    /**
     * @dev This function receives a rule id, which it uses to get the TokenMaxDailyTrades rule to check if the transfer is valid.
     * @param ruleId Rule identifier for rule arguments
     * @param transfersWithinPeriod Number of transfers within the time period
     * @param nftTags NFT tags applied
     * @param lastTransferTime block.timestamp of most recent transaction from sender.
     */
    function checkTokenMaxDailyTrades(uint32 ruleId, uint256 transfersWithinPeriod, bytes32[] calldata nftTags, uint64 lastTransferTime) external view returns (uint256);

    /**
     * @dev Assess the fee associated with the AMM Fee Rule
     * @param _ruleId Rule Identifier for rule arguments
     * @param _collateralizedTokenAmount total number of collateralized tokens to be swapped(this could be the "token in" or "token out" as the fees are always * assessed from the collateralized token)
     */
    function assessAMMFee(uint32 _ruleId, uint256 _collateralizedTokenAmount) external view returns (uint256);

    /// --------------------------- APPLICATION LEVEL --------------------------------

    /**
     * @dev This function checks if the requested action is valid according to the AccountMaxValueByRiskScore rule
     * @param _ruleId Rule Identifier
     * @param _toAddress Address of the recipient
     * @param _riskScoreTo the Risk Score of the recepient account
     * @param _totalValueTo recepient account's beginning balance in USD with 18 decimals of precision
     * @param _amountToTransfer total dollar amount to be transferred in USD with 18 decimals of precision
     */
    function checkAccountMaxValueByRiskScore(uint32 _ruleId, address _toAddress, uint8 _riskScoreTo, uint128 _totalValueTo, uint128 _amountToTransfer) external view;

    /**
     * @dev This function checks if the requested action is valid according to the AccountMaxValueByAccessLevel rule
     * @param _ruleId Rule Identifier
     * @param _accessLevelTo the Access Level of the recepient account
     * @param _totalValueTo recepient account's beginning balance in USD with 18 decimals of precision
     * @param _amountToTransfer total dollar amount to be transferred in USD with 18 decimals of precision
     */
    function checkAccountMaxValueByAccessLevel(uint32 _ruleId, uint8 _accessLevelTo, uint128 _totalValueTo, uint128 _amountToTransfer) external view;

    /**
     * @dev Rule that checks if the tx exceeds the limit size in USD for a specific risk profile
     * within a specified period of time.
     * @notice that these ranges are set by ranges.
     * @param ruleId to check against.
     * @param _valueTransactedInPeriod the cumulative amount of tokens recorded in the last period.
     * @param amount in USD of the current transaction with 18 decimals of precision.
     * @param lastTxDate timestamp of the last transfer of this token by this address.
     * @param riskScore of the address (0 -> 100)
     * @return updated value for the _valueTransactedInPeriod. If _valueTransactedInPeriod are
     * inside the current period, then this value is accumulated. If not, it is reset to current amount.
     * @dev this check will cause a revert if the new value of _valueTransactedInPeriod in USD exceeds
     * the limit for the address risk profile.
     */
    function checkAccountMaxTxValueByRiskScore(uint32 ruleId, uint128 _valueTransactedInPeriod, uint128 amount, uint64 lastTxDate, uint8 riskScore) external view returns (uint128);

    /**
     * @dev Function receives a rule id, retrieves the rule data and checks if the Token Max Buy Sell Volume Rule passes
     * @param ruleId id of the rule to be checked
     * @param currentTotalSupply total supply value passed in by the handler. This is for ERC20 tokens with a fixed total supply.
     * @param amountToTransfer total number of tokens to be transferred in transaction.
     * @param lastTransactionTime time of the most recent purchase from AMM. This starts the check if current transaction is within a purchase window.
     * @param totalWithinPeriod total amount of tokens sold within current period
     */
    function checkTokenMaxBuySellVolume(uint32 ruleId, uint256 currentTotalSupply, uint256 amountToTransfer, uint64 lastTransactionTime, uint256 totalWithinPeriod) external view returns (uint256);

    /**
     * @dev Ensure that AccountDenyForNoAccessLevel passes.
     * @param _accessLevel account access level
     *
     */
    function checkAccountDenyForNoAccessLevel(uint8 _accessLevel) external view;

    /**
     * @dev Rule that checks if the value out exceeds the limit size in USD for a specific access level
     * @notice that these ranges are set by ranges.
     * @param _ruleId to check against.
     * @param _accessLevel access level of the sending account
     * @param _withdrawal the amount, in USD, of previously withdrawn assets
     * @param _amountToTransfer total value of the transfer
     * @return Sending account's new total withdrawn.
     */
    function checkAccountMaxValueOutByAccessLevel(uint32 _ruleId, uint8 _accessLevel, uint128 _withdrawal, uint128 _amountToTransfer) external view returns (uint128);

    /**
     * @dev This function checks if the requested action is valid according to pause rules.
     * @param _dataServer address of the Application Rule Processor Diamond contract
     */
    function checkPauseRules(address _dataServer) external view;

    /**
     * @dev Rule checks if the token max trading volume rule will be violated.
     * @param _ruleId Rule identifier for rule arguments
     * @param _volume token's trading volume thus far
     * @param _amount Number of tokens to be transferred from this account
     * @param _supply Number of tokens in supply
     * @param _lastTransferTime the time of the last transfer
     * @return volumeTotal new accumulated volume
     */
    function checkTokenMaxTradingVolume(uint32 _ruleId, uint256 _volume, uint256 _supply, uint256 _amount, uint64 _lastTransferTime) external view returns (uint256);

    /**
     * @dev Rule checks if the tokenMaxSupplyVolatility rule will be violated.
     * @param _ruleId Rule identifier for rule arguments
     * @param _volumeTotalForPeriod token's increase/decreased volume total in period
     * @param _totalSupplyForPeriod token total supply updated at begining of period
     * @param _amount Number of tokens to be minted/burned
     * @param _supply Number of tokens in supply
     * @param _lastSupplyUpdateTime the time of the last transfer
     * @return volumeTotal new accumulated volume
     */
    function checkTokenMaxSupplyVolatility(
        uint32 _ruleId,
        int256 _volumeTotalForPeriod,
        uint256 _totalSupplyForPeriod,
        uint256 _supply,
        int256 _amount,
        uint64 _lastSupplyUpdateTime
    ) external view returns (int256, uint256);

    /**
     * @dev This function receives data needed to check Minimum hold time rule. This a simple rule and thus is not stored in the rule storage diamond.
     * @param _holdHours minimum number of hours the asset must be held
     * @param _ownershipTs beginning of hold period
     */
    function checkTokenMinHoldTime(uint32 _holdHours, uint256 _ownershipTs) external view;

    /* ---------------------------- Rule Validation Functions --------------------------------- */
    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAMMFee(ActionTypes[] memory _actions, uint32 _ruleId) external view;

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateTransactionLimitByRiskScore(ActionTypes[] memory _actions, uint32 _ruleId) external view;

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAccountMinMaxTokenBalanceERC721(ActionTypes[] memory _actions, uint32 _ruleId) external view;

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateTokenMaxDailyTrades(ActionTypes[] memory _actions, uint32 _ruleId) external view;

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAccountMinMaxTokenBalance(ActionTypes[] memory _actions, uint32 _ruleId) external view;

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAccountMaxTradeSize(ActionTypes[] memory _actions, uint32 _ruleId) external view;

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateTokenMinTxSize(ActionTypes[] memory _actions, uint32 _ruleId) external view;

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAccountApproveDenyOracle(ActionTypes[] memory _actions, uint32 _ruleId) external view;

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAccountApproveDenyOracleFlexible(ActionTypes[] memory _actions, uint32 _ruleId) external view;

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateTokenMaxBuySellVolume(ActionTypes[] memory _actions, uint32 _ruleId) external view;

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateTokenMaxTradingVolume(ActionTypes[] memory _actions, uint32 _ruleId) external view;

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateTokenMaxSupplyVolatility(ActionTypes[] memory _actions, uint32 _ruleId) external view;

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAccountMaxValueByRiskScore(ActionTypes[] memory _actions, uint32 _ruleId) external view;

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAccountMaxTxValueByRiskScore(ActionTypes[] memory _actions, uint32 _ruleId) external view;

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     * @param _dataServer address of the appManager contract
     */
    function validatePause(uint8[] memory _actions, uint32 _ruleId, address _dataServer) external view;

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAccountMaxValueByAccessLevel(ActionTypes[] memory _actions, uint32 _ruleId) external view;

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateAccountMaxValueOutByAccessLevel(ActionTypes[] memory _actions, uint32 _ruleId) external view;

    /**
     * @dev Validate the existence of the rule
     * @param _ruleId Rule Identifier
     */
    function validateTokenMinHoldTime(ActionTypes[] memory _actions, uint32 _ruleId) external view; 
}
