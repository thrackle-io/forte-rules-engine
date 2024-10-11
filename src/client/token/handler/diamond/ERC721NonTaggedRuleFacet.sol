// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {StorageLib as lib} from "src/client/token/handler/diamond/StorageLib.sol";
import "src/protocol/economic/IRuleProcessor.sol";
import "src/client/token/handler/common/HandlerUtils.sol";
import {Rule} from "src/client/token/handler/common/DataStructures.sol";
import {ActionTypes} from "src/common/ActionEnum.sol";
import "src/client/application/IAppManager.sol";
import "src/client/token/handler/diamond/RuleStorage.sol";
import "src/client/token/ITokenInterface.sol";
import "src/client/token/handler/common/AppAdministratorOrOwnerOnlyDiamondVersion.sol";
import "src/client/token/handler/ruleContracts/HandlerAccountApproveDenyOracle.sol";
import "src/client/token/handler/ruleContracts/HandlerAccountApproveDenyOracleFlexible.sol";
import "src/client/token/handler/ruleContracts/HandlerTokenMaxSupplyVolatility.sol";
import "src/client/token/handler/ruleContracts/HandlerTokenMaxTradingVolume.sol";
import "src/client/token/handler/ruleContracts/HandlerTokenMinTxSize.sol";
import "src/client/token/handler/ruleContracts/HandlerTokenMinHoldTime.sol";
import "src/client/token/handler/ruleContracts/HandlerTokenMaxDailyTrades.sol";

contract ERC721NonTaggedRuleFacet is
    AppAdministratorOrOwnerOnlyDiamondVersion,
    HandlerAccountApproveDenyOracle,
    HandlerAccountApproveDenyOracleFlexible,
    HandlerUtils,
    HandlerTokenMaxSupplyVolatility,
    HandlerTokenMaxTradingVolume,
    HandlerTokenMinTxSize,
    HandlerTokenMinHoldTime,
    HandlerTokenMaxDailyTrades
{
    /**
     * @dev This function uses the protocol's ruleProcessorto perform the actual rule checks.
     * @param action if selling or buying (of ActionTypes type)
     * @param _from address of the from account
     * @param _to address of the to account
     * @param _sender address of the caller 
     * @param _amount number of tokens transferred
     * @param _tokenId id of the NFT being transferred
     */
    function checkNonTaggedRules(ActionTypes action, address _from, address _to, address _sender, uint256 _amount, uint256 _tokenId) external onlyOwner {
        _from;
        HandlerBaseS storage handlerBaseStorage = lib.handlerBaseStorage();
        address handlerBase = handlerBaseStorage.ruleProcessor;
        _checkAccountApproveDenyOraclesRule(_from, _to, _sender, action, handlerBase);
        _checkAccountApproveDenyOraclesFlexibleRule(_from, _to, action, handlerBase);

        if (action == ActionTypes.BURN){
            /// tokenMaxTradingVolume Burn 
            if (lib.tokenMaxTradingVolumeStorage().tokenMaxTradingVolume[action]) _checkTokenMaxTradingVolumeRule(_amount, handlerBase);
            /// tokenMinTxSize Burn
            if (lib.tokenMinTxSizeStorage().tokenMinTxSize[action].active) _checkTokenMinTxSizeRule(_amount, action, handlerBase);
            /// tokenMaxDailyTrades BURN
            if (lib.tokenMaxDailyTradesStorage().tokenMaxDailyTrades[action].active) _checkTokenMaxDailyTradesRule(action, _tokenId);

        } else if (action == ActionTypes.MINT){
            /// tokenMaxTradingVolume Mint 
            if (lib.tokenMaxTradingVolumeStorage().tokenMaxTradingVolume[action]) _checkTokenMaxTradingVolumeRule(_amount, handlerBase);
            /// tokenMinTxSize Mint 
            if (lib.tokenMinTxSizeStorage().tokenMinTxSize[action].active) _checkTokenMinTxSizeRule(_amount, action, handlerBase);
            /// tokenMaxDailyTrades MINT
            if (lib.tokenMaxDailyTradesStorage().tokenMaxDailyTrades[action].active) _checkTokenMaxDailyTradesRule(action, _tokenId);

        } else if (action == ActionTypes.P2P_TRANSFER){
            /// tokenMaxTradingVolume P2P_TRANSFER 
            if (lib.tokenMaxTradingVolumeStorage().tokenMaxTradingVolume[action]) _checkTokenMaxTradingVolumeRule(_amount, handlerBase);
            /// tokenMinTxSize P2P_TRANSFER
            if (lib.tokenMinTxSizeStorage().tokenMinTxSize[action].active) _checkTokenMinTxSizeRule(_amount, action, handlerBase);
            /// tokenMaxDailyTrades P2P_TRANSFER
            if (lib.tokenMaxDailyTradesStorage().tokenMaxDailyTrades[action].active) _checkTokenMaxDailyTradesRule(action, _tokenId);

        } else if (action == ActionTypes.BUY){
            if (_from != _sender){ /// non custodial buy 
                /// tokenMaxTradingVolume BUY 
                /// tokenMaxTradingVolume uses single rule id for all actions so check if Buy has rule id set ELSE check if sell has ruleId set 
                if (lib.tokenMaxTradingVolumeStorage().tokenMaxTradingVolume[action]) {
                    _checkTokenMaxTradingVolumeRule(_amount, handlerBase);
                /// else if conditional used for tokenMaxTrading as there is only one ruleId used for this rule 
                } else if (lib.tokenMaxTradingVolumeStorage().tokenMaxTradingVolume[ActionTypes.SELL]) {
                    _checkTokenMaxTradingVolumeRule(_amount, handlerBase);
                }
                /// tokenMinTxSize SELL Side 
                if (lib.tokenMinTxSizeStorage().tokenMinTxSize[ActionTypes.SELL].active) _checkTokenMinTxSizeRule(_amount, action, handlerBase);
                /// tokenMaxDailyTrades SELL Side
                if (lib.tokenMaxDailyTradesStorage().tokenMaxDailyTrades[ActionTypes.SELL].active) _checkTokenMaxDailyTradesRule(action, _tokenId);
            } else { /// custodial buy 
                if (lib.tokenMaxTradingVolumeStorage().tokenMaxTradingVolume[action]) {
                    _checkTokenMaxTradingVolumeRule(_amount, handlerBase);
                }
            }
            /// tokenMinTxSize BUY
            if (lib.tokenMinTxSizeStorage().tokenMinTxSize[action].active) _checkTokenMinTxSizeRule(_amount, action, handlerBase);
            /// tokenMaxDailyTrades BUY
            if (lib.tokenMaxDailyTradesStorage().tokenMaxDailyTrades[action].active) _checkTokenMaxDailyTradesRule(action, _tokenId);
        } else if (action == ActionTypes.SELL){
            if (_to != _sender){ /// non custodial sell 
                /// tokenMaxTradingVolume SELL 
                /// tokenMaxTradingVolume uses single rule id for all actions so check if Sell has rule id set ELSE check if sell has ruleId set 
                if (lib.tokenMaxTradingVolumeStorage().tokenMaxTradingVolume[action]) {
                    _checkTokenMaxTradingVolumeRule(_amount, handlerBase);
                /// else if conditional used for tokenMaxTrading as there is only one ruleId used for this rule  
                } else if (lib.tokenMaxTradingVolumeStorage().tokenMaxTradingVolume[ActionTypes.BUY]) {
                    _checkTokenMaxTradingVolumeRule(_amount, handlerBase);
                }
            /// tokenMinTxSize BUY Side 
            if (lib.tokenMinTxSizeStorage().tokenMinTxSize[ActionTypes.BUY].active) _checkTokenMinTxSizeRule(_amount, action, handlerBase);
            /// tokenMaxDailyTrades BUY Side
            if (lib.tokenMaxDailyTradesStorage().tokenMaxDailyTrades[ActionTypes.BUY].active) _checkTokenMaxDailyTradesRule(action, _tokenId);
            } else { /// custodial sell 
                /// tokenMaxTradingVolume SELL 
                if (lib.tokenMaxTradingVolumeStorage().tokenMaxTradingVolume[action]) {
                    _checkTokenMaxTradingVolumeRule(_amount, handlerBase);
                }
            }
            /// tokenMinTxSize SELL
            if (lib.tokenMinTxSizeStorage().tokenMinTxSize[action].active) _checkTokenMinTxSizeRule(_amount, action, handlerBase);
            /// tokenMaxDailyTrades SELL
            if (lib.tokenMaxDailyTradesStorage().tokenMaxDailyTrades[action].active) _checkTokenMaxDailyTradesRule(action, _tokenId);
        }

        if (lib.tokenMaxSupplyVolatilityStorage().tokenMaxSupplyVolatility[action] && (_from == address(0x00) || _to == address(0x00))) {
            _checkTokenMaxSupplyVolatilityRule(_to, _amount, handlerBase);
        }
        _checkMinHoldTimeRules(action, _tokenId, handlerBase, _from, _to, _sender);
    }

    /**
     * @dev Internal function to check the Token Min Transaction Size rule 
     * @param _amount number of tokens transferred
     * @param action if selling or buying (of ActionTypes type)
     * @param handlerBase address of the handler proxy
     */
    function _checkTokenMinTxSizeRule(uint256 _amount, ActionTypes action, address handlerBase) internal view {
        IRuleProcessor(handlerBase).checkTokenMinTxSize(lib.tokenMinTxSizeStorage().tokenMinTxSize[action].ruleId, _amount);
    }

    /**
     * @dev Internal function to check the Account Approve Deny Oracle Rules 
     * @param _from address of the from account
     * @param _to address of the to account
     * @param _sender address of the caller 
     * @param action if selling or buying (of ActionTypes type)
     * @param handlerBase address of the handler proxy
     */
    function _checkAccountApproveDenyOraclesRule(address _from, address _to, address _sender, ActionTypes action, address handlerBase) internal view {
        mapping(ActionTypes => Rule[]) storage accountApproveDenyOracle = lib.accountApproveDenyOracleStorage().accountApproveDenyOracle;
        /// The action type determines if the _to or _from is checked by the oracle
        /// _from address is checked for Burn
        if (action == ActionTypes.BURN){
            IRuleProcessor(handlerBase).checkAccountApproveDenyOracles(accountApproveDenyOracle[action], _from);
        } else if (action == ActionTypes.MINT){
            /// _to address is checked  for Mint
            IRuleProcessor(handlerBase).checkAccountApproveDenyOracles(accountApproveDenyOracle[action], _to);
        } else if (action == ActionTypes.P2P_TRANSFER){
            /// _from and _to address are checked for BUY, SELL, and P2P_TRANSFER
            IRuleProcessor(handlerBase).checkAccountApproveDenyOracles(accountApproveDenyOracle[action], _from);
            IRuleProcessor(handlerBase).checkAccountApproveDenyOracles(accountApproveDenyOracle[action], _to);
        } else if (action == ActionTypes.BUY){
            if (_from != _sender){ /// non custodial buy 
                IRuleProcessor(handlerBase).checkAccountApproveDenyOracles(accountApproveDenyOracle[ActionTypes.SELL], _from);
                IRuleProcessor(handlerBase).checkAccountApproveDenyOracles(accountApproveDenyOracle[action], _to);
            } else { /// custodial buy 
                IRuleProcessor(handlerBase).checkAccountApproveDenyOracles(accountApproveDenyOracle[action], _from);
                IRuleProcessor(handlerBase).checkAccountApproveDenyOracles(accountApproveDenyOracle[action], _to);
            }
        } else if (action == ActionTypes.SELL){
            if (_to != _sender){ /// non custodial sell 
                IRuleProcessor(handlerBase).checkAccountApproveDenyOracles(accountApproveDenyOracle[action], _from);
                IRuleProcessor(handlerBase).checkAccountApproveDenyOracles(accountApproveDenyOracle[ActionTypes.BUY], _to);
            } else { /// custodial sell 
                IRuleProcessor(handlerBase).checkAccountApproveDenyOracles(accountApproveDenyOracle[action], _from);
                IRuleProcessor(handlerBase).checkAccountApproveDenyOracles(accountApproveDenyOracle[action], _to);
            }
        }
    }

    /**
     * @dev Internal function to check the Account Approve Deny Oracle Flexible Rules
     * @param _from address of the from account
     * @param _to address of the to account
     * @param action if selling or buying (of ActionTypes type)
     * @param handlerBase address of the handler proxy
     */
    function _checkAccountApproveDenyOraclesFlexibleRule(address _from, address _to, ActionTypes action, address handlerBase) internal view {
        mapping(ActionTypes => Rule[]) storage accountApproveDenyOracleFlexible = lib.accountApproveDenyOracleFlexibleStorage().accountApproveDenyOracleFlexible;
        IRuleProcessor(handlerBase).checkAccountApproveDenyOraclesFlexible(accountApproveDenyOracleFlexible[action], _to, _from);
    }

    /**
     * @dev Internal function to check the Token Max Trading Volume rule 
     * @param _amount number of tokens transferred
     * @param handlerBase address of the handler proxy
     */
    function _checkTokenMaxTradingVolumeRule(uint256 _amount, address handlerBase) internal {
        TokenMaxTradingVolumeS storage maxTradingVolume = lib.tokenMaxTradingVolumeStorage();
        maxTradingVolume.transferVolume = IRuleProcessor(handlerBase).checkTokenMaxTradingVolume(
            maxTradingVolume.ruleId,
            maxTradingVolume.transferVolume,
            IToken(msg.sender).totalSupply(),
            _amount,
            maxTradingVolume.lastTransferTime
        );
        maxTradingVolume.lastTransferTime = uint64(block.timestamp);
    }

    /**
     * @dev Internal function to check the Token Max Supply Volatility rule 
     * @param _to address of the to account
     * @param _amount number of tokens transferred
     * @param handlerBase address of the handler proxy
     */
    function _checkTokenMaxSupplyVolatilityRule(address _to, uint256 _amount, address handlerBase) internal {
        /// rule requires ruleID and either to or from address be zero address (mint/burn)
        TokenMaxSupplyVolatilityS storage maxSupplyVolatility = lib.tokenMaxSupplyVolatilityStorage();
        (maxSupplyVolatility.volumeTotalForPeriod, maxSupplyVolatility.totalSupplyForPeriod) = IRuleProcessor(handlerBase).checkTokenMaxSupplyVolatility(
            maxSupplyVolatility.ruleId,
            maxSupplyVolatility.volumeTotalForPeriod,
            maxSupplyVolatility.totalSupplyForPeriod,
            IToken(msg.sender).totalSupply(),
            _to == address(0x00) ? int(_amount) * -1 : int(_amount),
            maxSupplyVolatility.lastSupplyUpdateTime
        );
        maxSupplyVolatility.lastSupplyUpdateTime = uint64(block.timestamp);
    }

    /**
     * @dev Internal function to check the TokenMaxDailyTrades rule 
     * @param _tokenId id of the NFT being transferred
     * @param action if selling or buying (of ActionTypes type)
     */
    function _checkTokenMaxDailyTradesRule(ActionTypes action, uint256 _tokenId) internal {
        HandlerBaseS storage handlerBaseStorage = lib.handlerBaseStorage();
        // get all the tags for this NFT
        bytes32[] memory tags = IAppManager(handlerBaseStorage.appManager).getAllTags(handlerBaseStorage.assetAddress);
        TokenMaxDailyTradesS storage maxDailyTrades = lib.tokenMaxDailyTradesStorage();
        // If the rule has been modified after transaction data was recorded, clear the accumulated transaction data.
        if (maxDailyTrades.lastTxDate[maxDailyTrades.tokenMaxDailyTrades[action].ruleId][_tokenId] < maxDailyTrades.ruleChangeDate){
            delete maxDailyTrades.lastTxDate[maxDailyTrades.tokenMaxDailyTrades[action].ruleId][_tokenId];
        }
        // in order to prevent cross contamination of action specific rules, the data is further broken down by action
        maxDailyTrades.tradesInPeriod[maxDailyTrades.tokenMaxDailyTrades[action].ruleId][_tokenId] = IRuleProcessor(handlerBaseStorage.ruleProcessor).checkTokenMaxDailyTrades(
            maxDailyTrades.tokenMaxDailyTrades[action].ruleId,
            maxDailyTrades.tradesInPeriod[maxDailyTrades.tokenMaxDailyTrades[action].ruleId][_tokenId],
            tags,
            maxDailyTrades.lastTxDate[maxDailyTrades.tokenMaxDailyTrades[action].ruleId][_tokenId]
        );
        maxDailyTrades.lastTxDate[maxDailyTrades.tokenMaxDailyTrades[action].ruleId][_tokenId] = uint64(block.timestamp);
    }       

    /**
     * @dev This function uses the protocol's ruleProcessor to perform the Min Hold Time Rule Check. 
     * @param _action action to be checked
     * @param _tokenId the specific token to check 
     * @param handlerBase address of the handler proxy 
     */

    function _checkMinHoldTimeRules(ActionTypes _action, uint256 _tokenId, address handlerBase, address _from, address _to, address _sender) internal {
        TokenMinHoldTimeS storage minHoldTime = lib.tokenMinHoldTimeStorage();
        ActionTypes potentialOppositeAction;
        // If the rule was changed after ownership was recorded, reset ownership. 
        if (minHoldTime.ownershipStart[_tokenId] < minHoldTime.ruleChangeDate) minHoldTime.ownershipStart[_tokenId] = 0;
        
        if (minHoldTime.tokenMinHoldTime[_action].active && minHoldTime.ownershipStart[_tokenId] > 0)
            IRuleProcessor(handlerBase).checkTokenMinHoldTime(minHoldTime.tokenMinHoldTime[_action].period, minHoldTime.ownershipStart[_tokenId]);

        if (_action == ActionTypes.BUY && _from != _sender) {
            potentialOppositeAction = ActionTypes.SELL;
        } else if (_action == ActionTypes.SELL && _to != _sender) {
            potentialOppositeAction = ActionTypes.BUY;
        } else {
            return;
        }

        if (minHoldTime.tokenMinHoldTime[potentialOppositeAction].active && minHoldTime.ownershipStart[_tokenId] > 0) {
            IRuleProcessor(handlerBase).checkTokenMinHoldTime(minHoldTime.tokenMinHoldTime[potentialOppositeAction].ruleId, minHoldTime.ownershipStart[_tokenId]);
        }
    }


}
