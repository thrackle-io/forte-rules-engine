// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/client/token/handler/diamond/FacetsCommonImports.sol";
import "src/client/token/handler/common/HandlerUtils.sol";
import "src/client/token/handler/common/AppAdministratorOrOwnerOnlyDiamondVersion.sol";
import "src/client/token/handler/diamond/RuleStorage.sol";
import "src/client/token/ITokenInterface.sol";
import "src/client/token/handler/ruleContracts/HandlerAccountApproveDenyOracle.sol";
import "src/client/token/handler/ruleContracts/HandlerAccountApproveDenyOracleFlexible.sol";
import "src/client/token/handler/ruleContracts/HandlerTokenMaxSupplyVolatility.sol";
import "src/client/token/handler/ruleContracts/HandlerTokenMaxTradingVolume.sol";
import "src/client/token/handler/ruleContracts/HandlerTokenMinTxSize.sol";

contract ERC20NonTaggedRuleFacet is 
    AppAdministratorOrOwnerOnlyDiamondVersion, 
    HandlerUtils, 
    HandlerAccountApproveDenyOracle, 
    HandlerAccountApproveDenyOracleFlexible, 
    HandlerTokenMaxSupplyVolatility, 
    HandlerTokenMaxTradingVolume, 
    HandlerTokenMinTxSize 
{
    /**
     * @dev This function uses the protocol's ruleProcessorto perform the actual rule checks.
     * @param _from address of the from account
     * @param _to address of the to account
     * @param _sender address of the caller 
     * @param _amount number of tokens transferred
     * @param action if selling or buying (of ActionTypes type)
     */
    function checkNonTaggedRules(address _from, address _to, address _sender, uint256 _amount, ActionTypes action) external onlyOwner {
        HandlerBaseS storage handlerBaseStorage = lib.handlerBaseStorage();
        address handlerBase = handlerBaseStorage.ruleProcessor;
        _checkAccountApproveDenyOraclesRule(_from, _to, _sender, action, handlerBase);
        _checkAccountApproveDenyOraclesFlexibleRule(_from, _to, action, handlerBase);

        if (action == ActionTypes.BURN){
            /// tokenMaxTradingVolume Burn 
            if (lib.tokenMaxTradingVolumeStorage().tokenMaxTradingVolume[action]) _checkTokenMaxTradingVolumeRule(_amount, handlerBase);
            /// tokenMinTxSize Burn
            if (lib.tokenMinTxSizeStorage().tokenMinTxSize[action].active) _checkTokenMinTxSizeRule(_amount, action, handlerBase);

        } else if (action == ActionTypes.MINT){
            /// tokenMaxTradingVolume Mint 
            if (lib.tokenMaxTradingVolumeStorage().tokenMaxTradingVolume[action]) _checkTokenMaxTradingVolumeRule(_amount, handlerBase);
            /// tokenMinTxSize Mint 
            if (lib.tokenMinTxSizeStorage().tokenMinTxSize[action].active) _checkTokenMinTxSizeRule(_amount, action, handlerBase);

        } else if (action == ActionTypes.P2P_TRANSFER){
            /// tokenMaxTradingVolume P2P_TRANSFER 
            if (lib.tokenMaxTradingVolumeStorage().tokenMaxTradingVolume[action]) _checkTokenMaxTradingVolumeRule(_amount, handlerBase);
            /// tokenMinTxSize P2P_TRANSFER
            if (lib.tokenMinTxSizeStorage().tokenMinTxSize[action].active) _checkTokenMinTxSizeRule(_amount, action, handlerBase);

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
                /// tokenMinTxSize BUY
                if (lib.tokenMinTxSizeStorage().tokenMinTxSize[ActionTypes.SELL].active) _checkTokenMinTxSizeRule(_amount, action, handlerBase);
            } else { /// custodial buy 
                if (lib.tokenMaxTradingVolumeStorage().tokenMaxTradingVolume[action]) {
                    _checkTokenMaxTradingVolumeRule(_amount, handlerBase);
                }
            }
            /// tokenMinTxSize BUY
            if (lib.tokenMinTxSizeStorage().tokenMinTxSize[action].active) _checkTokenMinTxSizeRule(_amount, action, handlerBase);
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
            /// tokenMinTxSize BUY
            if (lib.tokenMinTxSizeStorage().tokenMinTxSize[ActionTypes.BUY].active) _checkTokenMinTxSizeRule(_amount, action, handlerBase);
            } else { /// custodial sell 
                /// tokenMaxTradingVolume SELL 
                if (lib.tokenMaxTradingVolumeStorage().tokenMaxTradingVolume[action]) {
                    _checkTokenMaxTradingVolumeRule(_amount, handlerBase);
                }
            }
            /// tokenMinTxSize SELL
            if (lib.tokenMinTxSizeStorage().tokenMinTxSize[action].active) _checkTokenMinTxSizeRule(_amount, action, handlerBase);
        }

        if (lib.tokenMaxSupplyVolatilityStorage().tokenMaxSupplyVolatility[action] && (_from == address(0x00) || _to == address(0x00))) {
            _checkTokenMaxSupplyVolatilityRule(_to, _amount, handlerBase);
        }
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
}
