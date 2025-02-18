// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/IERC721Enumerable.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "src/protocol/economic/AppAdministratorOnly.sol";
import "src/protocol/economic/ruleProcessor/RuleCodeData.sol";
import "src/protocol/economic/IRuleProcessor.sol";
import "src/protocol/economic/RuleAdministratorOnly.sol";
import "src/client/application/IAppManager.sol";
import "src/common/IProtocolERC721Pricing.sol";
import "src/common/IProtocolERC20Pricing.sol";
import "src/client/token/ITokenInterface.sol";
import {IApplicationHandlerEvents, ICommonApplicationHandlerEvents} from "src/common/IEvents.sol";
import {IZeroAddressError, IAppHandlerErrors} from "src/common/IErrors.sol";
import "src/client/application/ProtocolApplicationHandlerCommon.sol";
import "src/client/common/ActionTypesArray.sol";

/**
 * @title Protocol Application Handler Contract
 * @notice This contract is the rules handler for all application level rules. It is implemented via the AppManager
 * @dev This contract is injected into the appManagers.
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett
 */
contract ProtocolApplicationHandler is
    ActionTypesArray,
    Ownable,
    RuleAdministratorOnly,
    IApplicationHandlerEvents,
    ICommonApplicationHandlerEvents,
    IInputErrors,
    IZeroAddressError,
    IAppHandlerErrors,
    ProtocolApplicationHandlerCommon
{
    string private constant VERSION = "2.2.2";
    IAppManager immutable appManager;
    address public immutable appManagerAddress;
    IRuleProcessor immutable ruleProcessor;
    address public immutable ruleProcessorAddress; 

    /// Rule mappings
    mapping(ActionTypes => Rule) accountMaxValueByAccessLevel;
    mapping(ActionTypes => Rule) accountMaxReceivedByAccessLevel;
    mapping(ActionTypes => Rule) accountMaxValueByRiskScore;
    mapping(ActionTypes => Rule) accountMaxTxValueByRiskScore;
    mapping(ActionTypes => Rule) accountMaxValueOutByAccessLevel;
    mapping(ActionTypes => Rule) accountDenyForNoAccessLevel;

    /// Pause Rule on-off switch
    bool private pauseRuleActive;

    /// Pricing Module interfaces
    IProtocolERC20Pricing erc20Pricer;
    IProtocolERC721Pricing nftPricer;
    address public erc20PricingAddress;
    address public nftPricingAddress;

    /// MaxTxSizePerPeriodByRisk data
    mapping(address => uint128) usdValueTransactedInRiskPeriod;
    mapping(address => uint64) lastTxDateRiskRule;
    mapping(address => uint128) usdValueTotalWithrawals;

    /// Account Max Received by Access Level Accumulator
    mapping(address => uint128) usdValueAccountMaxReceived;

    /**
     * @dev Initializes the contract setting the AppManager address as the one provided and setting the ruleProcessor for protocol access
     * @param _ruleProcessorProxyAddress of the protocol's Rule Processor contract.
     * @param _appManagerAddress address of the application AppManager.
     */
    constructor(address _ruleProcessorProxyAddress, address _appManagerAddress) {
        if (_ruleProcessorProxyAddress == address(0) || _appManagerAddress == address(0)) revert ZeroAddress();
        appManagerAddress = _appManagerAddress;
        ruleProcessorAddress = _ruleProcessorProxyAddress;
        appManager = IAppManager(_appManagerAddress);
        ruleProcessor = IRuleProcessor(_ruleProcessorProxyAddress);
        transferOwnership(_appManagerAddress);
        emit AD1467_ApplicationHandlerDeployed(_appManagerAddress, _ruleProcessorProxyAddress);
    }

    function _checkWhichApplicationRulesActive(ActionTypes _action) internal view returns (bool) {
        return
            pauseRuleActive ||
            accountMaxValueByRiskScore[_action].active ||
            accountMaxTxValueByRiskScore[_action].active ||
            accountMaxValueByAccessLevel[_action].active ||
            accountMaxValueOutByAccessLevel[_action].active ||
            accountMaxReceivedByAccessLevel[_action].active ||
            accountDenyForNoAccessLevel[_action].active;
    }

    function _checkNonCustodialRules(ActionTypes _action) internal view returns (bool) {
        if (_action == ActionTypes.BUY) {
            return _checkWhichApplicationRulesActive(ActionTypes.SELL);
        } else if (_action == ActionTypes.SELL) {
            return _checkWhichApplicationRulesActive(ActionTypes.BUY);
        } else {
            return false;
        }
    }
    /**
     * @dev checks if any of the Application level rules are active
     * @param _action the current action type
     * @return true if one or more rules are active
     */
    function requireApplicationRulesChecked(ActionTypes _action, address _sender) public view returns (bool) {
        return _checkWhichApplicationRulesActive(_action) ? true 
            : isContract(_sender) ? _checkNonCustodialRules(_action)
            : false;
    }

    /**
     * @dev Check Application Rules for valid transaction.
     * @param _tokenAddress address of the token
     * @param _sender address of the calling account passed through from the token 
     * @param _from address of the from account
     * @param _to address of the to account
     * @param _amount amount of tokens to be transferred
     * @param _nftValuationLimit number of tokenID's per collection before checking collection price vs individual token price
     * @param _tokenId tokenId of the NFT token
     * @param _action Action to be checked. This param is intentially added for future enhancements.
     * @param _handlerType the type of handler, used to direct to correct token pricing
     */
    function checkApplicationRules(
        address _tokenAddress,
        address _sender,
        address _from,
        address _to,
        uint256 _amount,
        uint16 _nftValuationLimit,
        uint256 _tokenId,
        ActionTypes _action,
        HandlerTypes _handlerType
    ) external onlyOwner {
        _action;
        uint128 balanceValuation;
        uint128 price;
        uint128 transferValuation;

        if (pauseRuleActive) ruleProcessor.checkPauseRules(appManagerAddress);
        /// Based on the Handler Type retrieve pricing valuations
        if (_handlerType == HandlerTypes.ERC20HANDLER) {
            balanceValuation = uint128(getAccTotalValuation(_to, 0));
            price = uint128(_getERC20Price(_tokenAddress));
            transferValuation = uint128((price * _amount) / (10 ** IToken(_tokenAddress).decimals()));
        } else {
            balanceValuation = uint128(getAccTotalValuation(_to, _nftValuationLimit));
            transferValuation = uint128(nftPricer.getNFTPrice(_tokenAddress, _tokenId));
        }
        _checkAccessLevelRules(_from, _to, _sender, balanceValuation, transferValuation, _action);
        _checkRiskRules(_from, _to, _sender, balanceValuation, transferValuation, _action);
    }

    /**
     * @dev This function consolidates all the Risk rule checks.
     * @param _from address of the from account
     * @param _to address of the to account
     * @param _sender address of the caller
     * @param _balanceValuation recepient address current total application valuation in USD with 18 decimals of precision
     * @param _transferValuation valuation of the token being transferred in USD with 18 decimals of precision
     * @param _action the current user action
     */
    function _checkRiskRules(address _from, address _to, address _sender, uint128 _balanceValuation, uint128 _transferValuation, ActionTypes _action) internal {
        uint8 riskScoreTo = appManager.getRiskScore(_to);
        uint8 riskScoreFrom = appManager.getRiskScore(_from);

        if (_action == ActionTypes.P2P_TRANSFER) {
            if (accountMaxTxValueByRiskScore[_action].active) {
                _checkAccountMaxTxValueByRiskScore(_action, _from, riskScoreFrom, _transferValuation);
                _checkAccountMaxTxValueByRiskScore(_action, _to, riskScoreTo, _transferValuation);
            }
            if (accountMaxValueByRiskScore[_action].active) 
                ruleProcessor.checkAccountMaxValueByRiskScore(accountMaxValueByRiskScore[_action].ruleId, _to, riskScoreTo, _balanceValuation, _transferValuation);
        } else if (_action == ActionTypes.BUY) {
            if (_from != _sender){ /// non custodial buy 
                if (accountMaxTxValueByRiskScore[ActionTypes.SELL].active) _checkAccountMaxTxValueByRiskScore(_action, _from, riskScoreFrom, _transferValuation);
            }
            if (accountMaxTxValueByRiskScore[_action].active) _checkAccountMaxTxValueByRiskScore(_action, _to, riskScoreTo, _transferValuation);
            if (accountMaxValueByRiskScore[_action].active) 
                ruleProcessor.checkAccountMaxValueByRiskScore(accountMaxValueByRiskScore[_action].ruleId, _to, riskScoreTo, _balanceValuation, _transferValuation);
        } else if (_action == ActionTypes.SELL) {
            if (_to != _sender){ /// non custodial sell 
                if (accountMaxTxValueByRiskScore[ActionTypes.BUY].active) _checkAccountMaxTxValueByRiskScore(_action, _to, riskScoreTo, _transferValuation);
                if (accountMaxValueByRiskScore[_action].active) 
                    ruleProcessor.checkAccountMaxValueByRiskScore(accountMaxValueByRiskScore[_action].ruleId, _to, riskScoreTo, _balanceValuation, _transferValuation);
            }
            if (accountMaxTxValueByRiskScore[_action].active) _checkAccountMaxTxValueByRiskScore(_action,_from, riskScoreFrom, _transferValuation);
        } else if (_action == ActionTypes.MINT) {
            if (accountMaxTxValueByRiskScore[_action].active) _checkAccountMaxTxValueByRiskScore(_action, _to, riskScoreTo, _transferValuation); 
            if (accountMaxValueByRiskScore[_action].active) 
                ruleProcessor.checkAccountMaxValueByRiskScore(accountMaxValueByRiskScore[_action].ruleId, _to, riskScoreTo, _balanceValuation, _transferValuation);
        } else if (_action == ActionTypes.BURN) {
            if (accountMaxTxValueByRiskScore[_action].active) _checkAccountMaxTxValueByRiskScore(_action, _from, riskScoreFrom, _transferValuation); 
        } 

    }

    /**
     * @dev This function consolidates all the Access Level rule checks.
     * @param _from address of the from account
     * @param _to address of the to account
     * @param _sender address of the to caller
     * @param _balanceValuation recepient address current total application valuation in USD with 18 decimals of precision
     * @param _transferValuation valuation of the token being transferred in USD with 18 decimals of precision
     * @param _action the current user action
     */
    function _checkAccessLevelRules(address _from, address _to, address _sender, uint128 _balanceValuation, uint128 _transferValuation, ActionTypes _action) internal {
        uint8 score = appManager.getAccessLevel(_to);
        uint8 fromScore = appManager.getAccessLevel(_from);        
        if (_action == ActionTypes.P2P_TRANSFER) {
            if (accountDenyForNoAccessLevel[_action].active) {
                ruleProcessor.checkAccountDenyForNoAccessLevel(fromScore);
                ruleProcessor.checkAccountDenyForNoAccessLevel(score);
            }
            if (accountMaxValueByAccessLevel[_action].active && _to != address(0))
                ruleProcessor.checkAccountMaxValueByAccessLevel(accountMaxValueByAccessLevel[_action].ruleId, score, _balanceValuation, _transferValuation);
            if (accountMaxValueOutByAccessLevel[_action].active) {
                usdValueTotalWithrawals[_from] = ruleProcessor.checkAccountMaxValueOutByAccessLevel(
                    accountMaxValueOutByAccessLevel[_action].ruleId,
                    fromScore,
                    usdValueTotalWithrawals[_from],
                    _transferValuation
                );
            }
            if (accountMaxReceivedByAccessLevel[_action].active) {
                usdValueAccountMaxReceived[_to] = ruleProcessor.checkAccountMaxReceivedByAccessLevel(
                    accountMaxReceivedByAccessLevel[_action].ruleId,
                    score,
                    usdValueAccountMaxReceived[_to],
                    _from,
                    _transferValuation
                );
            }
        } else if (_action == ActionTypes.BUY) {
            if (_from != _sender){ /// Non custodial buy
                if (accountDenyForNoAccessLevel[ActionTypes.SELL].active) ruleProcessor.checkAccountDenyForNoAccessLevel(fromScore);
                if (accountMaxValueByAccessLevel[ActionTypes.SELL].active && _to != address(0))
                    ruleProcessor.checkAccountMaxValueByAccessLevel(accountMaxValueByAccessLevel[_action].ruleId, score, _balanceValuation, _transferValuation);
                if (accountMaxValueOutByAccessLevel[ActionTypes.SELL].active) {
                    usdValueTotalWithrawals[_from] = ruleProcessor.checkAccountMaxValueOutByAccessLevel(
                        accountMaxValueOutByAccessLevel[_action].ruleId,
                        fromScore,
                        usdValueTotalWithrawals[_from],
                        _transferValuation
                    );
                }
                if (accountMaxReceivedByAccessLevel[ActionTypes.SELL].active) {
                    usdValueAccountMaxReceived[_to] = ruleProcessor.checkAccountMaxReceivedByAccessLevel(
                    accountMaxReceivedByAccessLevel[ActionTypes.SELL].ruleId,
                    score,
                    usdValueAccountMaxReceived[_to],
                    _from,
                    _transferValuation
                );
            }
            }
            if (accountDenyForNoAccessLevel[_action].active) ruleProcessor.checkAccountDenyForNoAccessLevel(score);
            if (accountMaxValueByAccessLevel[_action].active && _to != address(0))
                ruleProcessor.checkAccountMaxValueByAccessLevel(accountMaxValueByAccessLevel[_action].ruleId, score, _balanceValuation, _transferValuation);
            if (accountMaxValueOutByAccessLevel[_action].active) {
                usdValueTotalWithrawals[_from] = ruleProcessor.checkAccountMaxValueOutByAccessLevel(
                    accountMaxValueOutByAccessLevel[_action].ruleId,
                    fromScore,
                    usdValueTotalWithrawals[_from],
                    _transferValuation
                );
            }
            if (accountMaxReceivedByAccessLevel[_action].active) {
                usdValueAccountMaxReceived[_to] = ruleProcessor.checkAccountMaxReceivedByAccessLevel(
                    accountMaxReceivedByAccessLevel[_action].ruleId,
                    score,
                    usdValueAccountMaxReceived[_to],
                    _from,
                    _transferValuation
                );
            }
        } else if (_action == ActionTypes.SELL ) {
            if (_to != _sender){ /// Non custodial sell 
                if (accountDenyForNoAccessLevel[ActionTypes.BUY].active) ruleProcessor.checkAccountDenyForNoAccessLevel(score);
                if (accountMaxValueByAccessLevel[ActionTypes.BUY].active && _to != address(0))
                    ruleProcessor.checkAccountMaxValueByAccessLevel(accountMaxValueByAccessLevel[ActionTypes.BUY].ruleId, score, _balanceValuation, _transferValuation);
                if (accountMaxValueOutByAccessLevel[_action].active) {
                    usdValueTotalWithrawals[_from] = ruleProcessor.checkAccountMaxValueOutByAccessLevel(
                        accountMaxValueOutByAccessLevel[_action].ruleId,
                        fromScore,
                        usdValueTotalWithrawals[_from],
                        _transferValuation
                    );
                }
                if (accountMaxReceivedByAccessLevel[ActionTypes.BUY].active) {
                        usdValueAccountMaxReceived[_to] = ruleProcessor.checkAccountMaxReceivedByAccessLevel(
                        accountMaxReceivedByAccessLevel[ActionTypes.BUY].ruleId,
                        score,
                        usdValueAccountMaxReceived[_to],
                        _from,
                        _transferValuation
                    );
                }
            }
            if (accountDenyForNoAccessLevel[_action].active) ruleProcessor.checkAccountDenyForNoAccessLevel(fromScore);
            if (accountMaxValueByAccessLevel[_action].active && _to != address(0))
                ruleProcessor.checkAccountMaxValueByAccessLevel(accountMaxValueByAccessLevel[_action].ruleId, score, _balanceValuation, _transferValuation);
            if (accountMaxValueOutByAccessLevel[_action].active) {
                usdValueTotalWithrawals[_from] = ruleProcessor.checkAccountMaxValueOutByAccessLevel(
                    accountMaxValueOutByAccessLevel[_action].ruleId,
                    fromScore,
                    usdValueTotalWithrawals[_from],
                    _transferValuation
                );
            }
        } else if (_action == ActionTypes.MINT) {
            if (accountDenyForNoAccessLevel[_action].active) ruleProcessor.checkAccountDenyForNoAccessLevel(score);
            if (accountMaxValueByAccessLevel[_action].active && _to != address(0))
                ruleProcessor.checkAccountMaxValueByAccessLevel(accountMaxValueByAccessLevel[_action].ruleId, score, _balanceValuation, _transferValuation);
            if (accountMaxValueOutByAccessLevel[_action].active) {
                usdValueTotalWithrawals[_from] = ruleProcessor.checkAccountMaxValueOutByAccessLevel(
                    accountMaxValueOutByAccessLevel[_action].ruleId,
                    fromScore,
                    usdValueTotalWithrawals[_from],
                    _transferValuation
                );
            }
            if (accountMaxReceivedByAccessLevel[_action].active) {
                usdValueAccountMaxReceived[_to] = ruleProcessor.checkAccountMaxReceivedByAccessLevel(
                    accountMaxReceivedByAccessLevel[_action].ruleId,
                    score,
                    usdValueAccountMaxReceived[_to],
                    _from,
                    _transferValuation
                );
            }
        } else if (_action == ActionTypes.BURN) {
            if (accountDenyForNoAccessLevel[_action].active)ruleProcessor.checkAccountDenyForNoAccessLevel(fromScore);
            if (accountMaxValueByAccessLevel[_action].active && _to != address(0))
                ruleProcessor.checkAccountMaxValueByAccessLevel(accountMaxValueByAccessLevel[_action].ruleId, score, _balanceValuation, _transferValuation);
            if (accountMaxValueOutByAccessLevel[_action].active) {
                usdValueTotalWithrawals[_from] = ruleProcessor.checkAccountMaxValueOutByAccessLevel(
                    accountMaxValueOutByAccessLevel[_action].ruleId,
                    fromScore,
                    usdValueTotalWithrawals[_from],
                    _transferValuation
                );
            }
        }
    }

    /**
     * @dev This function consolidates the MaxTXValueByRiskScore rule checks for the from address.
     * @param _address address of the account
     * @param _riskScoreFrom sender address risk score
     * @param _transferValuation valuation of the token being transferred in USD with 18 decimals of precision
     * @param _action the current user action
     */
    function _checkAccountMaxTxValueByRiskScore(ActionTypes _action, address _address, uint8 _riskScoreFrom, uint128 _transferValuation) internal {
        usdValueTransactedInRiskPeriod[_address] = ruleProcessor.checkAccountMaxTxValueByRiskScore(
                accountMaxTxValueByRiskScore[_action].ruleId,
                usdValueTransactedInRiskPeriod[_address],
                _transferValuation,
                lastTxDateRiskRule[_address],
                _riskScoreFrom
            );
            lastTxDateRiskRule[_address] = uint64(block.timestamp);
    }

    /// -------------- Pricing Module Configurations ---------------
    /**
     * @dev Sets the address of the nft pricing contract and loads the contract.
     * @param _address Nft Pricing Contract address.
     */
    function setNFTPricingAddress(address _address) external ruleAdministratorOnly(appManagerAddress) {
        if (_address == address(0)) revert ZeroAddress();
        nftPricingAddress = _address;
        nftPricer = IProtocolERC721Pricing(_address);
        emit AD1467_ERC721PricingAddressSet(_address);
    }

    /**
     * @dev Sets the address of the erc20 pricing contract and loads the contract.
     * @param _address ERC20 Pricing Contract address.
     */
    function setERC20PricingAddress(address _address) external ruleAdministratorOnly(appManagerAddress) {
        if (_address == address(0)) revert ZeroAddress();
        erc20PricingAddress = _address;
        erc20Pricer = IProtocolERC20Pricing(_address);
        emit AD1467_ERC20PricingAddressSet(_address);
    }

    /**
     * @dev Get the account's balance in dollars. It uses the registered tokens in the app manager.
     * @notice This gets the account's balance in dollars.
     * @param _account address to get the balance for
     * @return totalValuation of the account in dollars
     */
    // slither-disable-next-line calls-loop
    function getAccTotalValuation(address _account, uint256 _nftValuationLimit) public view returns (uint256 totalValuation) {
        address[] memory tokenList = appManager.getTokenList();
        uint256 tokenAmount;
        /// check if _account is zero address. If zero address we return a valuation of zero to allow for burning tokens when rules that need valuations are active.
        if (_account == address(0)) {
            return totalValuation;
        } else {
            /// Loop through all Nfts and ERC20s and add values to balance for account valuation
            for (uint256 i; i < tokenList.length; ++i) {
                /// Check to see if user owns the asset
                tokenAmount = (IToken(tokenList[i]).balanceOf(_account));
                if (tokenAmount > 0) {
                    try IERC165(tokenList[i]).supportsInterface(0x80ac58cd) returns (bool isERC721) {
                        if (isERC721 && tokenAmount >= _nftValuationLimit) totalValuation += _getNFTCollectionValue(tokenList[i], tokenAmount);
                        else if (isERC721 && tokenAmount < _nftValuationLimit) totalValuation += _getNFTValuePerCollection(tokenList[i], _account, tokenAmount);
                        else {
                            uint8 decimals = ERC20(tokenList[i]).decimals();
                            totalValuation += (_getERC20Price(tokenList[i]) * (tokenAmount)) / (10 ** decimals);
                        }
                    } catch {
                        uint8 decimals = ERC20(tokenList[i]).decimals();
                        totalValuation += (_getERC20Price(tokenList[i]) * (tokenAmount)) / (10 ** decimals);
                    }
                }
            }
        }
    }

    /**
     * @dev Get the value for a specific ERC20. This is done by interacting with the pricing module
     * @notice This gets the token's value in dollars.
     * @param _tokenAddress the address of the token
     * @return price the price of 1 in dollars
     */
    function _getERC20Price(address _tokenAddress) internal view returns (uint256) {
        if (erc20PricingAddress != address(0)) {
            // Disabling this finding, it is a false positive. The if statement for the zero address check
            // is being treated as a loop.
            // slither-disable-next-line calls-loop
            return erc20Pricer.getTokenPrice(_tokenAddress);
        } else {
            revert PricingModuleNotConfigured(erc20PricingAddress, nftPricingAddress);
        }
    }

    /**
     * @dev Get the value for a specific ERC721. This is done by interacting with the pricing module
     * @notice This gets the token's value in dollars.
     * @param _tokenAddress the address of the token
     * @param _account of the token holder
     * @param _tokenAmount amount of NFTs from _tokenAddress contract
     * @return totalValueInThisContract in whole USD
     */
    // slither-disable-next-line calls-loop
    function _getNFTValuePerCollection(address _tokenAddress, address _account, uint256 _tokenAmount) internal view returns (uint256 totalValueInThisContract) {
        if (nftPricingAddress != address(0)) {
            for (uint i; i < _tokenAmount; ++i) {
                totalValueInThisContract += nftPricer.getNFTPrice(_tokenAddress, IERC721Enumerable(_tokenAddress).tokenOfOwnerByIndex(_account, i));
            }
        } else {
            revert PricingModuleNotConfigured(erc20PricingAddress, nftPricingAddress);
        }
    }

    /**
     * @dev Get the total value for all tokens held by a wallet for a specific collection. This is done by interacting with the pricing module
     * @notice This function gets the total token value in dollars of all tokens owned in each collection by address.
     * @param _tokenAddress the address of the token
     * @param _tokenAmount amount of NFTs from _tokenAddress contract
     * @return totalValueInThisContract total valuation of tokens by collection in whole USD
     */
    function _getNFTCollectionValue(address _tokenAddress, uint256 _tokenAmount) private view returns (uint256 totalValueInThisContract) {
        if (nftPricingAddress != address(0)) {
            // Disabling this finding, it is a false positive. The if statement for the zero address check
            // is being treated as a loop.
            // slither-disable-next-line calls-loop
            totalValueInThisContract = _tokenAmount * uint256(nftPricer.getNFTCollectionPrice(_tokenAddress));
        } else {
            revert PricingModuleNotConfigured(erc20PricingAddress, nftPricingAddress);
        }
    }

    /**
     * @dev Set the accountMaxValueByRiskScoreRule. Restricted to app administrators only.
     * @notice that setting a rule will automatically activate it.
     * @param _actions action types in which to apply the rules
     * @param _ruleId Rule Id to set
     */
    function setAccountMaxValueByRiskScoreId(ActionTypes[] calldata _actions, uint32 _ruleId) external ruleAdministratorOnly(appManagerAddress) {
        for (uint i; i < _actions.length; ++i) {
            setAccountMaxValueByRiskScoreIdUpdate(_actions[i], _ruleId);
            emit AD1467_ApplicationRuleApplied(ACC_MAX_VALUE_BY_RISK_SCORE, _actions[i], _ruleId);
        }
    }

    /**
     * @dev Set the accountMaxValueByRiskScoreRule. Restricted to app administrators only.
     * @notice that setting a rule will automatically activate it.
     * @param _actions actions to have the rule applied to
     * @param _ruleIds Rule Id corresponding to the actions
     */
    function setAccountMaxValueByRiskScoreIdFull(ActionTypes[] calldata _actions, uint32[] calldata _ruleIds) external ruleAdministratorOnly(appManagerAddress) {
        validateRuleInputFull(_actions, _ruleIds);
        clearAccountMaxValueByRiskScore();
        for (uint i; i < _actions.length; ++i) {
            setAccountMaxValueByRiskScoreIdUpdate(_actions[i], _ruleIds[i]);
        }
        emit AD1467_ApplicationRuleAppliedFull(ACC_MAX_VALUE_BY_RISK_SCORE, _actions, _ruleIds);
    }

    /**
     * @dev Clear the rule data structure
     */
    function clearAccountMaxValueByRiskScore() internal {
        for (uint i; i <= lastPossibleAction;) {
            delete accountMaxValueByRiskScore[ActionTypes(i)];
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @dev Set the AccountMaxValuebyRiskSCoreRuleId.
     * @notice that setting a rule will automatically activate it.
     * @param _action the action type to set the rule
     * @param _ruleId Rule Id to set
     */
    // slither-disable-next-line calls-loop
    function setAccountMaxValueByRiskScoreIdUpdate(ActionTypes _action, uint32 _ruleId) internal {
        // slither-disable-next-line calls-loop
        IRuleProcessor(ruleProcessor).validateAccountMaxValueByRiskScore(createActionTypesArray(_action), _ruleId);
        accountMaxValueByRiskScore[_action].ruleId = _ruleId;
        accountMaxValueByRiskScore[_action].active = true;
        emit AD1467_ApplicationRuleApplied(ACC_MAX_VALUE_BY_RISK_SCORE, _ruleId);
    }

    /**
     * @dev enable/disable rule. Disabling a rule will save gas on transfer transactions.
     * @param _actions action types
     * @param _on boolean representing if a rule must be checked or not.
     */
    function activateAccountMaxValueByRiskScore(ActionTypes[] calldata _actions, bool _on) external ruleAdministratorOnly(appManagerAddress) {
        for (uint i; i < _actions.length; ++i) {
            accountMaxValueByRiskScore[_actions[i]].active = _on;
        }
        if (_on) {
            emit AD1467_ApplicationHandlerActivated(ACC_MAX_VALUE_BY_RISK_SCORE, _actions);
        } else {
            emit AD1467_ApplicationHandlerDeactivated(ACC_MAX_VALUE_BY_RISK_SCORE, _actions);
        }
    }

    /**
     * @dev Tells you if the accountMaxValueByRiskScore Rule is active or not.
     * @param _action the action type
     * @return boolean representing if the rule is active
     */
    function isAccountMaxValueByRiskScoreActive(ActionTypes _action) external view returns (bool) {
        return accountMaxValueByRiskScore[_action].active;
    }

    /**
     * @dev Retrieve the accountMaxValueByRiskScore rule id
     * @param _action action type
     * @return accountMaxValueByRiskScoreId rule id
     */
    function getAccountMaxValueByRiskScoreId(ActionTypes _action) external view returns (uint32) {
        return accountMaxValueByRiskScore[_action].ruleId;
    }

    /**
     * @dev Set the activateAccountDenyForNoAccessLevel. Restricted to app administrators only.
     * @notice that setting a rule will automatically activate it.
     * @param _actions action types in which to apply the rules
     */
    function setAccountDenyForNoAccessLevelId(ActionTypes[] calldata _actions) external ruleAdministratorOnly(appManagerAddress) {
        for (uint i; i < _actions.length; ++i) {
            setAccountDenyForNoAccessLevelIdUpdate(_actions[i]);
            emit AD1467_ApplicationRuleApplied(ACCOUNT_DENY_FOR_NO_ACCESS_LEVEL, _actions[i], 0);
        }
    }

    /**
     * @dev Set the activateAccountDenyForNoAccessLevel. Restricted to app administrators only.
     * @notice that setting a rule will automatically activate it.
     * @param _actions actions to have the rule applied to
     */
    function setAccountDenyForNoAccessLevelIdFull(ActionTypes[] calldata _actions) external ruleAdministratorOnly(appManagerAddress) {
        clearAccountDenyForNoAccessLevel();
        for (uint i; i < _actions.length; ++i) {
            setAccountDenyForNoAccessLevelIdUpdate(_actions[i]);
        }
        emit AD1467_ApplicationRuleAppliedFull(ACCOUNT_DENY_FOR_NO_ACCESS_LEVEL, _actions, new uint32[](_actions.length));
    }

    /**
     * @dev Clear the rule data structure
     */
    function clearAccountDenyForNoAccessLevel() internal {
        for (uint i; i <= lastPossibleAction; ++i) {
            delete accountDenyForNoAccessLevel[ActionTypes(i)];
        }
    }

    /**
     * @dev Set the AccountDenyForNoAccessLevelRuleId.
     * @notice that setting a rule will automatically activate it.
     * @param _action the action type to set the rule
     */
    // slither-disable-next-line calls-loop
    function setAccountDenyForNoAccessLevelIdUpdate(ActionTypes _action) internal {
        accountDenyForNoAccessLevel[_action].active = true;
    }

    /**
     * @dev enable/disable rule. Disabling a rule will save gas on transfer transactions.
     * @param _actions action types
     * @param _on boolean representing if a rule must be checked or not.
     */
    function activateAccountDenyForNoAccessLevelRule(ActionTypes[] calldata _actions, bool _on) external ruleAdministratorOnly(appManagerAddress) {
        for (uint i; i < _actions.length; ++i) {
            accountDenyForNoAccessLevel[_actions[i]].active = _on;
        }
        if (_on) {
            emit AD1467_ApplicationHandlerActivated(ACCOUNT_DENY_FOR_NO_ACCESS_LEVEL, _actions);
        } else {
            emit AD1467_ApplicationHandlerDeactivated(ACCOUNT_DENY_FOR_NO_ACCESS_LEVEL, _actions);
        }
    }

    /**
     * @dev Tells you if the AccountDenyForNoAccessLevel Rule is active or not.
     * @param _action the action type
     * @return boolean representing if the rule is active
     */
    function isAccountDenyForNoAccessLevelActive(ActionTypes _action) external view returns (bool) {
        return accountDenyForNoAccessLevel[_action].active;
    }

    /**
     * @dev Set the accountMaxReceivedByAccessLevelRule. Restricted to app administrators only.
     * @notice that setting a rule will automatically activate it.
     * @param _actions action types in which to apply the rules
     * @param _ruleId Rule Id to set
     */
    function setAccountMaxReceivedByAccessLevelId(ActionTypes[] calldata _actions, uint32 _ruleId) external ruleAdministratorOnly(appManagerAddress) {
        for (uint i; i < _actions.length; ++i) {
            setAccountMaxReceivedbyAccessLevelIdUpdate(_actions[i], _ruleId);
            emit AD1467_ApplicationRuleApplied(ACC_MAX_RECEIVED_BY_ACCESS_LEVEL, _actions[i], _ruleId);
        }
    }

    /**
     * @dev Set the accountMaxReceivedByAccessLevelRule. Restricted to app administrators only.
     * @notice that setting a rule will automatically activate it.
     * @param _actions actions to have the rule applied to
     * @param _ruleIds Rule Id corresponding to the actions
     */
    function setAccountMaxReceivedByAccessLevelIdFull(ActionTypes[] calldata _actions, uint32[] calldata _ruleIds) external ruleAdministratorOnly(appManagerAddress) {
        validateRuleInputFull(_actions, _ruleIds);
        clearAccountMaxReceivedByAccessLevel();
        for (uint i; i < _actions.length; ++i) {
            setAccountMaxReceivedbyAccessLevelIdUpdate(_actions[i], _ruleIds[i]);
        }
        emit AD1467_ApplicationRuleAppliedFull(ACC_MAX_RECEIVED_BY_ACCESS_LEVEL, _actions, _ruleIds);
    }

    /**
     * @dev Clear the rule data structure
     */
    function clearAccountMaxReceivedByAccessLevel() internal {
        for (uint i; i <= lastPossibleAction; ++i) {
            delete accountMaxReceivedByAccessLevel[ActionTypes(i)];
        }
    }

    /**
     * @dev Set the AccountMaxReceivedbyAccessLevelRuleId.
     * @notice that setting a rule will automatically activate it.
     * @param _action the action type to set the rule
     * @param _ruleId Rule Id to set
     */
    // slither-disable-next-line calls-loop
    function setAccountMaxReceivedbyAccessLevelIdUpdate(ActionTypes _action, uint32 _ruleId) internal {
        // slither-disable-next-line calls-loop
        IRuleProcessor(ruleProcessor).validateAccountMaxReceivedByAccessLevel(createActionTypesArray(_action), _ruleId);
        accountMaxReceivedByAccessLevel[_action].ruleId = _ruleId;
        accountMaxReceivedByAccessLevel[_action].active = true;
    }

    /**
     * @dev enable/disable rule. Disabling a rule will save gas on transfer transactions.
     * @param _actions action types
     * @param _on boolean representing if a rule must be checked or not.
     */
    function activateAccountMaxReceivedByAccessLevel(ActionTypes[] calldata _actions, bool _on) external ruleAdministratorOnly(appManagerAddress) {
        for (uint i; i < _actions.length; ++i) {
            accountMaxReceivedByAccessLevel[_actions[i]].active = _on;
        }
        if (_on) {
            emit AD1467_ApplicationHandlerActivated(ACC_MAX_RECEIVED_BY_ACCESS_LEVEL, _actions);
        } else {
            emit AD1467_ApplicationHandlerDeactivated(ACC_MAX_RECEIVED_BY_ACCESS_LEVEL, _actions);
        }
    }

    /**
     * @dev Tells you if the accountMaxReceivedByAccessLevel Rule is active or not.
     * @param _action the action type
     * @return boolean representing if the rule is active
     */
    function isAccountMaxReceivedByAccessLevelActive(ActionTypes _action) external view returns (bool) {
        return accountMaxReceivedByAccessLevel[_action].active;
    }

    /**
     * @dev Retrieve the accountMaxReceivedByAccessLevel rule id
     * @param _action action type
     * @return accountMaxReceivedByAccessLevelId rule id
     */
    function getAccountMaxReceivedByAccessLevelId(ActionTypes _action) external view returns (uint32) {
        return accountMaxReceivedByAccessLevel[_action].ruleId;
    }

    /**
     * @dev Set the accountMaxValueByAccessLevelRule. Restricted to app administrators only.
     * @notice that setting a rule will automatically activate it.
     * @param _actions action types in which to apply the rules
     * @param _ruleId Rule Id to set
     */
    function setAccountMaxValueByAccessLevelId(ActionTypes[] calldata _actions, uint32 _ruleId) external ruleAdministratorOnly(appManagerAddress) {
        for (uint i; i < _actions.length; ++i) {
            setAccountMaxValuebyAccessLevelIdUpdate(_actions[i], _ruleId);
            emit AD1467_ApplicationRuleApplied(ACC_MAX_VALUE_BY_ACCESS_LEVEL, _actions[i], _ruleId);
        }
    }

    /**
     * @dev Set the accountMaxValueByAccessLevelRule. Restricted to app administrators only.
     * @notice that setting a rule will automatically activate it.
     * @param _actions actions to have the rule applied to
     * @param _ruleIds Rule Id corresponding to the actions
     */
    function setAccountMaxValueByAccessLevelIdFull(ActionTypes[] calldata _actions, uint32[] calldata _ruleIds) external ruleAdministratorOnly(appManagerAddress) {
        validateRuleInputFull(_actions, _ruleIds);
        clearAccountMaxValueByAccessLevel();
        for (uint i; i < _actions.length; ++i) {
            setAccountMaxValuebyAccessLevelIdUpdate(_actions[i], _ruleIds[i]);
        }
        emit AD1467_ApplicationRuleAppliedFull(ACC_MAX_VALUE_BY_ACCESS_LEVEL, _actions, _ruleIds);
    }

    /**
     * @dev Clear the rule data structure
     */
    function clearAccountMaxValueByAccessLevel() internal {
        for (uint i; i <= lastPossibleAction; ++i) {
            delete accountMaxValueByAccessLevel[ActionTypes(i)];
        }
    }

    /**
     * @dev Set the AccountMaxValuebyAccessLevelRuleId.
     * @notice that setting a rule will automatically activate it.
     * @param _action the action type to set the rule
     * @param _ruleId Rule Id to set
     */
    // slither-disable-next-line calls-loop
    function setAccountMaxValuebyAccessLevelIdUpdate(ActionTypes _action, uint32 _ruleId) internal {
        // slither-disable-next-line calls-loop
        IRuleProcessor(ruleProcessor).validateAccountMaxValueByAccessLevel(createActionTypesArray(_action), _ruleId);
        accountMaxValueByAccessLevel[_action].ruleId = _ruleId;
        accountMaxValueByAccessLevel[_action].active = true;
    }

    /**
     * @dev enable/disable rule. Disabling a rule will save gas on transfer transactions.
     * @param _actions action types
     * @param _on boolean representing if a rule must be checked or not.
     */
    function activateAccountMaxValueByAccessLevel(ActionTypes[] calldata _actions, bool _on) external ruleAdministratorOnly(appManagerAddress) {
        for (uint i; i < _actions.length; ++i) {
            accountMaxValueByAccessLevel[_actions[i]].active = _on;
        }
        if (_on) {
            emit AD1467_ApplicationHandlerActivated(ACC_MAX_VALUE_BY_ACCESS_LEVEL, _actions);
        } else {
            emit AD1467_ApplicationHandlerDeactivated(ACC_MAX_VALUE_BY_ACCESS_LEVEL, _actions);
        }
    }

    /**
     * @dev Tells you if the accountMaxValueByAccessLevel Rule is active or not.
     * @param _action the action type
     * @return boolean representing if the rule is active
     */
    function isAccountMaxValueByAccessLevelActive(ActionTypes _action) external view returns (bool) {
        return accountMaxValueByAccessLevel[_action].active;
    }

    /**
     * @dev Retrieve the accountMaxValueByAccessLevel rule id
     * @param _action action type
     * @return accountMaxValueByAccessLevelId rule id
     */
    function getAccountMaxValueByAccessLevelId(ActionTypes _action) external view returns (uint32) {
        return accountMaxValueByAccessLevel[_action].ruleId;
    }

    /**
     * @dev Set the AccountMaxValueOutByAccessLevel. Restricted to app administrators only.
     * @notice that setting a rule will automatically activate it.
     * @param _actions action types in which to apply the rules
     * @param _ruleId Rule Id to set
     */
    function setAccountMaxValueOutByAccessLevelId(ActionTypes[] calldata _actions, uint32 _ruleId) external ruleAdministratorOnly(appManagerAddress) {
        for (uint i; i < _actions.length; ++i) {
            setAccountMaxValueOutByAccessLevelIdUpdate(_actions[i], _ruleId);
            emit AD1467_ApplicationRuleApplied(ACC_MAX_VALUE_OUT_ACCESS_LEVEL, _actions[i], _ruleId);
        }
    }

    /**
     * @dev Set the AccountMaxValueOutByAccessLevel. Restricted to app administrators only.
     * @notice that setting a rule will automatically activate it.
     * @param _actions actions to have the rule applied to
     * @param _ruleIds Rule Id corresponding to the actions
     */
    function setAccountMaxValueOutByAccessLevelIdFull(ActionTypes[] calldata _actions, uint32[] calldata _ruleIds) external ruleAdministratorOnly(appManagerAddress) {
        validateRuleInputFull(_actions, _ruleIds);
        clearAccountMaxValueOutByAccessLevel();
        for (uint i; i < _actions.length; ++i) {
            setAccountMaxValueOutByAccessLevelIdUpdate(_actions[i], _ruleIds[i]);
        }
        emit AD1467_ApplicationRuleAppliedFull(ACC_MAX_VALUE_OUT_ACCESS_LEVEL, _actions, _ruleIds);
    }

    /**
     * @dev Clear the rule data structure
     */
    function clearAccountMaxValueOutByAccessLevel() internal {
        for (uint i; i <= lastPossibleAction; ++i) {
            delete accountMaxValueOutByAccessLevel[ActionTypes(i)];
        }
    }

    /**
     * @dev Set the AccountMaxValueOutByAccessLevelRuleId.
     * @notice that setting a rule will automatically activate it.
     * @param _action the action type to set the rule
     * @param _ruleId Rule Id to set
     */
    // slither-disable-next-line calls-loop
    function setAccountMaxValueOutByAccessLevelIdUpdate(ActionTypes _action, uint32 _ruleId) internal {
        // slither-disable-next-line calls-loop
        IRuleProcessor(ruleProcessor).validateAccountMaxValueOutByAccessLevel(createActionTypesArray(_action), _ruleId);
        accountMaxValueOutByAccessLevel[_action].ruleId = _ruleId;
        accountMaxValueOutByAccessLevel[_action].active = true;
    }

    /**
     * @dev enable/disable rule. Disabling a rule will save gas on transfer transactions.
     * @param _actions action types
     * @param _on boolean representing if a rule must be checked or not.
     */
    function activateAccountMaxValueOutByAccessLevel(ActionTypes[] calldata _actions, bool _on) external ruleAdministratorOnly(appManagerAddress) {
        for (uint i; i < _actions.length; ++i) {
            accountMaxValueOutByAccessLevel[_actions[i]].active = _on;
        }
        if (_on) {
            emit AD1467_ApplicationHandlerActivated(ACC_MAX_VALUE_OUT_ACCESS_LEVEL, _actions);
        } else {
            emit AD1467_ApplicationHandlerDeactivated(ACC_MAX_VALUE_OUT_ACCESS_LEVEL, _actions);
        }
    }

    /**
     * @dev Tells you if the AccountMaxValueOutByAccessLevel Rule is active or not.
     * @param _action the action type
     * @return boolean representing if the rule is active
     */
    function isAccountMaxValueOutByAccessLevelActive(ActionTypes _action) external view returns (bool) {
        return accountMaxValueOutByAccessLevel[_action].active;
    }

    /**
     * @dev Retrieve the accountMaxValueOutByAccessLevel rule id
     * @param _action action type
     * @return accountMaxValueOutByAccessLevelId rule id
     */
    function getAccountMaxValueOutByAccessLevelId(ActionTypes _action) external view returns (uint32) {
        return accountMaxValueOutByAccessLevel[_action].ruleId;
    }

    /**
     * @dev Set the accountMaxTxValueByRiskScore. Restricted to app administrators only.
     * @notice that setting a rule will automatically activate it.
     * @param _actions action types in which to apply the rules
     * @param _ruleId Rule Id to set
     */
    function setAccountMaxTxValueByRiskScoreId(ActionTypes[] calldata _actions, uint32 _ruleId) external ruleAdministratorOnly(appManagerAddress) {
        for (uint i; i < _actions.length; ++i) {
            setAccountMaxTxValueByRiskScoreIdUpdate(_actions[i], _ruleId);
            emit AD1467_ApplicationRuleApplied(ACC_MAX_TX_VALUE_BY_RISK_SCORE, _actions[i], _ruleId);
        }
    }

    /**
     * @dev Set the accountMaxTxValueByRiskScore. Restricted to app administrators only.
     * @notice that setting a rule will automatically activate it.
     * @param _actions actions to have the rule applied to
     * @param _ruleIds Rule Id corresponding to the actions
     */
    function setAccountMaxTxValueByRiskScoreIdFull(ActionTypes[] calldata _actions, uint32[] calldata _ruleIds) external ruleAdministratorOnly(appManagerAddress) {
        validateRuleInputFull(_actions, _ruleIds);
        clearAccountMaxTxValueByRiskScore();
        for (uint i; i < _actions.length; ++i) {
            setAccountMaxTxValueByRiskScoreIdUpdate(_actions[i], _ruleIds[i]);
        }
        emit AD1467_ApplicationRuleAppliedFull(ACC_MAX_TX_VALUE_BY_RISK_SCORE, _actions, _ruleIds);
    }

    /**
     * @dev Clear the rule data structure
     */
    function clearAccountMaxTxValueByRiskScore() internal {
        for (uint i; i <= lastPossibleAction; ++i) {
            delete accountMaxTxValueByRiskScore[ActionTypes(i)];
        }
    }

    /**
     * @dev Set the AccountMaxTxValueByRiskScoreRuleId.
     * @notice that setting a rule will automatically activate it.
     * @param _action the action type to set the rule
     * @param _ruleId Rule Id to set
     */
    // slither-disable-next-line calls-loop
    function setAccountMaxTxValueByRiskScoreIdUpdate(ActionTypes _action, uint32 _ruleId) internal {
        // slither-disable-next-line calls-loop
        IRuleProcessor(ruleProcessor).validateAccountMaxTxValueByRiskScore(createActionTypesArray(_action), _ruleId);
        accountMaxTxValueByRiskScore[_action].ruleId = _ruleId;
        accountMaxTxValueByRiskScore[_action].active = true;
    }

    /**
     * @dev enable/disable rule. Disabling a rule will save gas on transfer transactions.
     * @param _actions action types
     * @param _on boolean representing if a rule must be checked or not.
     */
    function activateAccountMaxTxValueByRiskScore(ActionTypes[] calldata _actions, bool _on) external ruleAdministratorOnly(appManagerAddress) {
        for (uint i; i < _actions.length; ++i) {
            accountMaxTxValueByRiskScore[_actions[i]].active = _on;
        }
        if (_on) {
            emit AD1467_ApplicationHandlerActivated(ACC_MAX_TX_VALUE_BY_RISK_SCORE, _actions);
        } else {
            emit AD1467_ApplicationHandlerDeactivated(ACC_MAX_TX_VALUE_BY_RISK_SCORE, _actions);
        }
    }

    /**
     * @dev Tells you if the accountMaxTxValueByRiskScore Rule is active or not.
     * @param _action the action type
     * @return boolean representing if the rule is active
     */
    function isAccountMaxTxValueByRiskScoreActive(ActionTypes _action) external view returns (bool) {
        return accountMaxTxValueByRiskScore[_action].active;
    }

    /**
     * @dev Retrieve the AccountMaxTxValueByRiskScore rule id
     * @param _action action type
     * @return accountMaxTxValueByRiskScoreId rule id
     */
    function getAccountMaxTxValueByRiskScoreId(ActionTypes _action) external view returns (uint32) {
        return accountMaxTxValueByRiskScore[_action].ruleId;
    }

    /**
     * @dev enable/disable rule. Disabling a rule will save gas on transfer transactions.
     * This function does not use ruleAdministratorOnly modifier, the onlyOwner modifier checks that the caller is the appManager contract.
     * @notice This function uses the onlyOwner modifier since the appManager contract is calling this function when adding a pause rule or removing the final pause rule of the array.
     * @param _on boolean representing if a rule must be checked or not.
     */

    function activatePauseRule(bool _on) external onlyOwner {
        pauseRuleActive = _on;
        if (_on) {
            emit AD1467_ApplicationHandlerActivated(PAUSE_RULE);
        } else {
            emit AD1467_ApplicationHandlerDeactivated(PAUSE_RULE);
        }
    }

    /**
     * @dev Tells you if the pause rule check is active or not.
     * @return boolean representing if the rule is active for specified token
     */
    function isPauseRuleActive() external view returns (bool) {
        return pauseRuleActive;
    }

    /**
     * @dev gets the version of the contract
     * @return VERSION
     */
    function version() external pure returns (string memory) {
        return VERSION;
    }

    /**
     * @dev Check if the addresss is a contract
     * @param account address to check
     * @return bool
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize/address.code.length, which returns 0
        // for contracts in construction, since the code is only stored at the end
        // of the constructor execution.
        return account.code.length > 0;
    }

     /**
     * @dev Getter for rule processor address
     * @return ruleProcessorAddress
     */
    function getRuleProcessAddress() external view returns(address){
        return address(ruleProcessor);
    }
}