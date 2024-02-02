// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;
import {ActionTypes} from "src/common/ActionEnum.sol";

/**
 * @title Protocol Events Interface
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev This library for all events in the Protocol module for the protocol. Each contract in the Protocol module should inherit this library for emitting events.
 * @notice Protocol Module Events Library
 */

interface IAppLevelEvents {
    ///AppManager
    event HandlerConnected(address indexed handlerAddress, address indexed appManager);
    event RoleCheck(string contractName, string functionName, address checkedAddress, bytes32 checkedRole);
    event AppManagerDeployed(address indexed superAndAppAdmin, string indexed appName);
    event AppManagerDeployedForUpgrade(address indexed superAndAppAdmin, string indexed appName);
    event AppManagerUpgrade(address indexed deployedAddress, address replacedAddress);
    event AppManagerDataUpgradeProposed(address indexed deployedAddress, address replacedAddress);
    event DataContractsMigrated(address indexed ownerAddress);
    event RemoveFromRegistry(string contractName, address contractAddress);
    event RuleAdmin(address indexed admin, bool indexed add);
    event RiskAdmin(address indexed admin, bool indexed add);
    event AccessLevelAdmin(address indexed admin, bool indexed add);
    event AppAdministrator(address indexed admin, bool indexed add); 
    event SuperAdministrator(address indexed admin, bool indexed add);
    event RuleBypassAccount(address indexed bypassAccount, bool indexed add);  
    ///Registrations
    event TokenRegistered(string indexed _token, address indexed _address);
    event TokenNameUpdated(string indexed _token, address indexed _address);
    event AMMRegistered(address indexed _address);
    event TreasuryRegistered(address indexed _address);
    event TradingRuleAddressWhitelist(address indexed _address, bool indexed isApproved);
    ///Accounts
    event AccountProviderSet(address indexed _address);
    event AccountAdded(address indexed account);
    event AccountRemoved(address indexed account);
    ///Tags
    event TagProviderSet(address indexed _address);
    event Tag(address indexed _address, bytes32 indexed _tag, bool indexed add);
    event TagAlreadyApplied(address indexed _address);
    ///AccessLevels
    event AccessLevelProviderSet(address indexed _address);
    event AccessLevelAdded(address indexed _address, uint8 indexed _level);
    event AccessLevelRemoved(address indexed _address);
    ///PauseRules
    event PauseRuleProviderSet(address indexed _address);
    event PauseRuleEvent(uint256 indexed pauseStart, uint256 indexed pauseStop, bool indexed add);
    ///RiskScores
    event RiskProviderSet(address indexed _address);
    event RiskScoreAdded(address indexed _address, uint8 _score);
    event RiskScoreRemoved(address indexed _address);
}

interface IOracleEvents{
    event AllowedAddress(address indexed addr);
    event NotAllowedAddress(address indexed addr);
    event AllowListOracleDeployed();
    event DeniedAddress(address indexed addr);
    event NonDeniedAddress(address indexed addr);
    event DeniedListOracleDeployed();
    event OracleListChanged(bool indexed add, address[] addresses); // new event
}


/**
 * @title Application Handler Events Interface
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev This library for all events in the Protocol module for the protocol. Each contract in the Protocol module should inherit this library for emitting events.
 * @notice Protocol Module Events Library
 */

interface IApplicationHandlerEvents {
    event ApplicationHandlerDeployed(address indexed appManager);
    // Rule applied
    event ApplicationRuleApplied(bytes32 indexed ruleType, uint32 indexed ruleId);
    /// Pricing
    event ERC721PricingAddressSet(address indexed _address);
    event ERC20PricingAddressSet(address indexed _address);
}

/**
 * @title Application Handler Events Interface
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev This library for all events in the Protocol module for the protocol. Each contract in the Protocol module should inherit this library for emitting events.
 * @notice Protocol Module Events Library
 */
interface ICommonApplicationHandlerEvents {
    /// Rule deactivated
    event ApplicationHandlerDeactivated(bytes32 indexed ruleType);
    /// Rule activated
    event ApplicationHandlerActivated(bytes32 indexed ruleType);
    //// Rule Bypassed Via Rule Bypass Account 
    event RulesBypassedViaRuleBypassAccount(address indexed ruleBypassAccount, address indexed appManager);
}

/**
 *@title Rule Storage Diamond Events Interface
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev This library for all events in the Rule Processor Module for the protocol. Each contract in the access module should inherit this library for emitting events.
 * @notice Rule Processor Module Events Library
 */
interface IRuleStorageDiamondEvents {
    ///RuleStorageDiamond
    event RuleStorageDiamondDeployed(address indexed econRuleDiamond);
}

/**
 * @title Economic Events Interface
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev This library for all events in the Rule Processor Module for the protocol. Each contract in the access module should inherit this library for emitting events.
 * @notice Rule Processor Module Events Library
 */

interface IEconomicEvents {
    /// Generic Rule Creation Event
    event ProtocolRuleCreated(bytes32 indexed ruleType, uint32 indexed ruleId, bytes32[] extraTags);
    ///TokenRuleRouterProxy
    event newHandler(address indexed Handler);
}

/**
 * @title Tokem Handler Events Interface
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev This library for all protocol Handler Events. Each contract in the access module should inherit this library for emitting events.
 * @notice Handler Events Library
 */
interface ITokenHandlerEvents {
    ///Handler
    event HandlerDeployed(address indexed appManager);
    /// Rule applied
    event ApplicationHandlerActionApplied(bytes32 indexed ruleType, ActionTypes action, uint32 indexed ruleId);
    event ApplicationHandlerSimpleActionApplied(bytes32 indexed ruleType, ActionTypes action, uint256 indexed param1);
    /// Rule deactivated
    event ApplicationHandlerActionDeactivated(bytes32 indexed ruleType, ActionTypes action);
    /// Rule activated
    event ApplicationHandlerActionActivated(bytes32 indexed ruleType, ActionTypes action);
    /// NFT Valuation Limit Updated
    event NFTValuationLimitUpdated(uint256 indexed nftValuationLimit);
    event AppManagerAddressSet(address indexed _address);
    event AppManagerAddressProposed(address indexed _address);
    /// Fees
    event FeeActivationSet(bool indexed _activation);
    /// Configuration
    event ERC721AddressSet(address indexed _address);
}

/**
 * @title Application Events
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev This library for all events for the Application ecosystems. Each Contract should inherit this library for emitting events.
 * @notice Application Events Library
 */

interface IApplicationEvents {
    /// Application Handler
    event HandlerConnected(address indexed handlerAddress, address indexed assetAddress); // ...in favor of this one since regular deploy and upgrade now looks the same?
    ///ProtocolERC20
    event NewTokenDeployed(address indexed applicationCoin, address indexed appManagerAddress);
    ///ProtocolERC721 & ERC721A
    event NewNFTDeployed(address indexed applicationNFT, address indexed appManagerAddress);
    ///AMM
    event AMMDeployed(address indexed ammAddress);
    event Swap(address indexed tokenIn, uint256 amountIn, uint256 amountOut);
    event AddLiquidity(address token0, address token1, uint256 amount0, uint256 amount1);
    event RemoveLiquidity(address token, uint256 amount);
    ///ERC20Pricing
    event TokenPrice(address indexed token, uint256 indexed price);
    ///NFTPricing
    event SingleTokenPrice(address indexed collection, uint256 indexed tokenID, uint256 indexed price);
    event CollectionPrice(address indexed collection, uint256 indexed price);
    ///Fees
    event FeeType(bytes32 indexed tag, bool indexed add, uint256 minBalance, uint256 maxBalance, int256 feePercentage, address targetAccount);
    ///AppManager set
    event AppManagerAddressSet(address indexed _address);
}
