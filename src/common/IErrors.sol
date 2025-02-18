// SPDX-License-Identifier: BUSL-1.1

pragma solidity ^0.8.24;

/**
 * @title Error Interfaces For Protocol Contracts
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett
 * @notice All errors are declared in this file, and then inherited in contracts.
 */

interface IERC721Errors {
    error OverMaxDailyTrades();
    error UnderHoldPeriod();
}

interface IHandlerDiamondErrors{
    error AlreadyInitialized();
}

interface IRuleProcessorErrors {
    error RuleDoesNotExist();
    error NotEnoughBalance();
}

interface IAccessLevelErrors {
    error OverMaxValueByAccessLevel();
    error OverMaxValueOutByAccessLevel();
    error OverMaxReceivedByAccessLevel();
    error NotAllowedForAccessLevel();
    error AccessLevelIsNotValid(uint8 accessLevel);
}

interface IPauseRuleErrors {
    error ApplicationPaused(uint256 started, uint256 ends);
    error InvalidDateWindow(uint256 startDate, uint256 endDate);
    error MaxPauseRulesReached();
}

interface IRiskErrors {
    error OverMaxTxValueByRiskScore(uint8 riskScore, uint256 maxTxSize);
    error OverMaxAccValueByRiskScore();
}

interface IERC20Errors {
    error UnderMinTxSize();
    error AddressIsDenied();
    error AddressNotApproved();
    error OracleTypeInvalid();
    error OverMaxBuyVolume();
    error OverMaxSellVolume();
    error OverMaxVolume();
    error OverMaxTradingVolume();
    error OverMaxSupplyVolatility();
}

interface IMaxTagLimitError {
    error MaxTagLimitReached();
}

interface ITagRuleErrors {
    error OverMaxBalance();
    error UnderMinBalance();
    error TxnInFreezeWindow();
    error OverMaxSellSize();
    error OverMaxSize();
}

interface IInputErrors {
    error IndexOutOfRange();
    error WrongArrayOrder();
    error InputArraysSizesNotValid();
    error InputArraysMustHaveSameLength();
    error ValueOutOfRange(uint256 _value);
    error ZeroValueNotPermited();
    error InvertedLimits();
    error CantMixPeriodicAndNonPeriodic();
    error InvalidOracleType(uint8 _type);
    error InvalidRuleInput();
    error PeriodExceeds5Years();
}

interface IAppRuleInputErrors {
    error InvalidHourOfTheDay();
    error AccessLevelRulesShouldHave5Levels(uint8 inputLevels);
}

interface IRiskInputErrors {
    error RiskLevelCannotExceed99();
    error riskScoreOutOfRange(uint8 riskScore);
}

interface ITagInputErrors {
    error BlankTag();
    error TagAlreadyExists();
}

interface ITagRuleInputErrors {
    error DateInThePast(uint256 date);
    error StartTimeNotValid();
}

interface IPermissionModifierErrors {
    error AppManagerNotConnected();
    error NotAppAdministrator();
    error NotAppAdministratorOrOwner();
    error NotSuperAdmin(address);
    error NotRuleAdministrator();
    error BelowMinAdminThreshold();
}

interface INoAddressToRemove{
    error NoAddressToRemove();
}

interface IAppManagerErrors is INoAddressToRemove{
    error PricingModuleNotConfigured(address _erc20PricingAddress, address nftPricingAddress);
    error NotAccessLevelAdministrator(address _address);
    error NotRiskAdmin(address _address);
    error NotAUser(address _address);
    error AddressAlreadyRegistered();
    error NotRegisteredHandler(address);
    error ProposedAddressCannotBeSuperAdmin();
}

interface AMMCalculatorErrors {
    error AmountsAreZero();
    error InsufficientPoolDepth(uint256 pool, int256 attemptedWithdrawal);
}

interface AMMErrors {
    error TokenInvalid(address);
    error AmountExceedsBalance(uint256);
    error TransferFailed();
}

interface NFTPricingErrors {
    error NotAnNFTContract(address nftContract);
}

interface IStakingErrors {
    error DepositFailed();
    error NotStakingEnough(uint256 minStake);
    error NotStakingForAnyTime();
    error RewardPoolLow(uint256 balance);
    error NoRewardsToClaim();
    error RewardsWillBeZero();
    error InvalidTimeUnit();
}

interface IERC721StakingErrors {
    error TokenNotValidToStake();
    error TokenNotAvailableToWithdraw();
}

interface IProtocolERC20Errors {
    error ExceedingMaxSupply();
    error CallerNotAuthorizedToMint();
}

interface IZeroAddressError {
    error ZeroAddress();
}

interface IAssetHandlerErrors {
    error actionCheckFailed();
    error CannotTurnOffAccountDenyForNoAccessLevelWhileActive();
    error ZeroValueNotPermited();
    error BatchMintBurnNotSupported();
    error FeesAreGreaterThanTransactionAmount(address);
    error AccountApproveDenyOraclesPerAssetLimitReached();
    error InvalidAction();
    error InputArraysMustHaveSameLength();
    error InputArraysSizesNotValid();
}

interface IFeesErrors {
    error FeesAreGreaterThanTransactionAmount(address);
}

interface IOwnershipErrors {
    error ConfirmerDoesNotMatchProposedAddress();
    error NoProposalHasBeenMade();
}

interface IAppHandlerErrors {
    error PricingModuleNotConfigured(address _erc20PricingAddress, address nftPricingAddress);
}