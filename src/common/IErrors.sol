// SPDX-License-Identifier: MIT

pragma solidity ^0.8.17;

/**
 * @title Error Interfaces For Protocol Contracts
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett
 * @notice All errors are declared in this file, and then inherited in contracts.
 */

interface IERC721Errors {
    error MaxNFTTransferReached();
    error MinimumHoldTimePeriodNotReached();
}

interface IRuleProcessorErrors {
    error RuleDoesNotExist();
}

interface IAccessLevelErrors {
    error BalanceExceedsAccessLevelAllowedLimit();
    error WithdrawalExceedsAccessLevelAllowedLimit();
    error NotAllowedForAccessLevel();
    error AccessLevelIsNotValid(uint8 accessLevel);
}

interface IPauseRuleErrors {
    error ApplicationPaused(uint256 started, uint256 ends);
    error InvalidDateWindow(uint256 startDate, uint256 endDate);
    error MaxPauseRulesReached();
}

interface IRiskErrors {
    error MaxTxSizePerPeriodReached(uint8 riskScore, uint256 maxTxSize, uint16 hoursOfPeriod);
    error TransactionExceedsRiskScoreLimit();
    error BalanceExceedsRiskScoreLimit();
}

interface IERC20Errors {
    error BelowMinTransfer();
    error AddressIsDenied();
    error AddressNotOnAllowedList();
    error OracleTypeInvalid();
    error PurchasePercentageReached();
    error SellPercentageReached();
    error TransferExceedsMaxVolumeAllowed();
    error TotalSupplyVolatilityLimitReached();
}

interface IMaxTagLimitError {
    error MaxTagLimitReached();
}

interface ITagRuleErrors {
    error MaxBalanceExceeded();
    error BalanceBelowMin();
    error TxnInFreezeWindow();
    error TemporarySellRestriction();
}

interface IInputErrors {
    error IndexOutOfRange();
    error WrongArrayOrder();
    error InputArraysSizesNotValid();
    error InputArraysMustHaveSameLength();
    error ValueOutOfRange(uint256 _value);
    error ZeroValueNotPermited();
    error InvertedLimits();
    error InvalidOracleType(uint8 _type);
    error InvalidRuleInput();
}

interface IAppRuleInputErrors {
    error InvalidHourOfTheDay();
    error BalanceAmountsShouldHave5Levels(uint8 inputLevels);
    error WithdrawalAmountsShouldHave5Levels(uint8 inputLevels);
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

interface INoAddressToRemove {
    error NoAddressToRemove();
}

interface IAppManagerErrors is INoAddressToRemove {
    error PricingModuleNotConfigured(address _erc20PricingAddress, address nftPricingAddress);
    error NotAccessTierAdministrator(address _address);
    error NotRiskAdmin(address _address);
    error NotAUser(address _address);
    error AddressAlreadyRegistered();
    error AdminWithdrawalRuleisActive();
    error NotRegisteredHandler(address);
}

interface AMMCalculatorErrors {
    error AmountsAreZero();
    error OutOfRange();
    error ValueOutOfRange(uint256 value);
    error ZeroValueNotPermited();
}


interface CurveErrors{
    error CurvesInvertedOrIntersecting();
}

interface AMMErrors {
    error TokenInvalid(address);
    error AmountExceedsBalance(uint256);
    error TransferFailed();
    error NotTheOwnerOfNFT(uint256 _tokenId);
    error NotEnumerable();
    error NotEnoughTokensForSwap(uint256 _tokensIn,uint256 _tokensRequired);
    error InsufficientPoolDepth(uint256 pool, uint256 attemptedWithdrawal);
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
    error PricingModuleNotConfigured(address _erc20PricingAddress, address nftPricingAddress);
    error actionCheckFailed();
    error CannotTurnOffAccessLevel0WithAccessLevelBalanceActive();
    error PeriodExceeds5Years();
    error ZeroValueNotPermited();
    error BatchMintBurnNotSupported();
    error FeesAreGreaterThanTransactionAmount(address);
}

interface IOwnershipErrors {
    error ConfirmerDoesNotMatchProposedAddress();
    error NoProposalHasBeenMade();
}