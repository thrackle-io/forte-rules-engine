// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {RuleProcessorDiamondLib as Diamond, RuleDataStorage} from "./RuleProcessorDiamondLib.sol";
import {FeeRuleDataFacet} from "./FeeRuleDataFacet.sol";
import {IFeeRules as Fee} from "./RuleDataInterfaces.sol";
import {IRuleProcessorErrors} from "../../interfaces/IErrors.sol";

/**
 * @title Fee Rule Processor Facet Contract
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev Facet in charge of the logic to check fee rule compliance
 * @notice Implements Token Fee Rules on Accounts.
 */
contract FeeRuleProcessorFacet is IRuleProcessorErrors {
    /**
     * @dev Assess the fee associated with the AMM Fee Rule
     * @param _ruleId Rule Identifier for rule arguments
     * @param _collateralizedTokenAmount total number of collateralized tokens to be swapped(this could be the "token in" or "token out" as the fees are always * assessed from the collateralized token)
     */
    function assessAMMFee(uint32 _ruleId, uint256 _collateralizedTokenAmount) external view returns (uint256) {
        FeeRuleDataFacet data = FeeRuleDataFacet(Diamond.ruleDataStorage().rules);

        if (data.getTotalAMMFeeRules() != 0) {
            Fee.AMMFeeRule memory feeRule = data.getAMMFeeRule(_ruleId);
            /// the percentage is stored as three digits so the true percent is feePercentage/100
            if (feeRule.feePercentage > 0) return (_collateralizedTokenAmount * feeRule.feePercentage) / 10000;
        }
        return 0;
    }
}
