// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "test/client/token/TokenUtils.sol";
import {DummyNFTAMM} from "test/client/token/TestTokenCommon.sol";
import {ApplicationERC721AdminOrOwnerMint as ApplicationERC721} from "src/example/ERC721/ApplicationERC721AdminOrOwnerMint.sol";

/**
 * @title Rule Creation Functions
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev This contract is an abstract template to be reused by all the tests.
 * This contract holds the functions for adding a protocol rule for tests.
 */

abstract contract ERC721Util is TokenUtils, DummyNFTAMM {
    function setAccountApproveDenyOracleRule(address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT, ActionTypes.BURN);
        ERC721NonTaggedRuleFacet(address(assetHandler)).setAccountApproveDenyOracleId(actionTypes, ruleId);
    }

    function setAccountApproveDenyOracleRuleSingleAction(ActionTypes action, address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ERC721NonTaggedRuleFacet(address(assetHandler)).setAccountApproveDenyOracleId(createActionTypeArray(action), ruleId);
    }

    function setAccountApproveDenyOracleRuleFull(address assetHandler, ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        ERC721NonTaggedRuleFacet(address(assetHandler)).setAccountApproveDenyOracleIdFull(actions, ruleIds);
    }

    function setAccountApproveDenyOracleFlexibleRule(address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT, ActionTypes.BURN);
        ERC721NonTaggedRuleFacet(address(assetHandler)).setAccountApproveDenyOracleFlexibleId(actionTypes, ruleId);
    }

    function setAccountApproveDenyOracleFlexibleRuleSingleAction(ActionTypes action, address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ERC721NonTaggedRuleFacet(address(assetHandler)).setAccountApproveDenyOracleFlexibleId(createActionTypeArray(action), ruleId);
    }

    function setAccountApproveDenyOracleFlexibleRuleFull(address assetHandler, ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        ERC721NonTaggedRuleFacet(address(assetHandler)).setAccountApproveDenyOracleFlexibleIdFull(actions, ruleIds);
    }

    function setTokenMaxDailyTradesRule(address assetHandler, uint32 ruleId) public endWithStopPrank endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT);
        ERC721NonTaggedRuleFacet(address(assetHandler)).setTokenMaxDailyTradesId(actionTypes, ruleId);
    }

    function setTokenMaxDailyTradesRuleSingleAction(address assetHandler, ActionTypes[] memory actions, uint32 ruleId) public endWithStopPrank endWithStopPrank {
        switchToRuleAdmin();
        ERC721NonTaggedRuleFacet(address(assetHandler)).setTokenMaxDailyTradesId(actions, ruleId);
    }

    function setTokenMaxDailyTradesRuleSingleAction(ActionTypes action, address assetHandler, uint32 ruleId) public endWithStopPrank endWithStopPrank {
        switchToRuleAdmin();
        ERC721NonTaggedRuleFacet(address(assetHandler)).setTokenMaxDailyTradesId(createActionTypeArray(action), ruleId);
    }

    function setTokenMaxDailyTradesRuleFull(address assetHandler, ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        ERC721NonTaggedRuleFacet(address(assetHandler)).setTokenMaxDailyTradesIdFull(actions, ruleIds);
    }

    function setAccountMinMaxTokenBalanceRule(address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT, ActionTypes.BURN);
        ERC721TaggedRuleFacet(address(assetHandler)).setAccountMinMaxTokenBalanceId(actionTypes, ruleId);
    }

    function setAccountMaxTradeSizeRuleFull(address assetHandler, ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        TradingRuleFacet(address(assetHandler)).setAccountMaxTradeSizeIdFull(actions, ruleIds);
    }

    function setTokenMaxBuySellVolumeIdFull(address assetHandler, ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        TradingRuleFacet(address(assetHandler)).setTokenMaxBuySellVolumeIdFull(actions, ruleIds);
    }

    function setAccountMinMaxTokenBalanceRuleSingleAction(ActionTypes action, address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ERC721TaggedRuleFacet(address(assetHandler)).setAccountMinMaxTokenBalanceId(createActionTypeArray(action), ruleId);
    }

    function setAccountMinMaxTokenBalanceRuleFull(address assetHandler, ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        ERC721TaggedRuleFacet(address(assetHandler)).setAccountMinMaxTokenBalanceIdFull(actions, ruleIds);
    }

    function setAccountMinMaxTokenBalanceRuleSingleAction(address assetHandler, ActionTypes[] memory actions, uint32 ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        ERC721TaggedRuleFacet(address(assetHandler)).setAccountMinMaxTokenBalanceId(actions, ruleIds);
    }

    function setTokenMaxSupplyVolatilityRuleSingleAction(ActionTypes action, address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ERC721NonTaggedRuleFacet(address(assetHandler)).setTokenMaxSupplyVolatilityId(createActionTypeArray(action), ruleId);
    }

    function setTokenMaxSupplyVolatilityRule(address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.MINT, ActionTypes.BURN);
        ERC721NonTaggedRuleFacet(address(assetHandler)).setTokenMaxSupplyVolatilityId(actionTypes, ruleId);
    }

    function setTokenMaxTradingVolumeRule(address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT, ActionTypes.BURN);
        ERC721NonTaggedRuleFacet(address(assetHandler)).setTokenMaxTradingVolumeId(actionTypes, ruleId);
    }

    function setTokenMaxTradingVolumeRuleSingleAction(ActionTypes _action, address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(_action);
        ERC721NonTaggedRuleFacet(address(assetHandler)).setTokenMaxTradingVolumeId(actionTypes, ruleId);
    }
 
    function setTokenMaxSupplyVolatilityRuleFull(address assetHandler, ActionTypes[] memory actions, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ERC721NonTaggedRuleFacet(address(assetHandler)).setTokenMaxSupplyVolatilityIdFull(actions, ruleId);
    }

    function setTokenMaxTradingVolumeRuleFull(address assetHandler, ActionTypes[] memory actions, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ERC721NonTaggedRuleFacet(address(assetHandler)).setTokenMaxTradingVolumeIdFull(actions, ruleId);
    }

    function setTokenMinimumTransactionRule(address assetHandler, uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.BURN, ActionTypes.BUY, ActionTypes.SELL, ActionTypes.MINT);
        ERC721NonTaggedRuleFacet(address(assetHandler)).setTokenMinTxSizeId(actionTypes, ruleId);
    }

    function setTokenMinimumTransactionRuleFull(address assetHandler, ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        ERC721NonTaggedRuleFacet(address(assetHandler)).setTokenMinTxSizeIdFull(actions, ruleIds);
    }

    function setTokenMinHoldTimeRule(uint32 ruleId) public endWithStopPrank {
        switchToRuleAdmin();
        ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).setTokenMinHoldTime(createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.BURN, ActionTypes.SELL), ruleId);
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinHoldTimePeriod(ActionTypes.P2P_TRANSFER), ruleId);
    }

    function setTokenMinHoldTimeRuleFull(address assetHandler, ActionTypes[] memory actions, uint32[] memory ruleIds) public endWithStopPrank {
        switchToRuleAdmin();
        ERC721NonTaggedRuleFacet(address(assetHandler)).setTokenMinHoldTimeFull(actions, ruleIds);
    }
    
    function initializeERC721AMM(address fungibleToken, address nonFungibleToken) public endWithStopPrank returns (DummyNFTAMM amm) {
        amm = new DummyNFTAMM();
        switchToAppAdministrator();

        ApplicationERC20(fungibleToken).mint(address(amm), 1_000_000_000_000 * ATTO);
        ApplicationERC721(nonFungibleToken).safeMint(address(amm));

        assertEq(ApplicationERC20(fungibleToken).balanceOf(address(amm)), 1_000_000_000_000 * ATTO);
        assertEq(ApplicationERC721(nonFungibleToken).balanceOf(address(amm)), 1);    
    }
}
