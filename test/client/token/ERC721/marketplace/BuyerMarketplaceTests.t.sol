// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/client/token/TokenUtils.sol";
import "test/client/token/ERC721/util/NftMarketplace.sol";
import "test/client/token/ERC721/util/ERC721Util.sol";
import "test/client/token/ERC20/util/ERC20Util.sol";
import "test/util/TestArrays.sol";
import "forge-std/Test.sol";


import {ActionTypes} from "src/common/ActionEnum.sol";
import "src/common/IErrors.sol";

/**
 * @title MarketplaceTests
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett, @mpetersoCode55, @VoR0220
 * @dev This is to test rule functionality with the operator style marketplace.
 */
contract MarketplaceNonCustodialTestsErc20SellsNftBuys is TokenUtils, ERC721Util {
    NftMarketplace public marketplace;
    uint constant buyPrice = 100_000_000_000;
    uint constant NFT_ID_1 = 0;
    uint constant NFT_ID_2 = 1;

    // made as an attempt to get around a stack too deep error in the testing
    struct MaxTradeSizeTest {
        bytes32 tag;
        uint240 maxTradeSize;
        uint16 period;
        uint32 ruleId;
        ActionTypes[] actionTypes;
        address handler;
        bytes expectedError;
    }

    function setUp() public {
        marketplace = new NftMarketplace();
        setUpProcotolAndCreateERC721MinLegacyAndDiamondHandler();
        switchToAppAdministrator();
        applicationCoin.mint(user1, buyPrice + 1);
        applicationNFTv2.safeMint(user2);
        vm.stopPrank();

        vm.startPrank(user1);
        applicationCoin.approve(address(marketplace), buyPrice);
        vm.stopPrank();
        vm.startPrank(user2);
        applicationNFTv2.approve(address(marketplace), NFT_ID_1);
        marketplace.listItem(address(applicationNFTv2), NFT_ID_1, address(applicationCoin), buyPrice);
        vm.stopPrank();
    }

    function test_inBuyersOperatorMarketplace_accountDenyForNoAccessLevel_ERC20Sell() public endWithStopPrank() {
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user2, 1);
        vm.stopPrank();
        // create rule for sell only
        ActionTypes[] memory actionTypes = new ActionTypes[](1);
        actionTypes[0] = ActionTypes.SELL;
        createAccountDenyForNoAccessLevelRuleFull(actionTypes);

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IAccessLevelErrors.NotAllowedForAccessLevel.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_accountDenyForNoAccessLevel_ERC20Buy() public endWithStopPrank() {
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user2, 1);
        vm.stopPrank();
        // create rule for buy only
        ActionTypes[] memory actionTypes = new ActionTypes[](1);
        actionTypes[0] = ActionTypes.BUY;
        createAccountDenyForNoAccessLevelRuleFull(actionTypes);

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IAccessLevelErrors.NotAllowedForAccessLevel.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_accountDenyForNoAccessLevel_ERC721Sell() public endWithStopPrank() {
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user1, 1);
        vm.stopPrank();
        // create rule for sell only
        ActionTypes[] memory actionTypes = new ActionTypes[](1);
        actionTypes[0] = ActionTypes.SELL;
        createAccountDenyForNoAccessLevelRuleFull(actionTypes);

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IAccessLevelErrors.NotAllowedForAccessLevel.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_accountDenyForNoAccessLevel_ERC721Buy() public endWithStopPrank() {
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user2, 1);
        vm.stopPrank();
        // create rule for buy only
        ActionTypes[] memory actionTypes = new ActionTypes[](1);
        actionTypes[0] = ActionTypes.BUY;
        createAccountDenyForNoAccessLevelRuleFull(actionTypes);

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IAccessLevelErrors.NotAllowedForAccessLevel.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_accountDenyForNoAccessLevel_HappyPath() public endWithStopPrank() {
        // give them access level
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user2, 1);
        applicationAppManager.addAccessLevel(user1, 1);
        vm.stopPrank();

        // create rule for buy only
        ActionTypes[] memory actionTypes = new ActionTypes[](2);
        actionTypes[0] = ActionTypes.BUY;
        actionTypes[1] = ActionTypes.SELL;
        createAccountDenyForNoAccessLevelRuleFull(actionTypes);

        vm.startPrank(user1, user1);
        vm.expectEmit(address(marketplace));
        emit NftMarketplace.ItemBought(user1, address(applicationNFTv2), 0, buyPrice);
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function _riskScoreHelper() internal returns (uint8[] memory riskScores, uint48[] memory txLimits, uint32 ruleId) {
        riskScores = new uint8[](2);
        riskScores[0] = 25;
        riskScores[1] = 50;
        txLimits = new uint48[](2);
        txLimits[0] = uint48(buyPrice);
        txLimits[1] = uint48(99);
        ruleId = createAccountMaxTxValueByRiskRule(riskScores, txLimits);

        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(applicationCoin), 10 * (10 ** 26)); //setting at $1
        erc721Pricer.setNFTCollectionPrice(address(applicationNFTv2), buyPrice * (10 ** 26)); //setting at $1,000,000,000
        vm.stopPrank();

        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, riskScores[1]);
        applicationAppManager.addRiskScore(user2, riskScores[1]);
        vm.stopPrank();
    }

    // expecting it to revert on erc20 sell
    function test_inBuyersOperatorMarketplace_accountMaxTxValueByRiskScore_ERC20Sell() public endWithStopPrank() {
        (, , uint32 ruleId) = _riskScoreHelper();

        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.SELL, ruleId);

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IRiskErrors.OverMaxTxValueByRiskScore.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
        vm.stopPrank();
    }

    // expecting it to revert on erc721 buy
    function test_inBuyersOperatorMarketplace_accountMaxTxValueByRiskScore_ERC721Buy() public endWithStopPrank() {
        (, , uint32 ruleId) = _riskScoreHelper();

        // test that buy fails
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.BUY, ruleId);
        
        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(applicationCoin), 10 * (10 ** 18)); //setting at $1
        vm.stopPrank();

        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, 25);
        vm.stopPrank();

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IRiskErrors.OverMaxTxValueByRiskScore.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
        vm.stopPrank();
    }
    
    // expecting it to revert on erc20 buy
    function test_inBuyersOperatorMarketplace_accountMaxTxValueByRiskScore_ERC20Buy() public endWithStopPrank() {
        (, , uint32 ruleId) = _riskScoreHelper();

        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.BUY, ruleId);

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IRiskErrors.OverMaxTxValueByRiskScore.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
        vm.stopPrank();
    }

    // expecting it to revert on erc721 sell
    function test_inBuyersOperatorMarketplace_accountMaxTxValueByRiskScore_ERC721Sell() public endWithStopPrank() {
        (, , uint32 ruleId) = _riskScoreHelper();
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.SELL, ruleId);
                
        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(applicationCoin), 10 * (10 ** 18)); //setting at $1
        vm.stopPrank();

        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, 25);
        vm.stopPrank();

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IRiskErrors.OverMaxTxValueByRiskScore.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
        vm.stopPrank();
    }

        // expecting it to revert on erc721 sell
    function test_inBuyersOperatorMarketplace_accountMaxTxValueByRiskScore_HappyPath() public endWithStopPrank() {
        (uint8[] memory riskScores, , uint32 ruleId) = _riskScoreHelper();
        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(applicationCoin), 10 * (10 ** 18)); //setting at $1
        erc721Pricer.setNFTCollectionPrice(address(applicationNFTv2), buyPrice * (10 ** 18)); //setting at $1,000,000,000
        vm.stopPrank();

        ActionTypes[] memory actionTypes = new ActionTypes[](2);
        actionTypes[0] = ActionTypes.SELL;
        actionTypes[1] = ActionTypes.BUY;
        uint32[] memory ruleIds = new uint32[](2);
        ruleIds[0] = ruleId;
        ruleIds[1] = ruleId;
        setAccountMaxTxValueByRiskRuleFull(actionTypes, ruleIds);

        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, riskScores[0]);
        applicationAppManager.addRiskScore(user2, riskScores[0]);
        vm.stopPrank();

        vm.prank(user1);
        vm.expectEmit(address(marketplace));
        emit NftMarketplace.ItemBought(user1, address(applicationNFTv2), NFT_ID_1, buyPrice);
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function getRuleForMaxTradeSize(uint8 i) internal returns (MaxTradeSizeTest memory) {
        vm.warp(Blocktime);
        switchToAppAdministrator();
        applicationNFTv2.safeMint(user2); // give them a 2nd NFT
        applicationCoin.mint(user1, 2);
        vm.stopPrank();
        vm.startPrank(user2);
        applicationNFTv2.approve(address(marketplace), NFT_ID_2);
        marketplace.listItem(address(applicationNFTv2), NFT_ID_2, address(applicationCoin), 1);
        vm.stopPrank();

        vm.startPrank(user1, user1);
        applicationCoin.approve(address(marketplace), applicationCoin.balanceOf(user1));
        vm.stopPrank();

        bytes32 justBuyTag = "JUSTBUY";
        bytes32 justSellTag = "JUSTSELL";
        bytes32 buyAndSellTag = "BUYANDSELL";
        uint240 maxTradeSizeERC20 = uint240(buyPrice - 1);
        uint240 maxTradeSizeERC721 = uint240(1);
        uint16 period = 1;
        ActionTypes[] memory justBuy = createActionTypeArray(ActionTypes.BUY);
        ActionTypes[] memory justSell = createActionTypeArray(ActionTypes.SELL);
        ActionTypes[] memory buyAndSell = createActionTypeArray(ActionTypes.BUY, ActionTypes.SELL);


        if (i == 0) {
            uint32 justSellRuleIdERC20 = createAccountMaxTradeSizeRule(justSellTag, maxTradeSizeERC20, period);
            return MaxTradeSizeTest({
                tag: justSellTag,
                maxTradeSize: maxTradeSizeERC20,
                period: period,
                ruleId: justSellRuleIdERC20,
                actionTypes: justSell,
                handler: address(applicationCoinHandler),
                expectedError: abi.encodeWithSelector(
                    TransferFailed.selector, 
                    address(applicationCoin), 
                    ITagRuleErrors.OverMaxSize.selector
                )
            });
        } else if (i == 1) {
            uint32 justBuyRuleIdERC20 = createAccountMaxTradeSizeRule(justBuyTag, maxTradeSizeERC20, period);
            return MaxTradeSizeTest({
                tag: justBuyTag,
                maxTradeSize: maxTradeSizeERC20,
                period: period,
                ruleId: justBuyRuleIdERC20,
                actionTypes: justBuy,
                handler: address(applicationCoinHandler),
                expectedError: abi.encodeWithSelector(
                    TransferFailed.selector, 
                    address(applicationCoin), 
                    ITagRuleErrors.OverMaxSize.selector
                )
            });
        } else if (i == 2) {
            uint32 justBuyRuleIdERC721 = createAccountMaxTradeSizeRule(justBuyTag, maxTradeSizeERC721, period);
            return MaxTradeSizeTest({
                tag: justBuyTag,
                maxTradeSize: maxTradeSizeERC721,
                period: period,
                ruleId: justBuyRuleIdERC721,
                actionTypes: justBuy,
                handler: address(applicationNFTHandlerv2),
                expectedError: abi.encodeWithSelector(
                    TransferFailed.selector, 
                    address(applicationNFTv2), 
                    ITagRuleErrors.OverMaxSize.selector
                )
            });
        } else if (i == 3) {
            uint32 justSellRuleIdERC721 = createAccountMaxTradeSizeRule(justSellTag, maxTradeSizeERC721, period);
            return MaxTradeSizeTest({
                tag: justSellTag,
                maxTradeSize: maxTradeSizeERC721,
                period: period,
                ruleId: justSellRuleIdERC721,
                actionTypes: justSell,
                handler: address(applicationNFTHandlerv2),
                expectedError: abi.encodeWithSelector(
                    TransferFailed.selector, 
                    address(applicationNFTv2), 
                    ITagRuleErrors.OverMaxSize.selector
                )
            });
        } else if (i == 4) {
            uint32 buyAndSellRuleIdERC20 = createAccountMaxTradeSizeRule(buyAndSellTag, maxTradeSizeERC20, period);
            return MaxTradeSizeTest({
                tag: buyAndSellTag,
                maxTradeSize: maxTradeSizeERC20,
                period: period,
                ruleId: buyAndSellRuleIdERC20,
                actionTypes: buyAndSell,
                handler: address(applicationCoinHandler),
                expectedError: abi.encodeWithSelector(
                    TransferFailed.selector, 
                    address(applicationCoin), 
                    ITagRuleErrors.OverMaxSize.selector
                )
            });
        } else if (i == 5) {
            uint32 buyAndSellRuleIdERC721 = createAccountMaxTradeSizeRule(buyAndSellTag, maxTradeSizeERC721, period);
            return MaxTradeSizeTest({
                tag: buyAndSellTag,
                maxTradeSize: maxTradeSizeERC721,
                period: period,
                ruleId: buyAndSellRuleIdERC721,
                actionTypes: buyAndSell,
                handler: address(applicationNFTHandlerv2),
                expectedError: abi.encodeWithSelector(
                    TransferFailed.selector, 
                    address(applicationNFTv2), 
                    ITagRuleErrors.OverMaxSize.selector
                )
            });
        } else {
            revert("Invalid i");
        }
    }

    function test_inBuyersOperatorMarketplace_accountMaxTradeSize_ERC20Sell() public endWithStopPrank() {
        MaxTradeSizeTest memory test = getRuleForMaxTradeSize(0);
        setAccountMaxTradeSizeRule(test.handler, test.actionTypes, test.ruleId);
        switchToAppAdministrator();
        applicationAppManager.addTag(user1, test.tag);
        applicationAppManager.addTag(user2, test.tag);
        vm.stopPrank();

        vm.startPrank(user1, user1);
        //marketplace.buyItem(address(applicationNFTv2), NFT_ID_2); // need to buy atleast 1 first to trigger the bad outcome
        if (test.expectedError.length > 0) {
            vm.expectRevert(
                test.expectedError
            );
        }
        marketplace.buyItem(address(applicationNFTv2), 0);
    }

    function test_inBuyersOperatorMarketplace_accountMaxTradeSize_ERC20Buy() public endWithStopPrank() {
        MaxTradeSizeTest memory test = getRuleForMaxTradeSize(1);
        setAccountMaxTradeSizeRule(test.handler, test.actionTypes, test.ruleId);
        switchToAppAdministrator();
        applicationAppManager.addTag(user1, test.tag);
        applicationAppManager.addTag(user2, test.tag);
        vm.stopPrank();

        vm.startPrank(user1, user1);
        //marketplace.buyItem(address(applicationNFTv2), NFT_ID_2); // need to buy atleast 1 first to trigger the bad outcome
        if (test.expectedError.length > 0) {
            vm.expectRevert(
                test.expectedError
            );
        }
        marketplace.buyItem(address(applicationNFTv2), 0);
    }

    function test_inBuyersOperatorMarketplace_accountMaxTradeSize_ERC721Buy() public endWithStopPrank() {
        MaxTradeSizeTest memory test = getRuleForMaxTradeSize(2);
        setAccountMaxTradeSizeRule(test.handler, test.actionTypes, test.ruleId);
        switchToAppAdministrator();
        applicationAppManager.addTag(user1, test.tag);
        applicationAppManager.addTag(user2, test.tag);
        vm.stopPrank();

        vm.startPrank(user1, user1);
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_2); // need to buy atleast 1 first to trigger the bad outcome
        if (test.expectedError.length > 0) {
            vm.expectRevert(
                test.expectedError
            );
        }
        marketplace.buyItem(address(applicationNFTv2), 0);
    }

    function test_inBuyersOperatorMarketplace_accountMaxTradeSize_ERC721Sell() public endWithStopPrank() {
        MaxTradeSizeTest memory test = getRuleForMaxTradeSize(3);
        setAccountMaxTradeSizeRule(test.handler, test.actionTypes, test.ruleId);
        switchToAppAdministrator();
        applicationAppManager.addTag(user1, test.tag);
        applicationAppManager.addTag(user2, test.tag);
        vm.stopPrank();

        vm.startPrank(user1, user1);
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_2); // need to buy atleast 1 first to trigger the bad outcome
        if (test.expectedError.length > 0) {
            vm.expectRevert(
                test.expectedError
            );
        }
        marketplace.buyItem(address(applicationNFTv2), 0);
    }

    function _accountMinMaxTokenBalanceInitializer() internal {
        bytes32[] memory accsERC20 = createBytes32Array("ERC20_SOLIDMIN_SOLIDMAX", "ERC20_SOLIDMIN_NOMAX");
        bytes32[] memory accsERC721 = createBytes32Array("ERC721_NOMIN_SOLIDMAX", "ERC721_SOLIDMIN_SOLIDMAX");
        uint256[] memory minAmountsERC20 = createUint256Array(buyPrice, 250_000);
        uint256[] memory minAmountsERC721 = createUint256Array(0, 1);
        uint256[] memory maxAmountsERC20 = createUint256Array(buyPrice * 10, type(uint256).max);
        uint256[] memory maxAmountsERC721 = createUint256Array(1, 3);

        switchToRuleAdmin();
        uint32 ruleIdERC20 = createAccountMinMaxTokenBalanceRule(accsERC20, minAmountsERC20, maxAmountsERC20);
        uint32 ruleIdERC721 = createAccountMinMaxTokenBalanceRule(accsERC721, minAmountsERC721, maxAmountsERC721);

        setAccountMinMaxTokenBalanceRule(address(applicationCoinHandler), ruleIdERC20);
        setAccountMinMaxTokenBalanceRule(address(applicationNFTHandlerv2), ruleIdERC721);
        vm.warp(Blocktime + 15);
    }

    function _accountMinMaxTokenBalance_ERC721Initializer() internal {
        switchToAppAdministrator();
        applicationNFTv2.safeMint(user2);
        applicationAppManager.addTag(user1, "ERC721_NOMIN_SOLIDMAX");
        applicationAppManager.addTag(user2, "ERC721_SOLIDMIN_SOLIDMAX");
        vm.stopPrank();

        vm.startPrank(user2);
        applicationNFTv2.approve(address(marketplace), NFT_ID_2);
        marketplace.updateListing(address(applicationNFTv2), NFT_ID_1, buyPrice / 2);
        marketplace.listItem(address(applicationNFTv2), NFT_ID_2, address(applicationCoin), buyPrice / 2);
        vm.stopPrank();
    }

    function test_inBuyersOperatorMarketplace_accountMinMaxTokenBalance_ERC20Under() public endWithStopPrank() {
        _accountMinMaxTokenBalanceInitializer();
        switchToAppAdministrator();
        applicationAppManager.addTag(user1, "ERC20_SOLIDMIN_SOLIDMAX");
        applicationAppManager.addTag(user2, "NOMIN_NOMAX");
        vm.stopPrank();

        vm.prank(user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                ITagRuleErrors.UnderMinBalance.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_accountMinMaxTokenBalance_ERC20Over() public endWithStopPrank() {
        _accountMinMaxTokenBalanceInitializer();
        switchToAppAdministrator();
        applicationCoin.mint(user1, buyPrice * 10 + 1);
        applicationAppManager.addTag(user1, "ERC20_SOLIDMIN_NOMAX");
        applicationAppManager.addTag(user2, "ERC20_SOLIDMIN_SOLIDMAX");
        vm.stopPrank();

        vm.startPrank(user2);
        marketplace.updateListing(address(applicationNFTv2), NFT_ID_1, buyPrice * 10 + 1);
        vm.stopPrank();
        
        vm.startPrank(user1);
        applicationCoin.approve(address(marketplace), buyPrice * 10 + 1);

        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                ITagRuleErrors.OverMaxBalance.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_accountMinMaxTokenBalance_ERC721Under() public endWithStopPrank() {
        _accountMinMaxTokenBalanceInitializer();
        _accountMinMaxTokenBalance_ERC721Initializer();

        // now test that the min is being followed
        switchToAppAdministrator();
        applicationAppManager.removeTag(user1, "ERC721_NOMIN_SOLIDMAX");
        applicationAppManager.addTag(user2, "ERC721_SOLIDMIN_SOLIDMAX");
        vm.stopPrank();

        vm.startPrank(user1);
        vm.expectEmit(address(marketplace));
        emit NftMarketplace.ItemBought(user1, address(applicationNFTv2), NFT_ID_1, buyPrice / 2);
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                ITagRuleErrors.UnderMinBalance.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_2);
        vm.stopPrank();
    }

    function test_inBuyersOperatorMarketplace_accountMinMaxTokenBalance_ERC721Over() public endWithStopPrank() {
        _accountMinMaxTokenBalanceInitializer();
        _accountMinMaxTokenBalance_ERC721Initializer();

        vm.startPrank(user1, user1);
        vm.expectEmit(address(marketplace));
        emit NftMarketplace.ItemBought(user1, address(applicationNFTv2), NFT_ID_1, buyPrice / 2);
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);  
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                ITagRuleErrors.OverMaxBalance.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_2);
        vm.stopPrank();
    }

    function test_inBuyersOperatorMarketplace_accountMinMaxTokenBalance_HappyPath() public endWithStopPrank() {
        _accountMinMaxTokenBalanceInitializer();

        switchToAppAdministrator();
        applicationAppManager.addTag(user1, "ERC721_NOMIN_SOLIDMAX");
        applicationAppManager.addTag(user2, "ERC20_SOLIDMIN_SOLIDMAX");
        vm.stopPrank();

        vm.prank(user2);
        marketplace.updateListing(address(applicationNFTv2), NFT_ID_1, buyPrice / 2);

        vm.prank(user1);
        vm.expectEmit(address(marketplace));
        emit NftMarketplace.ItemBought(user1, address(applicationNFTv2), NFT_ID_1, buyPrice / 2);
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function _maxBuySellVolumeSetup() internal view returns (
        ActionTypes[] memory actionTypes, 
        uint16 tokenPercentage, 
        uint16 period, 
        uint256 ERC20TotalSupply, 
        uint256 ERC721TotalSupply, 
        uint64 startTime
    ) {
        actionTypes = new ActionTypes[](1);
        actionTypes[0] = ActionTypes.SELL;
        tokenPercentage = 10;
        period = 1;
        ERC20TotalSupply = applicationCoin.totalSupply();
        ERC721TotalSupply = applicationNFTv2.totalSupply();
        startTime = uint64(block.timestamp); 
    }

    function test_inBuyersOperatorMarketplace_MaxBuySellVolume_ERC20Sell() public endWithStopPrank() {
        (ActionTypes[] memory actionTypes, uint16 tokenPercentage, uint16 period, uint256 ERC20TotalSupply, , uint64 startTime) = _maxBuySellVolumeSetup();
        uint32 ruleId = createTokenMaxBuySellVolumeRule(tokenPercentage, period, ERC20TotalSupply, startTime);
        setTokenMaxBuySellVolumeRule(address(applicationCoinHandler), actionTypes, ruleId);

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IERC20Errors.OverMaxVolume.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_MaxBuySellVolume_ERC20Buy() public endWithStopPrank() {
        (ActionTypes[] memory actionTypes, uint16 tokenPercentage, uint16 period, uint256 ERC20TotalSupply, , uint64 startTime) = _maxBuySellVolumeSetup();
        actionTypes[0] = ActionTypes.BUY;

        uint32 ruleId = createTokenMaxBuySellVolumeRule(tokenPercentage, period, ERC20TotalSupply, startTime);
        setTokenMaxBuySellVolumeRule(address(applicationCoinHandler), actionTypes, ruleId);

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IERC20Errors.OverMaxVolume.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_MaxBuySellVolume_ERC721Sell() public endWithStopPrank() {
        (ActionTypes[] memory actionTypes, uint16 tokenPercentage, uint16 period, , uint256 ERC721TotalSupply, uint64 startTime) = _maxBuySellVolumeSetup();
        uint32 ruleId = createTokenMaxBuySellVolumeRule(tokenPercentage, period, ERC721TotalSupply, startTime);
        setTokenMaxBuySellVolumeRule(address(applicationNFTHandlerv2), actionTypes, ruleId);

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IERC20Errors.OverMaxVolume.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_MaxBuySellVolume_ERC721Buy() public endWithStopPrank() {
        (ActionTypes[] memory actionTypes, uint16 tokenPercentage, uint16 period, , uint256 ERC721TotalSupply, uint64 startTime) = _maxBuySellVolumeSetup();
        actionTypes[0] = ActionTypes.BUY;
        uint32 ruleId = createTokenMaxBuySellVolumeRule(tokenPercentage, period, ERC721TotalSupply, startTime);
        setTokenMaxBuySellVolumeRule(address(applicationNFTHandlerv2), actionTypes, ruleId);

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IERC20Errors.OverMaxVolume.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_MaxBuySellVolume_HappyPath() public endWithStopPrank() {
        (ActionTypes[] memory actionTypes, , uint16 period, , , uint64 startTime) = _maxBuySellVolumeSetup();
        actionTypes = new ActionTypes[](2);
        actionTypes[0] = ActionTypes.BUY;
        actionTypes[1] = ActionTypes.SELL;

        switchToAppAdministrator();
        for (uint i = 0; i < 10; ++i) {
            applicationCoin.mint(user3, buyPrice); // just multiply the amount in an elegant way
            applicationNFTv2.safeMint(user3);
        }
        vm.stopPrank();

        uint32 ruleId = createTokenMaxBuySellVolumeRule(1110, period, applicationCoin.totalSupply(), startTime);
        uint32 ruleId2 = createTokenMaxBuySellVolumeRule(1110, period, applicationNFTv2.totalSupply(), startTime);
        setTokenMaxBuySellVolumeRule(address(applicationCoinHandler), actionTypes, ruleId);
        setTokenMaxBuySellVolumeRule(address(applicationNFTHandlerv2), actionTypes, ruleId2);

        vm.startPrank(user1, user1);
        vm.expectEmit(address(marketplace));
        emit NftMarketplace.ItemBought(user1, address(applicationNFTv2), 0, buyPrice);
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function _setUpTokenMinHoldTime(ActionTypes action) internal {
        vm.warp(Blocktime);
        uint32[] memory ruleId = new uint32[](1);
        ruleId[0] = createTokenMinHoldTimeRule(24);
        ActionTypes[] memory actions = createActionTypeArray(action);
        setTokenMinHoldTimeRuleFull(address(applicationNFTHandlerv2), actions, ruleId);
        assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandlerv2)).isTokenMinHoldTimeActive(action));

        switchToAppAdministrator();
        applicationNFTv2.safeMint(user2);
        vm.stopPrank();

        vm.startPrank(user2, user2);
        applicationNFTv2.approve(address(marketplace), NFT_ID_2);
        marketplace.listItem(address(applicationNFTv2), NFT_ID_2, address(applicationCoin), buyPrice);
        vm.stopPrank();
    }

    function test_inBuyersOperatorMarketplace_tokenMinHoldTime_ERC721Sell() public endWithStopPrank() {
        _setUpTokenMinHoldTime(ActionTypes.SELL);

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IERC721Errors.UnderHoldPeriod.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_2);
    }


    function _oracleRuleSetUp() internal returns (uint32, uint32) {
        // create oracle rule and set users to approve list 
        switchToRuleAdmin();
        // ERC20 Approve Oracle 
        uint32 ruleId = createAccountApproveDenyOracleRule(1);
        setAccountApproveDenyOracleRule(address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // ERC721 Deny Oracle 
        uint32 newRuleId = createAccountApproveDenyOracleRule(0);
        return (ruleId, newRuleId); 
    }

    function test_inBuyersOperatorMarketplace_AccountApproveDenyOracleRules_ApproveAndDenyOracle_ERC20Buy() public endWithStopPrank() {
        (uint32 ruleId, uint32 newRuleId) = _oracleRuleSetUp();
        newRuleId; 
        ruleId;
        // test 1 - Test Buy side of ERC20 Transaction fails if buyer is not approved 
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IERC20Errors.AddressNotApproved.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);

    } 

    function test_inBuyersOperatorMarketplace_AccountApproveDenyOracleRules_ApproveAndDenyOracle_ERC20Sell() public endWithStopPrank() {
        (uint32 ruleId, uint32 newRuleId) = _oracleRuleSetUp();
        ruleId;
        newRuleId;
        // test 2 - Test Sell side of ERC20 Transaction fails if seller is not approved 
        switchToAppAdministrator();
        goodBoys.push(address(user1));
        oracleApproved.addToApprovedList(goodBoys);
        
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IERC20Errors.AddressNotApproved.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_AccountApproveDenyOracleRules_ApproveAndDenyOracle_ERC721Buy() public endWithStopPrank() {
        (uint32 ruleId, uint32 newRuleId) = _oracleRuleSetUp();
        ruleId;
        // test 3 - Test Buy side of ERC721 Transaction fails if buyer is not approved 
        switchToAppAdministrator();
        goodBoys.push(address(user1));
        goodBoys.push(address(user2));
        oracleApproved.addToApprovedList(goodBoys);
        badBoys.push(address(user1));
        oracleDenied.addToDeniedList(badBoys);
        setAccountApproveDenyOracleRule(address(applicationNFTHandlerv2), newRuleId);

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IERC20Errors.AddressIsDenied.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);

    }

    function test_inBuyersOperatorMarketplace_AccountApproveDenyOracleRules_ApproveAndDenyOracle_ERC721Sell() public endWithStopPrank() {
        (uint32 ruleId, uint32 newRuleId) = _oracleRuleSetUp();
        ruleId;
        // test 4 - Test Sell side of ERC20 Transaction fails if buyer is not approved 
        switchToAppAdministrator();
        goodBoys.push(address(user1));
        goodBoys.push(address(user2));
        oracleApproved.addToApprovedList(goodBoys);
        badBoys.push(address(user2));
        oracleDenied.addToDeniedList(badBoys);
        setAccountApproveDenyOracleRule(address(applicationNFTHandlerv2), newRuleId);

        vm.stopPrank();
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IERC20Errors.AddressIsDenied.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_AccountApproveDenyOracleRules_ApproveAndDenyOracle_Full() public endWithStopPrank() {
        (uint32 ruleId, uint32 newRuleId) = _oracleRuleSetUp();
        ruleId;
        // all passing 
        switchToAppAdministrator();
        goodBoys.push(address(user1));
        goodBoys.push(address(user2));
        oracleApproved.addToApprovedList(goodBoys);
        setAccountApproveDenyOracleRule(address(applicationNFTHandlerv2), newRuleId);
        // Both oracle rules active 
        // users approved and no users denied 
        vm.startPrank(user1, user1);
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_AccountApproveDenyOracleRules_DenyAndApproveOracle() public endWithStopPrank() {
        // create oracle rule and set users to approve list 
        switchToRuleAdmin();
        // ERC20 Deny Oracle 
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        switchToAppAdministrator();
        // ERC721 Approve Oracle 
        uint32 newRuleId = createAccountApproveDenyOracleRule(1);
        setAccountApproveDenyOracleRule(address(applicationNFTHandlerv2), newRuleId);

        uint snapshot = vm.snapshot();

        // test 1 - Test Buy side of ERC20 Transaction fails if buyer is not approved 
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IERC20Errors.AddressNotApproved.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);

        // test 2 - Test Sell side of ERC20 Transaction fails if seller is not approved 
        vm.revertTo(snapshot);
        switchToAppAdministrator();
        goodBoys.push(address(user1));
        oracleApproved.addToApprovedList(goodBoys);
        
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IERC20Errors.AddressNotApproved.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);

        // test 3 - Test Buy side of ERC721 Transaction fails if buyer is not approved 
        vm.revertTo(snapshot);
        switchToAppAdministrator();
        goodBoys.push(address(user1));
        goodBoys.push(address(user2));
        oracleApproved.addToApprovedList(goodBoys);
        badBoys.push(address(user1));
        oracleDenied.addToDeniedList(badBoys);
        setAccountApproveDenyOracleRule(address(applicationCoinHandler), ruleId);

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IERC20Errors.AddressIsDenied.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
        // test 4 - Test Sell side of ERC20 Transaction fails if buyer is not approved 

        vm.revertTo(snapshot);
        switchToAppAdministrator();
        goodBoys.push(address(user1));
        goodBoys.push(address(user2));
        oracleApproved.addToApprovedList(goodBoys);
        badBoys.push(address(user2));
        oracleDenied.addToDeniedList(badBoys);
        setAccountApproveDenyOracleRule(address(applicationCoinHandler), ruleId);

        vm.stopPrank();
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IERC20Errors.AddressIsDenied.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);

        // all passing 
        vm.revertTo(snapshot);
        switchToAppAdministrator();
        goodBoys.push(address(user1));
        goodBoys.push(address(user2));
        oracleApproved.addToApprovedList(goodBoys);
        setAccountApproveDenyOracleRule(address(applicationCoinHandler), ruleId);


        // Both oracle rules active 
        // users approved and no users denied 
        vm.startPrank(user1, user1);
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function _oracleFlexibleRuleSetUp() internal returns (uint32, uint32) {
        // create oracle rule and set users to approve list 
        switchToRuleAdmin();
        // ERC20 Approve Oracle 
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(1, 0);
        setAccountApproveDenyOracleFlexibleRule(address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // ERC721 Deny Oracle 
        uint32 newRuleId = createAccountApproveDenyOracleFlexibleRule(0, 3);
        return (ruleId, newRuleId); 
    }

    function test_inBuyersOperatorMarketplace_AccountApproveDenyOracleFlexibleRules_ApproveAndDenyOracleFlexible_ERC20Buy() public endWithStopPrank() {
        (uint32 ruleId, uint32 newRuleId) = _oracleFlexibleRuleSetUp();
        newRuleId; 
        ruleId;
        // test 1 - Test Buy side of ERC20 Transaction fails if buyer is not approved 
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IERC20Errors.AddressNotApproved.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);

    } 

    function test_inBuyersOperatorMarketplace_AccountApproveDenyOracleFlexibleRules_ApproveAndDenyOracleFlexible_ERC20Sell() public endWithStopPrank() {
        (uint32 ruleId, uint32 newRuleId) = _oracleFlexibleRuleSetUp();
        ruleId;
        newRuleId;
        // test 2 - Test Sell side of ERC20 Transaction fails if seller is not approved 
        switchToAppAdministrator();
        goodBoys.push(address(user1));
        oracleApproved.addToApprovedList(goodBoys);
        
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IERC20Errors.AddressNotApproved.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_AccountApproveDenyOracleFlexibleRules_ApproveAndDenyOracleFlexible_ERC721Buy() public endWithStopPrank() {
        (uint32 ruleId, uint32 newRuleId) = _oracleFlexibleRuleSetUp();
        ruleId;
        // test 3 - Test Buy side of ERC721 Transaction fails if buyer is not approved 
        switchToAppAdministrator();
        goodBoys.push(address(user1));
        goodBoys.push(address(user2));
        oracleApproved.addToApprovedList(goodBoys);
        badBoys.push(address(user1));
        oracleDenied.addToDeniedList(badBoys);
        setAccountApproveDenyOracleFlexibleRule(address(applicationNFTHandlerv2), newRuleId);

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IERC20Errors.AddressIsDenied.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);

    }

    function test_inBuyersOperatorMarketplace_AccountApproveDenyOracleFlexibleRules_ApproveAndDenyOracleFlexible_ERC721Sell() public endWithStopPrank() {
        (uint32 ruleId, uint32 newRuleId) = _oracleFlexibleRuleSetUp();
        ruleId;
        // test 4 - Test Sell side of ERC20 Transaction fails if buyer is not approved 
        switchToAppAdministrator();
        goodBoys.push(address(user1));
        goodBoys.push(address(user2));
        oracleApproved.addToApprovedList(goodBoys);
        badBoys.push(address(user2));
        oracleDenied.addToDeniedList(badBoys);
        setAccountApproveDenyOracleFlexibleRule(address(applicationNFTHandlerv2), newRuleId);

        vm.stopPrank();
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IERC20Errors.AddressIsDenied.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_AccountApproveDenyOracleFlexibleRules_ApproveAndDenyOracleFlexible_Full() public endWithStopPrank() {
        (uint32 ruleId, uint32 newRuleId) = _oracleFlexibleRuleSetUp();
        ruleId;
        // all passing 
        switchToAppAdministrator();
        goodBoys.push(address(user1));
        goodBoys.push(address(user2));
        oracleApproved.addToApprovedList(goodBoys);
        setAccountApproveDenyOracleFlexibleRule(address(applicationNFTHandlerv2), newRuleId);
        // Both oracle rules active 
        // users approved and no users denied 
        vm.startPrank(user1, user1);
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_AccountApproveDenyOracleFlexibleRules_DenyAndApproveOracleFlexible() public endWithStopPrank() {
        // create oracle rule and set users to approve list 
        switchToRuleAdmin();
        // ERC20 Deny Oracle 
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(0, 3);
        switchToAppAdministrator();
        // ERC721 Approve Oracle 
        uint32 newRuleId = createAccountApproveDenyOracleFlexibleRule(1, 0);
        setAccountApproveDenyOracleFlexibleRule(address(applicationNFTHandlerv2), newRuleId);

        uint snapshot = vm.snapshot();

        // test 1 - Test Buy side of ERC20 Transaction fails if buyer is not approved 
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IERC20Errors.AddressNotApproved.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);

        // test 2 - Test Sell side of ERC20 Transaction fails if seller is not approved 
        vm.revertTo(snapshot);
        switchToAppAdministrator();
        goodBoys.push(address(user1));
        oracleApproved.addToApprovedList(goodBoys);
        
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IERC20Errors.AddressNotApproved.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);

        // test 3 - Test Buy side of ERC721 Transaction fails if buyer is not approved 
        vm.revertTo(snapshot);
        switchToAppAdministrator();
        goodBoys.push(address(user1));
        goodBoys.push(address(user2));
        oracleApproved.addToApprovedList(goodBoys);
        badBoys.push(address(user1));
        oracleDenied.addToDeniedList(badBoys);
        setAccountApproveDenyOracleFlexibleRule(address(applicationCoinHandler), ruleId);

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IERC20Errors.AddressIsDenied.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
        // test 4 - Test Sell side of ERC20 Transaction fails if buyer is not approved 

        vm.revertTo(snapshot);
        switchToAppAdministrator();
        goodBoys.push(address(user1));
        goodBoys.push(address(user2));
        oracleApproved.addToApprovedList(goodBoys);
        badBoys.push(address(user2));
        oracleDenied.addToDeniedList(badBoys);
        setAccountApproveDenyOracleFlexibleRule(address(applicationCoinHandler), ruleId);

        vm.stopPrank();
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IERC20Errors.AddressIsDenied.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);

        // all passing 
        vm.revertTo(snapshot);
        switchToAppAdministrator();
        goodBoys.push(address(user1));
        goodBoys.push(address(user2));
        oracleApproved.addToApprovedList(goodBoys);
        setAccountApproveDenyOracleFlexibleRule(address(applicationCoinHandler), ruleId);


        // Both oracle rules active 
        // users approved and no users denied 
        vm.startPrank(user1, user1);
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }


    function _setUpTokenMaxTradingVolumeBuyAction(uint8 handlerType, ActionTypes action, address handler) internal {
        uint32 ruleId;
        vm.warp(Blocktime);
        switchToRuleAdmin();
        // ERC20 Handler 
        if (handlerType == 1){
            /// 40% of total supply allowed to trade
            ruleId = createTokenMaxTradingVolumeRule(4000, 2, Blocktime, 0);
        } 
        // ERC721 Handler 
        if (handlerType == 0){
            /// 10% of total supply allowed to trade 
            ruleId = createTokenMaxTradingVolumeRule(1000, 2, Blocktime, 0);
        }
        setTokenMaxTradingVolumeRuleSingleAction(action, address(handler), ruleId);
    }

    function test_inBuyersOperatorMarketplace_tokenMaxTradingVolume_ERC721Sell() public endWithStopPrank() {
        _setUpTokenMaxTradingVolumeBuyAction(0, ActionTypes.SELL, address(applicationNFTHandlerv2));
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IERC20Errors.OverMaxTradingVolume.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_tokenMaxTradingVolume_ERC721Buy() public endWithStopPrank() {
        _setUpTokenMaxTradingVolumeBuyAction(0, ActionTypes.SELL, address(applicationNFTHandlerv2));
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IERC20Errors.OverMaxTradingVolume.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_tokenMaxTradingVolume_ERC20Sell() public endWithStopPrank() {
        _setUpTokenMaxTradingVolumeBuyAction(1, ActionTypes.SELL, address(applicationCoinHandler));
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IERC20Errors.OverMaxTradingVolume.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_tokenMaxTradingVolume_ERC20Buy() public endWithStopPrank() {
        _setUpTokenMaxTradingVolumeBuyAction(1, ActionTypes.BUY, address(applicationCoinHandler));
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IERC20Errors.OverMaxTradingVolume.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_tokenMaxTradingVolume_FullTrade() public endWithStopPrank() {
         /// set up rule new rules with larger total supply for trade to pass 
        vm.warp(Blocktime);
        switchToRuleAdmin();
        // ERC20 Handler 
        uint32 ruleId = createTokenMaxTradingVolumeRule(4000, 2, Blocktime, 400_000_000_000_000);
        // ERC721 Handler 
        uint32 erc721RuleId = createTokenMaxTradingVolumeRule(1000, 2, Blocktime, 1000);
        
        setTokenMaxTradingVolumeRuleSingleAction(ActionTypes.BUY, address(applicationCoinHandler), ruleId);
        setTokenMaxTradingVolumeRuleSingleAction(ActionTypes.SELL, address(applicationNFTHandlerv2), erc721RuleId);

        vm.startPrank(user1, user1);
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function _setUpTokenMinTxSizeAction(uint8 handlerType, ActionTypes action, address handler) internal {
        uint32 ruleId;
        vm.warp(Blocktime);
        switchToRuleAdmin();
        // ERC20 Handler 
        if (handlerType == 1){
            ruleId = createTokenMinimumTransactionRule(100_000_000_000_000);
            switchToRuleAdmin();
            ActionTypes[] memory actionTypes = createActionTypeArray(action);
            ERC20NonTaggedRuleFacet(address(handler)).setTokenMinTxSizeId(actionTypes, ruleId);
        } 
        // ERC721 Handler 
        if (handlerType == 0){
            ruleId = createTokenMinimumTransactionRule(2);
            switchToRuleAdmin();
            ActionTypes[] memory actionTypes = createActionTypeArray(action);
            ERC721NonTaggedRuleFacet(address(handler)).setTokenMinTxSizeId(actionTypes, ruleId);
        }
    }

    function test_inSellersOperatorMarketplace_tokenMinTxSize_ERC721Sell() public endWithStopPrank() {
        _setUpTokenMinTxSizeAction(0, ActionTypes.SELL, address(applicationNFTHandlerv2));
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IERC20Errors.UnderMinTxSize.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inSellersOperatorMarketplace_tokenMinTxSize_ERC721Buy() public endWithStopPrank() {
        _setUpTokenMinTxSizeAction(0, ActionTypes.BUY, address(applicationNFTHandlerv2));
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IERC20Errors.UnderMinTxSize.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_tokenMinTxSize_ERC20Sell() public endWithStopPrank() {
        _setUpTokenMinTxSizeAction(1, ActionTypes.SELL, address(applicationCoinHandler));
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IERC20Errors.UnderMinTxSize.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_tokenMinTxSize_ERC20Buy() public endWithStopPrank() {
        _setUpTokenMinTxSizeAction(1, ActionTypes.BUY, address(applicationCoinHandler));
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IERC20Errors.UnderMinTxSize.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inBuyersOperatorMarketplace_tokenMinTxSize_FullTrade() public endWithStopPrank() {
        /// set up rule new rules with larger total supply for trade to pass 
        vm.warp(Blocktime);
        switchToRuleAdmin();
        // ERC20 Handler 
        uint32 ruleId = createTokenMinimumTransactionRule(100_000_000);
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.SELL);
        ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).setTokenMinTxSizeId(actionTypes, ruleId);
        // ERC721 Handler 
        uint32 erc721RuleId = createTokenMinimumTransactionRule(1);
        switchToRuleAdmin();
        ActionTypes[] memory erc721ActionTypes = createActionTypeArray(ActionTypes.BUY);
        ERC721NonTaggedRuleFacet(address(applicationNFTHandlerv2)).setTokenMinTxSizeId(erc721ActionTypes, erc721RuleId);
    
        vm.startPrank(user1, user1);
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function _setUpTokenMaxDailyTradesAction(ActionTypes action, address handler) internal {
        vm.warp(Blocktime);
        switchToRuleAdmin();
        uint32 ruleId = createTokenMaxDailyTradesRule("BoredGrape", "DiscoPunk", 0, 5);
        setTokenMaxDailyTradesRuleSingleAction(action, address(handler), ruleId);
        switchToAppAdministrator();
        applicationAppManager.addTag(address(applicationNFTv2), "BoredGrape"); ///add tag
    }

    function test_inSellersOperatorMarketplace_tokenMaxDailyTrades_ERC721Sell() public endWithStopPrank() {
        _setUpTokenMaxDailyTradesAction(ActionTypes.SELL, address(applicationNFTHandlerv2));
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IERC721Errors.OverMaxDailyTrades.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inSellersOperatorMarketplace_tokenMaxDailyTrades_ERC721Buy() public endWithStopPrank() {
        _setUpTokenMaxDailyTradesAction(ActionTypes.BUY, address(applicationNFTHandlerv2));
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IERC721Errors.OverMaxDailyTrades.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_inSellersOperatorMarketplace_tokenMaxDailyTrades_FullTrade() public endWithStopPrank() {
        /// set up rule new rules with larger total supply for trade to pass 
        _setUpTokenMaxDailyTradesAction(ActionTypes.BUY, address(applicationNFTHandlerv2));
        switchToAppAdministrator();
        applicationAppManager.removeTag(address(applicationNFTv2), "BoredGrape"); ///remove previous tag
        applicationAppManager.addTag(address(applicationNFTv2), "DiscoPunk"); ///add tag

        vm.startPrank(user1, user1);
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_accountMaxValueByRiskScore_inOperatorMarketplace_ERC20Buy() public endWithStopPrank {
        uint8[] memory riskScores = new uint8[](2);
        riskScores[0] = 25;
        riskScores[1] = 50;
        uint48[] memory txLimits = new uint48[](2);
        txLimits[0] = uint48(buyPrice);
        txLimits[1] = uint48(99);

        uint32 ruleId = createAccountMaxValueByRiskRule(riskScores, txLimits);
        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(applicationCoin), 10 * (10 ** 26)); //setting at $1
        erc721Pricer.setNFTCollectionPrice(address(applicationNFTv2), buyPrice * (10 ** 26)); //setting at $1,000,000,000
        vm.stopPrank();

        setAccountMaxValueByRiskRuleSingleAction(ActionTypes.BUY, ruleId);

        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, riskScores[0]);
        applicationAppManager.addRiskScore(user2, riskScores[1]);
        
        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2),
                IRiskErrors.OverMaxAccValueByRiskScore.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_accountMaxValueByRiskScore_inOperatorMarketplace_ERC721Buy() public endWithStopPrank {
        uint8[] memory riskScores = new uint8[](2);
        riskScores[0] = 25;
        riskScores[1] = 50;
        uint48[] memory txLimits = new uint48[](2);
        txLimits[0] = uint48(buyPrice);
        txLimits[1] = uint48(99);

        uint32 ruleId = createAccountMaxValueByRiskRule(riskScores, txLimits);
        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(applicationCoin), 10 * (10 ** 26)); //setting at $1
        erc721Pricer.setNFTCollectionPrice(address(applicationNFTv2), buyPrice * (10 ** 26)); //setting at $1,000,000,000
        vm.stopPrank();

        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, riskScores[1]);
        applicationAppManager.addRiskScore(user2, riskScores[0]);
        
        setAccountMaxValueByRiskRuleSingleAction(ActionTypes.BUY, ruleId);

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IRiskErrors.OverMaxAccValueByRiskScore.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_accountMaxValueByRiskScore_inOperatorMarketplace_HappyPath() public endWithStopPrank {
        uint8[] memory riskScores = new uint8[](2);
        riskScores[0] = 25;
        riskScores[1] = 50;
        uint48[] memory txLimits = new uint48[](2);
        txLimits[0] = uint48(buyPrice);
        txLimits[1] = uint48(99);

        uint32 ruleId = createAccountMaxValueByRiskRule(riskScores, txLimits);
        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(applicationCoin), 10 * (10 ** 26)); //setting at $1
        erc721Pricer.setNFTCollectionPrice(address(applicationNFTv2), buyPrice * (10 ** 26)); //setting at $1,000,000,000
        vm.stopPrank();
        
        setAccountMaxValueByRiskRuleSingleAction(ActionTypes.BUY, ruleId);

        vm.startPrank(user1, user1);
        vm.expectEmit(address(marketplace));
        emit NftMarketplace.ItemBought(user1, address(applicationNFTv2), NFT_ID_1, buyPrice);
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_accountMaxValueByAccessLevel_inOperatorMarketplace_ERC20Buy() public endWithStopPrank {
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user2, 0);
        applicationAppManager.addAccessLevel(user1, 4);
        ActionTypes action = ActionTypes.BUY;
        switchToRuleAdmin();
        uint32[] memory ruleIds = new uint32[](1);
        ruleIds[0] = createAccountMaxValueByAccessLevelRule(0, 1, 10, 50, 100_000_000_000);
        setAccountMaxValueByAccessLevelRuleFull(createActionTypeArray(action), ruleIds);

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IAccessLevelErrors.OverMaxValueByAccessLevel.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_accountMaxValueByAccessLevel_inOperatorMarketplace_ERC721Buy() public endWithStopPrank {
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user1, 0);
        applicationAppManager.addAccessLevel(user2, 4);
        vm.stopPrank();

        ActionTypes action = ActionTypes.BUY;
        switchToRuleAdmin();
        uint32[] memory ruleIds = new uint32[](1);
        ruleIds[0] = createAccountMaxValueByAccessLevelRule(0, 1, 10, 50, 100);
        setAccountMaxValueByAccessLevelRuleFull(createActionTypeArray(action), ruleIds);

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationNFTv2), 
                IAccessLevelErrors.OverMaxValueByAccessLevel.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_accountMaxValueByAccessLevel_inOperatorMarketplace_Buy_HappyPath() public endWithStopPrank {
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user2, 4);
        applicationAppManager.addAccessLevel(user1, 4);
        vm.stopPrank();

        ActionTypes action = ActionTypes.BUY;
        switchToRuleAdmin();
        uint32[] memory ruleIds = new uint32[](1);
        ruleIds[0] = createAccountMaxValueByAccessLevelRule(0, 1, 10, 50, 100_000_000_000);
        setAccountMaxValueByAccessLevelRuleFull(createActionTypeArray(action), ruleIds);

        vm.startPrank(user1, user1);
        vm.expectEmit(address(marketplace));
        emit NftMarketplace.ItemBought(user1, address(applicationNFTv2), 0, buyPrice);
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_accountMaxValueOutByAccessLevel_inOperatorMarketplace_ERC20Buy() public endWithStopPrank {
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user1, 0);
        applicationAppManager.addAccessLevel(user2, 4);

        ActionTypes action = ActionTypes.SELL;
        switchToRuleAdmin();
        uint32[] memory ruleIds = new uint32[](1);
        ruleIds[0] = createAccountMaxValueOutByAccessLevelRule(0, 1, 10, 50, 100_000_000_000_000);
        setAccountMaxValueOutByAccessLevelRuleFull(createActionTypeArray(action), ruleIds);
        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(applicationCoin), 10 * (10 ** 26)); //setting at $1
        erc721Pricer.setNFTCollectionPrice(address(applicationNFTv2), buyPrice * (10 ** 26)); //setting at $1,000,000,000

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector, 
                address(applicationCoin), 
                IAccessLevelErrors.OverMaxValueOutByAccessLevel.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_accountMaxValueOutByAccessLevel_inOperatorMarketplace_ERC721Buy() public endWithStopPrank {
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user1, 4);
        applicationAppManager.addAccessLevel(user2, 0);

        ActionTypes action = ActionTypes.SELL;
        switchToRuleAdmin();
        uint32[] memory ruleIds = new uint32[](1);
        ruleIds[0] = createAccountMaxValueOutByAccessLevelRule(0, 1, 10, 50, 100_000_000_000);
        setAccountMaxValueOutByAccessLevelRuleFull(createActionTypeArray(action), ruleIds);
        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(applicationCoin), 10 * (10 ** 26)); //setting at $1
        erc721Pricer.setNFTCollectionPrice(address(applicationNFTv2), buyPrice * (10 ** 26)); //setting at $1,000,000,000

        vm.startPrank(user1, user1);
        vm.expectRevert(
            abi.encodeWithSelector(
                TransferFailed.selector,
                address(applicationNFTv2), 
                IAccessLevelErrors.OverMaxValueOutByAccessLevel.selector
            )
        );
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }

    function test_accountMaxValueOutByAccessLevel_inOperatorMarketplace_Buy_HappyPath() public endWithStopPrank {
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user1, 4);
        applicationAppManager.addAccessLevel(user2, 1);

        ActionTypes action = ActionTypes.SELL;
        switchToRuleAdmin();
        uint32[] memory ruleIds = new uint32[](1);
        ruleIds[0] = createAccountMaxValueOutByAccessLevelRule(0, 1, 10, 50, 100_000_000_000);
        setAccountMaxValueOutByAccessLevelRuleFull(createActionTypeArray(action), ruleIds);

        vm.startPrank(user1, user1);
        vm.expectEmit(address(marketplace));
        emit NftMarketplace.ItemBought(user1, address(applicationNFTv2), 0, buyPrice);
        marketplace.buyItem(address(applicationNFTv2), NFT_ID_1);
    }
}
