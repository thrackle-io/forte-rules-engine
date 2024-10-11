// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/util/TestCommonFoundry.sol";
import "../../TestTokenCommon.sol";
import "test/client/token/ERC721/util/ERC721Util.sol";

abstract contract ERC721CommonTests is TestCommonFoundry, ERC721Util {
    IERC721 testCaseNFT;
    uint256 erc721Liq = 10_000;
    uint256 erc20Liq = 100_000 * ATTO;
    DummyNFTAMM amm;

    function testERC721_ERC721CommonTests_HandlerVersions() public view ifDeploymentTestsEnabled {
        string memory version = VersionFacet(address(applicationNFTHandler)).version();
        assertEq(version, "2.1.0");
    }

    function testERC20_ERC721CommonTests_ERC721Handler_RuleProcessorGetter() public view ifDeploymentTestsEnabled {
        address ruleProcessorAddress = ERC721HandlerMainFacet(address(applicationNFTHandler)).getRuleProcessorAddress();
        assertEq(address(ruleProcessor), ruleProcessorAddress);
    }

    function testERC20_ERC721CommonTests_ERC721Handler_AssetAddressGetter() public view ifDeploymentTestsEnabled {
        address assetAddress = ERC721HandlerMainFacet(address(applicationNFTHandler)).getAssetAddress();
        assertEq(address(testCaseNFT), assetAddress);
    }

    function testERC20_ERC721CommonTests_ERC721Handler_AppManagerAddressGetter() public view ifDeploymentTestsEnabled {
        address appManagerAddress = ERC721HandlerMainFacet(address(applicationNFTHandler)).getAppManagerAddress();
        assertEq(address(applicationAppManager), appManagerAddress);
    }

    function testERC721_ERC721CommonTests_AlreadyInitialized() public endWithStopPrank ifDeploymentTestsEnabled {
        vm.startPrank(address(testCaseNFT));
        vm.expectRevert(abi.encodeWithSignature("AlreadyInitialized()"));
        ERC721HandlerMainFacet(address(applicationNFTHandler)).initialize(user1, user2, user3);
    }

    function testERC721_ERC721CommonTests_NFTEvaluationLimitEventEmission() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        vm.expectEmit(true, true, true, false);
        emit AD1467_NFTValuationLimitUpdated(20);
        ERC721HandlerMainFacet(address(applicationNFTHandler)).setNFTValuationLimit(20);
    }

    function testERC721_ERC721CommonTests_ERC721OnlyTokenCanCallCheckAllRules() public endWithStopPrank ifDeploymentTestsEnabled {
        address handler = IProtocolToken(address(testCaseNFT)).getHandlerAddress();
        assertEq(handler, address(applicationNFTHandler));
        address owner = ERC173Facet(address(applicationNFTHandler)).owner();
        assertEq(owner, address(testCaseNFT));
        vm.expectRevert("UNAUTHORIZED");
        ERC20HandlerMainFacet(handler).checkAllRules(0, 0, user1, user2, user3, 0);
    }

    function testERC721_ERC721CommonTests_Mint() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// Owner Mints new tokenId
        UtilApplicationERC721(address(testCaseNFT)).safeMint(appAdministrator);
        console.log(testCaseNFT.balanceOf(appAdministrator));
        /// Owner Mints a second new tokenId
        UtilApplicationERC721(address(testCaseNFT)).safeMint(appAdministrator);
        console.log(testCaseNFT.balanceOf(appAdministrator));
        assertEq(testCaseNFT.balanceOf(appAdministrator), 2);
    }

    function testERC721_ERC721CommonTests_Transfer_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(appAdministrator);
        testCaseNFT.transferFrom(appAdministrator, user, 0);
        assertEq(testCaseNFT.balanceOf(appAdministrator), 0);
        assertEq(testCaseNFT.balanceOf(user), 1);
    }

    function testERC721_ERC721CommonTests_Transfer_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        vm.expectRevert("ERC721: invalid token ID");
        testCaseNFT.transferFrom(appAdministrator, user, 0);
    }

    function testERC721_ERC721CommonTests_BurnERC721_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        ///Mint and transfer tokenId 0
        UtilApplicationERC721(address(testCaseNFT)).safeMint(appAdministrator);
        testCaseNFT.transferFrom(appAdministrator, appAdministrator, 0);
        ///Mint tokenId 1
        UtilApplicationERC721(address(testCaseNFT)).safeMint(appAdministrator);
        ///Test token burn of token 0 and token 1
        ERC721Burnable(address(testCaseNFT)).burn(1);

        /// Burn appAdministrator token
        ERC721Burnable(address(testCaseNFT)).burn(0);
        assertEq(testCaseNFT.balanceOf(appAdministrator), 0);
    }

    function testERC721_ERC721CommonTests_BurnERC721_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        ///Mint and transfer tokenId 0
        UtilApplicationERC721(address(testCaseNFT)).safeMint(appAdministrator);
        switchToUser();
        ///attempt to burn token that user does not own
        vm.expectRevert("ERC721: caller is not token owner or approved");
        ERC721Burnable(address(testCaseNFT)).burn(0);
    }

    function testERC721_ERC721CommonTests_ZeroAddressChecksERC721() public endWithStopPrank ifDeploymentTestsEnabled {
        if (vm.envAddress("DEPLOYMENT_OWNER") != address(0x0)) {
            vm.expectRevert(0xd92e233d);
            new UtilApplicationERC721("Dracula Coin", "DRAC", address(0x0), "https://SampleApp.io");
        } else {
            vm.expectRevert(0xd92e233d);
            new UtilApplicationERC721("Dracula Coin", "DRAC", address(0x0), "https://SampleApp.io");
            vm.expectRevert(0xba80c9e5);
            IProtocolToken(address(testCaseNFT)).connectHandlerToToken(address(0));
        }

        /// test both address checks in constructor
        applicationNFTHandler = _createERC721HandlerDiamond();

        vm.expectRevert(0xd92e233d);
        ERC721HandlerMainFacet(address(applicationNFTHandler)).initialize(address(0x0), address(applicationAppManager), address(testCaseNFT));
        vm.expectRevert(0xd92e233d);
        ERC721HandlerMainFacet(address(applicationNFTHandler)).initialize(address(ruleProcessor), address(0x0), address(testCaseNFT));
        vm.expectRevert(0xd92e233d);
        ERC721HandlerMainFacet(address(applicationNFTHandler)).initialize(address(ruleProcessor), address(applicationAppManager), address(0x0));

        vm.expectRevert(0xd66c3008);
        applicationHandler.setNFTPricingAddress(address(0x00));
    }

    /// Account Min/Max Token Balance Tests
    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalanceRule_Minimum_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        /// make sure the minimum rules fail results in revert
        _accountMinMaxTokenBalanceRuleSetup(true);
        vm.startPrank(user1, user1);
        vm.expectRevert(0x3e237976);
        testCaseNFT.transferFrom(user1, user3, 4);
    }

    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalanceRule_Maximum_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        ///make sure the maximum rule fail results in revert
        _accountMinMaxTokenBalanceRuleSetup(true);
        switchToAppAdministrator();
        testCaseNFT.transferFrom(appAdministrator, user2, 2);
        for (uint i; i < 5; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
        }

        // transfer to user1 to exceed limit
        vm.startPrank(user2, user2);
        vm.expectRevert(abi.encodeWithSignature("OverMaxBalance()"));
        testCaseNFT.transferFrom(user2, user1, 3);
    }

    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalanceRule_Burning() public endWithStopPrank ifDeploymentTestsEnabled {
        /// test that burn works with rule
        _accountMinMaxTokenBalanceRuleSetup(true);
        vm.startPrank(rich_user, rich_user);
        ERC721Burnable(address(testCaseNFT)).burn(1);
        vm.startPrank(user1, user1);
        vm.expectRevert("ERC721: caller is not token owner or approved");
        ERC721Burnable(address(testCaseNFT)).burn(5);
    }

    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalanceBlankTag_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        ///perform transfer that checks rule
        _accountMinMaxTokenBalanceRuleSetup(false);
        vm.startPrank(user1, user1);
        assertEq(testCaseNFT.balanceOf(user2), 1);
        assertEq(testCaseNFT.balanceOf(user1), 1);
    }

    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalanceBlankTag_Minimum_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        /// make sure the minimum rules fail results in revert
        _accountMinMaxTokenBalanceRuleSetup(false);
        vm.startPrank(user1, user1);
        vm.expectRevert(0x3e237976);
        testCaseNFT.transferFrom(user1, user3, 4);
    }

    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalanceBlankTag_Maximum_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        ///make sure the maximum rule fail results in revert
        _accountMinMaxTokenBalanceRuleSetup(false);
        switchToAppAdministrator();
        testCaseNFT.transferFrom(appAdministrator, rich_user, 5);
        testCaseNFT.transferFrom(appAdministrator, user2, 2);
        vm.startPrank(rich_user, rich_user);
        testCaseNFT.transferFrom(rich_user, user1, 0);
        assertEq(testCaseNFT.balanceOf(user1), 2);
        testCaseNFT.transferFrom(rich_user, user1, 1);
        assertEq(testCaseNFT.balanceOf(user1), 3);
        // one more should revert for max
        vm.startPrank(user2, user2);
        vm.expectRevert(0x1da56a44);
        testCaseNFT.transferFrom(user2, user1, 2);
    }

    // Test that Minting up to the Maximum results in rule check
    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalance_Mint_Maxmimum() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceRuleSetup(true);
        switchToAppAdministrator();
        /// mint 6 NFTs to appAdministrator for transfer
        for (uint i; i < 4; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(rich_user);
        }
        assertEq(testCaseNFT.balanceOf(rich_user), 6);
    }

    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalance_Mint_Maxmimum_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceRuleSetup(true);
        switchToAppAdministrator();
        /// mint 6 NFTs to appAdministrator for transfer
        for (uint i; i < 4; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(rich_user);
        }
        vm.expectRevert(abi.encodeWithSignature("OverMaxBalance()"));
        UtilApplicationERC721(address(testCaseNFT)).safeMint(rich_user);
    }

    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalance_Burn_Minimum() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceRuleSetup(true);
        vm.stopPrank();
        vm.startPrank(rich_user, rich_user);
        UtilApplicationERC721(address(testCaseNFT)).burn(1);
    }
    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalance_Burn_Minimum_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceRuleSetup(true);
        vm.stopPrank();
        vm.startPrank(user1, user1);
        vm.expectRevert(abi.encodeWithSignature("UnderMinBalance()"));
        UtilApplicationERC721(address(testCaseNFT)).burn(4);
    }

    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalance_Buy_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpAccountMinMaxTokenBuySellActions(createActionTypesArray(ActionTypes.BUY));
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 9, true);
        assertEq(testCaseNFT.balanceOf(user), 4);
    }

    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalance_Sell_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpAccountMinMaxTokenBuySellActions(createActionTypesArray(ActionTypes.SELL));
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 11, false);
        assertEq(testCaseNFT.balanceOf(user), 2);
    }

    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalance_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpAccountMinMaxTokenBuySellActions(createActionTypesArray(ActionTypes.SELL));
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 10, false);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 11, false);
        assertEq(testCaseNFT.balanceOf(user), 1);
        vm.expectRevert(abi.encodeWithSignature("UnderMinBalance()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 12, false);
    }

    function _setUpAccountMinMaxTokenBuySellActions(ActionTypes[] memory _action) internal {
        uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array(""), createUint256Array(1), createUint256Array(11));
        setAccountMinMaxTokenBalanceRuleSingleAction(address(applicationNFTHandler), _action, ruleId);
        _setUpNFTAMMForRuleChecks();
    }

    /// Account Approve Deny Oracle Tests
    function testERC721_ERC721CommonTests_AccountApproveDenyOracle_Deny_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        ///perform transfer that checks rule
        // This one should fail
        _accountApproveDenyOracleSetup(true);
        vm.startPrank(user1, user1);
        vm.expectRevert(0x2767bda4);
        testCaseNFT.transferFrom(user1, address(69), 1);
        assertEq(testCaseNFT.balanceOf(address(69)), 0);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracle_Approve_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleSetup(false);
        // This one should fail
        vm.startPrank(user1, user1);
        vm.expectRevert(0xcafd3316);
        testCaseNFT.transferFrom(user1, address(88), 3);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracle_Invalid() public endWithStopPrank ifDeploymentTestsEnabled {
        // Finally, check the invalid type
        vm.expectRevert("Oracle Type Invalid");
        createAccountApproveDenyOracleRule(2);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracle_Burning() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleSetup(true);
        /// swap to user and burn
        vm.startPrank(user1, user1);
        ERC721Burnable(address(testCaseNFT)).burn(4);
        /// set oracle to deny and add address(0) to list to deny burns
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        setAccountApproveDenyOracleRule(address(applicationNFTHandler), ruleId);
        switchToAppAdministrator();
        badBoys.push(address(user1));
        oracleDenied.addToDeniedList(badBoys);
        /// user attempts burn
        vm.startPrank(user1, user1);
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        ERC721Burnable(address(testCaseNFT)).burn(3);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracle_Approve_Burn() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleSetup(false);
        switchToAppAdministrator();
        goodBoys.push(address(user2));
        oracleApproved.addToApprovedList(goodBoys);
        vm.stopPrank();
        vm.startPrank(user2, user2);
        ERC721Burnable(address(testCaseNFT)).burn(0);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracle_Approve_Mint() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleSetup(false);
        switchToAppAdministrator();
        goodBoys.push(address(user2));
        oracleApproved.addToApprovedList(goodBoys);
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user2);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracle_Approve_Buy() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountApproveDenyOracleSetupNoMints(false);
        switchToAppAdministrator();
        goodBoys.push(user);
        goodBoys.push(address(amm));
        oracleApproved.addToApprovedList(goodBoys);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 9, true);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracle_Approve_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountApproveDenyOracleSetupNoMints(false);
        applicationCoin.mint(rich_user, 500);
        vm.stopPrank();
        vm.startPrank(rich_user, rich_user);
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 9, true);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracle_Approve_Sell() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountApproveDenyOracleSetupNoMints(false);
        switchToAppAdministrator();
        goodBoys.push(address(amm));
        oracleApproved.addToApprovedList(goodBoys);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 12, false);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracle_Approve_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        switchToUser();
        UtilApplicationERC721(address(testCaseNFT)).safeTransferFrom(user, rich_user, 12);
        _accountApproveDenyOracleSetupNoMints(false);
        vm.stopPrank();
        vm.startPrank(rich_user, rich_user);
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 12, false);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracle_Deny_Burn() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleSetup(true);
        vm.stopPrank();
        vm.startPrank(user2, user2);
        ERC721Burnable(address(testCaseNFT)).burn(0);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracle_Deny_Mint() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleSetup(true);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user2);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracle_Deny_Buy() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountApproveDenyOracleSetupNoMints(true);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 9, true);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracle_Deny_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountApproveDenyOracleSetupNoMints(true);
        applicationCoin.mint(rich_user, 500);
        vm.stopPrank();
        vm.startPrank(rich_user, rich_user);
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 9, true);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracle_Deny_Sell() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountApproveDenyOracleSetupNoMints(true);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 12, false);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracle_Deny_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        switchToUser();
        UtilApplicationERC721(address(testCaseNFT)).safeTransferFrom(user, rich_user, 12);
        _accountApproveDenyOracleSetupNoMints(true);
        vm.stopPrank();
        vm.startPrank(rich_user, rich_user);
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 12, false);
    }

    /// Account Approve Deny Oracle Flexible Tests
    function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexible_Deny_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        ///perform transfer that checks rule
        // This one should fail
        _accountApproveDenyOracleFlexibleSetup(true, 3);
        vm.startPrank(user1, user1);
        vm.expectRevert(0x2767bda4);
        testCaseNFT.transferFrom(user1, address(69), 1);
        assertEq(testCaseNFT.balanceOf(address(69)), 0);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexible_Approve_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleFlexibleSetup(false, 0);
        // This one should fail
        vm.startPrank(user1, user1);
        vm.expectRevert(0xcafd3316);
        testCaseNFT.transferFrom(user1, address(88), 3);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexible_Invalid() public endWithStopPrank ifDeploymentTestsEnabled {
        // Finally, check the invalid type
        vm.expectRevert("Oracle Type Invalid");
        createAccountApproveDenyOracleFlexibleRule(2, 0);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexible_Burning() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleFlexibleSetup(true, 0);
        /// swap to user and burn
        vm.startPrank(user1, user1);
        ERC721Burnable(address(testCaseNFT)).burn(4);
        /// set oracle to deny and add address(0) to list to deny burns
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(0, 3);
        setAccountApproveDenyOracleFlexibleRule(address(applicationNFTHandler), ruleId);
        switchToAppAdministrator();
        badBoys.push(address(user1));
        oracleDenied.addToDeniedList(badBoys);
        /// user attempts burn
        vm.startPrank(user1, user1);
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        ERC721Burnable(address(testCaseNFT)).burn(3);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexible_Approve_Burn() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleFlexibleSetup(false, 2);
        switchToAppAdministrator();
        goodBoys.push(address(user2));
        oracleApproved.addToApprovedList(goodBoys);
        vm.stopPrank();
        vm.startPrank(user2, user2); 
        ERC721Burnable(address(testCaseNFT)).burn(0);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexible_Approve_Mint() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleFlexibleSetup(false, 1);
        switchToAppAdministrator();
        goodBoys.push(address(user2));
        oracleApproved.addToApprovedList(goodBoys);
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user2);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexible_Approve_Buy() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountApproveDenyOracleFlexibleSetupNoMints(false, 0);
        switchToAppAdministrator();
        goodBoys.push(user);
        goodBoys.push(address(amm));
        oracleApproved.addToApprovedList(goodBoys);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 9, true);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexible_Approve_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountApproveDenyOracleFlexibleSetupNoMints(false, 3);
        applicationCoin.mint(rich_user, 500); 
        vm.stopPrank();
        vm.startPrank(rich_user, rich_user); 
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 9, true);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexible_Approve_Sell() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountApproveDenyOracleFlexibleSetupNoMints(false, 0);
        switchToAppAdministrator();
        goodBoys.push(address(amm));
        oracleApproved.addToApprovedList(goodBoys);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 12, false);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexible_Approve_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        switchToUser();
        UtilApplicationERC721(address(testCaseNFT)).safeTransferFrom(user, rich_user, 12);
        _accountApproveDenyOracleFlexibleSetupNoMints(false, 0);
        vm.stopPrank();
        vm.startPrank(rich_user, rich_user);
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 12, false);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexible_Deny_Burn() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleFlexibleSetup(true, 3);
        vm.stopPrank();
        vm.startPrank(user2, user2); 
        ERC721Burnable(address(testCaseNFT)).burn(0);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexible_Deny_Mint() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleFlexibleSetup(true, 3);
        switchToAppAdministrator(); 
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user2);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexible_Deny_Buy() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountApproveDenyOracleFlexibleSetupNoMints(true, 3);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 9, true);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexible_Deny_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountApproveDenyOracleFlexibleSetupNoMints(true, 3);
        applicationCoin.mint(rich_user, 500); 
        vm.stopPrank();
        vm.startPrank(rich_user, rich_user); 
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 9, true);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexible_Deny_Sell() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountApproveDenyOracleFlexibleSetupNoMints(true, 3);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 12, false);
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexible_Deny_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        switchToUser();
        UtilApplicationERC721(address(testCaseNFT)).safeTransferFrom(user, rich_user, 12);
        _accountApproveDenyOracleFlexibleSetupNoMints(true, 3);
        vm.stopPrank();
        vm.startPrank(rich_user, rich_user);
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 12, false);
    }

    function testERC721_ERC721CommonTests_PauseRulesViaAppManager() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// set up a non admin user an nft
        for (uint i; i < 5; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
        }

        assertEq(testCaseNFT.balanceOf(user1), 5);
        ///set pause rule and check check that the transaction reverts
        switchToRuleAdmin();
        applicationAppManager.addPauseRule(Blocktime + 1000, Blocktime + 1500);
        vm.warp(Blocktime + 1001);
        vm.startPrank(user1, user1);
        bytes4 selector = bytes4(keccak256("ApplicationPaused(uint256,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, Blocktime + 1000, Blocktime + 1500));
        testCaseNFT.transferFrom(user1, address(59), 2);
    }

    function testERC721_ERC721CommonTests_TokenMaxDailyTrades_FlexibleTag() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxDailyTradesSetup(true);
        switchToAppAdministrator();
        applicationAppManager.removeTag(address(testCaseNFT), "BoredGrape"); ///add tag
        applicationAppManager.addTag(address(testCaseNFT), "DiscoPunk"); ///add tag
        // ensure standard transfer works by transferring 1 to user2 and back(2 trades)
        ///perform transfer that checks rule
        vm.startPrank(user1, user1);
        testCaseNFT.transferFrom(user1, user2, 0);
        assertEq(testCaseNFT.balanceOf(user2), 2);
        vm.startPrank(user2, user2);
        testCaseNFT.transferFrom(user2, user1, 0);
        assertEq(testCaseNFT.balanceOf(user2), 1);
    }

    function testERC721_ERC721CommonTests_TokenMaxDailyTrades_StrictTag_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxDailyTradesSetup(true);
        vm.startPrank(user2, user2);
        // this one should fail because it is more than 1 in 24 hours
        vm.expectRevert(abi.encodeWithSignature("OverMaxDailyTrades()"));
        testCaseNFT.transferFrom(user2, user1, 1);
        assertEq(testCaseNFT.balanceOf(user2), 1);
    }

    function testERC721_ERC721CommonTests_TokenMaxDailyTrades_Period() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxDailyTradesSetup(true);
        // add a day to the time and it should pass
        vm.warp(block.timestamp + 1 days);
        vm.startPrank(user2, user2);
        testCaseNFT.transferFrom(user2, user1, 1);
        assertEq(testCaseNFT.balanceOf(user2), 0);
    }

    function testERC721_ERC721CommonTests_TokenMaxDailyTrades_MultipleTag() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxDailyTradesSetup(true);
        // add the other tag and check to make sure that it still only allows 1 trade
        vm.startPrank(user1, user1);
        // first one should pass
        testCaseNFT.transferFrom(user1, user2, 2);
        vm.startPrank(user2, user2);
        // this one should fail because it is more than 1 in 24 hours
        vm.expectRevert(abi.encodeWithSignature("OverMaxDailyTrades()"));
        testCaseNFT.transferFrom(user2, user1, 2);
    }
    /// TokenMaxDailyTrades test to ensure data is properly pruned
    function testERC721_ERC721CommonTests_TokenMaxDailyTrades_Pruning() public endWithStopPrank ifDeploymentTestsEnabled {
        vm.warp(Blocktime);
        _tokenMaxDailyTradesSetup(true);
        vm.warp(block.timestamp + 1);
        // add the other tag and check to make sure that it still only allows 1 trade
        vm.startPrank(user1, user1);
        // first one should pass
        testCaseNFT.transferFrom(user1, user2, 2);
        vm.startPrank(user2, user2);
        // this one should fail because it is more than 1 in 24 hours
        vm.expectRevert(abi.encodeWithSignature("OverMaxDailyTrades()"));
        testCaseNFT.transferFrom(user2, user1, 2);
        // deactivate and reactivate which will prune accumulators
        switchToRuleAdmin();
        vm.warp(block.timestamp + 1);
        ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).activateTokenMaxDailyTrades(createActionTypeArray(ActionTypes.P2P_TRANSFER), false);
        ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).activateTokenMaxDailyTrades(createActionTypeArray(ActionTypes.P2P_TRANSFER), true);
        vm.warp(block.timestamp + 1);
        // this one should work
        vm.startPrank(user2, user2);
        testCaseNFT.transferFrom(user2, user1, 2);
    }

    /// TokenMaxDailyTrades test to ensure data is properly pruned
    function testERC721_ERC721CommonTests_TokenMaxDailyTrades_Update_Pruning() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxDailyTradesSetup(true);
        // add the other tag and check to make sure that it still only allows 1 trade
        vm.startPrank(user1, user1);
        // first one should pass
        testCaseNFT.transferFrom(user1, user2, 2);
        vm.startPrank(user2, user2);
        // this one should fail because it is more than 1 in 24 hours
        vm.expectRevert(abi.encodeWithSignature("OverMaxDailyTrades()"));
        testCaseNFT.transferFrom(user2, user1, 2);
        // deactivate and reactivate which will prune accumulators
        switchToRuleAdmin();
        uint32 ruleId = createTokenMaxDailyTradesRule("", 1);
        setTokenMaxDailyTradesRule(address(applicationNFTHandler), ruleId);
        // this one should work
        vm.startPrank(user2, user2);
        testCaseNFT.transferFrom(user2, user1, 2);
    }

    function testERC721_ERC721CommonTests_TokenMaxDailyTrades_BlankTag_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxDailyTradesSetup(false);
        vm.startPrank(user2, user2);
        // this one should fail because it is more than 1 in 24 hours
        vm.expectRevert(abi.encodeWithSignature("OverMaxDailyTrades()"));
        testCaseNFT.transferFrom(user2, user1, 1);
        assertEq(testCaseNFT.balanceOf(user2), 1);
    }

    function testERC721_ERC721CommonTests_TokenMaxDailyTrades_BlankTag_Period() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxDailyTradesSetup(false);
        // add a day to the time and it should pass
        vm.startPrank(user2, user2);
        vm.warp(block.timestamp + 1 days);
        testCaseNFT.transferFrom(user2, user1, 1);
        assertEq(testCaseNFT.balanceOf(user2), 0);
    }

    function testERC721_ERC721CommonTests_TokenMaxDailyTrades_Burn_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        /// There is no positive burn test as this action type should not be allowed to be added to the rule
        switchToRuleAdmin();
        uint32 ruleId = createTokenMaxDailyTradesRule("BoredGrape", "DiscoPunk", 1, 5);
        switchToRuleAdmin();
        vm.expectRevert(abi.encodeWithSignature("InvalidAction()"));
        ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).setTokenMaxDailyTradesId(createActionTypeArray(ActionTypes.BURN), ruleId);
    }

    function testERC721_ERC721CommonTests_TokenMaxDailyTrades_Mint() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxDailyTradesSetup(false);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
    }

    function testERC721_ERC721CommonTests_TokenMaxDailyTrades_Mint_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint32 ruleId = createTokenMaxDailyTradesRule("", 0); // Set trade limit at 0 to test if mints will be prevented
        setTokenMaxDailyTradesRule(address(applicationNFTHandler), ruleId);
        switchToAppAdministrator();
        vm.expectRevert(abi.encodeWithSignature("OverMaxDailyTrades()"));
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
    }

    function testERC721_ERC721CommonTests_TokenMaxDailyTrades_Buy() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _tokenMaxDailyTradesSetupNoBurns();
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 9, true);
    }

    function testERC721_ERC721CommonTests_TokenMaxDailyTrades_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _tokenMaxDailyTradesSetupNoBurns();
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 9, true);
        vm.expectRevert(abi.encodeWithSignature("OverMaxDailyTrades()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 9, false);
    }

    function testERC721_ERC721CommonTests_TokenMaxDailyTrades_Sell() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _tokenMaxDailyTradesSetupNoBurns();
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 12, false);
        vm.expectRevert(abi.encodeWithSignature("OverMaxDailyTrades()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 12, true);
    }

    function testERC721_ERC721CommonTests_TokenMaxDailyTrades_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _tokenMaxDailyTradesSetupNoBurns();
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 12, false);
    }
    /**
     * This tests that no cross contamination happens when separate rules are attached to actions.
     */
    function testERC721_ERC721CommonTests_TokenMaxDailyTrades_Accumulator_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks(); // This puts 10 nfts in the AMM
        // set up multiple rules
        // buy = 1
        // sell = 3
        // p2p transfer = 10
        _tokenMaxDailyTradesSetupMultipleRuleIds();
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        // single buy should pass
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 0, true);

        // 3 sells should pass
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        // sell first time
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 0, false);
        // put the same nft back into user account
        vm.startPrank(address(amm));
        testCaseNFT.transferFrom(address(amm), user, 0); // this transfer will get labeled a sell because it is going from contract to eoa
        // sell second time
        switchToUser();
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 0, false);
        assertEq(testCaseNFT.balanceOf(user), 3); // should have the original 3 that are added by _setUpNFTAMMForRuleChecks
    }

    /**
     * This tests that no cross contamination happens when separate rules are attached to actions.
     */
    function testERC721_ERC721CommonTests_TokenMaxDailyTrades_Accumulator_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        // mint 10 NFT's to user
        _mintNFTsToAddress(10, user, address(testCaseNFT));
        // set up multiple rules
        // buy = 1
        // sell = 3
        // p2p transfer = 10
        _tokenMaxDailyTradesSetupMultipleRuleIds();
        // transfer the same NFT back and forth 10 times. This will take it to the limit.
        for (uint256 i = 0; i < 10; i++) {
            if (i % 2 == 0) {
                vm.startPrank(user, user);
                testCaseNFT.transferFrom(user, user2, 0);
            } else {
                vm.startPrank(user2, user2);
                testCaseNFT.transferFrom(user2, user, 0);
            }
        }
        // one more transfer should cause an error
        vm.startPrank(user, user);
        vm.expectRevert(abi.encodeWithSignature("OverMaxDailyTrades()"));
        testCaseNFT.transferFrom(user, user2, 0);
        // set up the AMM
        _setUpNFTAMMForRuleChecks(); // This puts 10 nfts in the AMM
        switchToUser();

        // a sell should not cause the error because it's a separate rule and accumulators
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        // sell the same NFT that was transferred back and forth.
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 0, false);

        // a buy should not cause the error because it's a separate rule and accumulators
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 0, true);
    }

    /// Account Max Transaction Value By Risk Score Tests
    function testERC721_ERC721CommonTests_AccountMaxTransactionValueByRiskScore_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        ///Transfer NFT's
        ///Positive cases
        _accountMaxTransactionValueByRiskScoreSetup(false);
        vm.startPrank(user1, user1);
        testCaseNFT.safeTransferFrom(user1, user3, 0);
        vm.startPrank(user3, user3);
        testCaseNFT.safeTransferFrom(user3, user1, 0);
        vm.startPrank(user1, user1);
        testCaseNFT.safeTransferFrom(user1, user2, 4);
        testCaseNFT.safeTransferFrom(user1, user2, 1);
    }

    function testERC721_ERC721CommonTests_AccountMaxTransactionValueByRiskScore_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        ///Fail cases
        _accountMaxTransactionValueByRiskScoreSetup(false);
        vm.startPrank(user2, user2);
        bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 10, 15000000000000000000));
        testCaseNFT.safeTransferFrom(user2, user3, 7);

        selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 10, 15000000000000000000));
        testCaseNFT.safeTransferFrom(user2, user3, 6);

        selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 40, 12000000000000000000));
        testCaseNFT.safeTransferFrom(user2, user3, 5);
    }

    function testERC721_ERC721CommonTests_AccountMaxTransactionValueByRiskScore_PriceChange() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxTransactionValueByRiskScoreSetup(false);
        ///simulate price changes
        switchToAppAdministrator();
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 4, 1050 * (10 ** 16)); // in cents
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 5, 1550 * (10 ** 16)); // in cents
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 6, 11 * ATTO); // in dollars
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 7, 9 * ATTO); // in dollars

        vm.startPrank(user1, user1);
        testCaseNFT.safeTransferFrom(user1, user2, 4);
        vm.startPrank(user2, user2);
        testCaseNFT.safeTransferFrom(user2, user3, 7);
        testCaseNFT.safeTransferFrom(user2, user3, 6);
        bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 10, 15000000000000000000));
        testCaseNFT.safeTransferFrom(user2, user3, 5);
        vm.startPrank(user2, user2);
        testCaseNFT.safeTransferFrom(user2, user3, 4);
    }

    function testERC721_ERC721CommonTests_AccountMaxTransactionValueByRiskScore_Burning() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxTransactionValueByRiskScoreSetup(false);
        /// set price of token 5 below limit of user 2
        switchToAppAdministrator();
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 5, 14 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 4, 17 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 6, 25 * ATTO);
        /// test burning with this rule active
        /// transaction valuation must remain within risk limit for sender
        vm.startPrank(user2, user2);
        ERC721Burnable(address(testCaseNFT)).burn(5);

        vm.startPrank(user2, user2);
        bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 10, 15000000000000000000));
        ERC721Burnable(address(testCaseNFT)).burn(6);
    }

    function testERC721_ERC721CommonTests_AccountMaxTransactionValueByRiskScore_Period_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        ///Transfer NFT's
        ///Positive cases
        _accountMaxTransactionValueByRiskScoreSetup(true);
        vm.startPrank(user1, user1);
        testCaseNFT.safeTransferFrom(user1, user3, 0);
        vm.warp(block.timestamp + 25 hours);
        vm.startPrank(user3, user3);
        testCaseNFT.safeTransferFrom(user3, user1, 0);

        vm.warp(block.timestamp + 25 hours * 2);
        vm.startPrank(user1, user1);
        testCaseNFT.safeTransferFrom(user1, user2, 4);
        vm.warp(block.timestamp + 25 hours * 3);
        testCaseNFT.safeTransferFrom(user1, user2, 1);
    }

    function testERC721_ERC721CommonTests_AccountMaxTransactionValueByRiskScore_Period_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        ///Fail cases
        _accountMaxTransactionValueByRiskScoreSetup(true);
        vm.startPrank(user2, user2);
        bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 10, 15000000000000000000));
        testCaseNFT.safeTransferFrom(user2, user3, 7);

        selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 10, 15000000000000000000));
        testCaseNFT.safeTransferFrom(user2, user3, 6);

        selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 40, 12000000000000000000));
        testCaseNFT.safeTransferFrom(user2, user3, 5);
    }

    function testERC721_ERC721CommonTests_AccountMaxTransactionValueByRiskScore_Period_Combination() public endWithStopPrank ifDeploymentTestsEnabled {
        ///simulate price changes
        _accountMaxTransactionValueByRiskScoreSetup(true);
        switchToAppAdministrator();
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 4, 1050 * (ATTO / 100)); // in cents
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 5, 1550 * (ATTO / 100)); // in cents
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 6, 11 * ATTO); // in dollars
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 7, 9 * ATTO); // in dollars

        vm.startPrank(user1, user1);
        testCaseNFT.safeTransferFrom(user1, user2, 4);

        vm.warp(block.timestamp + 25 hours * 5);
        vm.startPrank(user2, user2);
        testCaseNFT.safeTransferFrom(user2, user3, 7);
        vm.warp(block.timestamp + 25 hours * 6);
        testCaseNFT.safeTransferFrom(user2, user3, 6);

        bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 10, 15000000000000000000));
        testCaseNFT.safeTransferFrom(user2, user3, 5);

        vm.warp(block.timestamp + 25 hours * 7);
        vm.startPrank(user2, user2);
        testCaseNFT.safeTransferFrom(user2, user3, 4);
    }

    function testERC721_ERC721CommonTests_AccountMaxTransactionValueByRiskScore_Period_Burning() public endWithStopPrank ifDeploymentTestsEnabled {
        /// set price of token 5 below limit of user 2
        _accountMaxTransactionValueByRiskScoreSetup(true);
        switchToAppAdministrator();
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 5, 14 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 4, 17 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 6, 25 * ATTO);
        /// test burning with this rule active
        /// transaction valuation must remain within risk limit for sender
        vm.startPrank(user2, user2);
        ERC721Burnable(address(testCaseNFT)).burn(5);
        bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 10, 15000000000000000000));
        ERC721Burnable(address(testCaseNFT)).burn(6);
    }

    function testERC721_ERC721CommonTests_AccountMaxTransactionValueByRiskScore_Mint_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxTransactionValueByRiskScoreSetupNoMints();
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user2);
    }

    function testERC721_ERC721CommonTests_AccountMaxTransactionValueByRiskScore_Mint_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxTransactionValueByRiskScoreSetupNoMints();
        switchToAppAdministrator();
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 1, 12 * ATTO);
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user2, 80);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user2);
        bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 80, 11000000000000000000));
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user2);
    }

    function testERC721_ERC721CommonTests_AccountMaxTransactionValueByRiskScore_Buy_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountMaxTransactionValueByRiskScoreSetupNoMints();
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 1, true);
    }

    function testERC721_ERC721CommonTests_AccountMaxTransactionValueByRiskScore_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountMaxTransactionValueByRiskScoreSetupNoMints();
        switchToAppAdministrator();
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 1, 18 * ATTO);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 0, 17000000000000000000));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 1, true);
    }

    function testERC721_ERC721CommonTests_AccountMaxTransactionValueByRiskScore_Sell_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountMaxTransactionValueByRiskScoreSetupNoMints();
        switchToAppAdministrator();
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 11, 11 * ATTO);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 11, false);
    }

    function testERC721_ERC721CommonTests_AccountMaxTransactionValueByRiskScore_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        switchToAppAdministrator();
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 11, 18 * ATTO);
        _accountMaxTransactionValueByRiskScoreSetupNoMints();
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 0, 17000000000000000000));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 11, false);
    }

    /**
     * @dev Test the AccessLevel = 0 rule
     */
    function testERC721_ERC721CommonTests_AccountDenyForNoAccessLevelInNFT_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        // transfers should not work for addresses without AccessLevel
        _accountDenyForNoAccessLevelInNFTSetup();
        vm.startPrank(user1, user1);
        vm.expectRevert(0x3fac082d);
        testCaseNFT.transferFrom(user1, user2, 0);
        // set AccessLevel and try again
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user2, 1);
        vm.startPrank(user1, user1);
        vm.expectRevert(0x3fac082d); /// still fails since user 1 is accessLevel0
        testCaseNFT.transferFrom(user1, user2, 0);
    }

    function testERC721_ERC721CommonTests_AccountDenyForNoAccessLevelInNFT_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountDenyForNoAccessLevelInNFTSetup();
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user2, 1);
        applicationAppManager.addAccessLevel(user1, 1);
        vm.startPrank(user1, user1);
        testCaseNFT.transferFrom(user1, user2, 0);
        assertEq(testCaseNFT.balanceOf(user2), 1);
    }

    function testERC721_ERC721CommonTests_AccountDenyForNoAccessLevelInNFT_Burn() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountDenyForNoAccessLevelInNFTSetup();
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user1, 1);
        vm.startPrank(user1, user1);
        ERC721Burnable(address(testCaseNFT)).burn(0);
        assertEq(testCaseNFT.balanceOf(user1), 4);
    }

    function testERC721_ERC721CommonTests_AccountDenyForNoAccessLevelInNFT_Burn_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountDenyForNoAccessLevelInNFTSetup();
        switchToAccessLevelAdmin();
        vm.stopPrank();
        vm.startPrank(user1, user1);
        vm.expectRevert(abi.encodeWithSignature("NotAllowedForAccessLevel()"));
        ERC721Burnable(address(testCaseNFT)).burn(0);
        assertEq(testCaseNFT.balanceOf(user1), 5);
    }

    function testERC721_ERC721CommonTests_AccountDenyForNoAccessLevelInNFT_Mint() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountDenyForNoAccessLevelInNFTSetup();
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user1, 1);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
        assertEq(testCaseNFT.balanceOf(user1), 6);
    }

    function testERC721_ERC721CommonTests_AccountDenyForNoAccessLevelInNFT_Mint_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountDenyForNoAccessLevelInNFTSetup();
        switchToAppAdministrator();
        vm.expectRevert(abi.encodeWithSignature("NotAllowedForAccessLevel()"));
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
        assertEq(testCaseNFT.balanceOf(user1), 5);
    }

    function testERC721_ERC721CommonTests_AccountDenyForNoAccessLevelInNFT_Buy() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountDenyForNoAccessLevelInNFTSetup();
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user, 1);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 1, true);
    }

    function testERC721_ERC721CommonTests_AccountDenyForNoAccessLevelInNFT_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountDenyForNoAccessLevelInNFTSetup();
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        vm.expectRevert(abi.encodeWithSignature("NotAllowedForAccessLevel()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 1, true);
    }

    function testERC721_ERC721CommonTests_AccountDenyForNoAccessLevelInNFT_Sell() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountDenyForNoAccessLevelInNFTSetup();
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user, 1);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 11, false);
    }

    function testERC721_ERC721CommonTests_AccountDenyForNoAccessLevelInNFT_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _accountDenyForNoAccessLevelInNFTSetup();
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        /// User is minted NFTs in set up prior to rule activation. Selling accquired NFT's post rule activation results in revert
        vm.expectRevert(abi.encodeWithSignature("NotAllowedForAccessLevel()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 11, false);
    }

    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalance_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        /// Transfers passing (above min value limit)
        _accountMinMaxTokenBalanceSetup(true);
        vm.startPrank(user1, user1);
        testCaseNFT.safeTransferFrom(user1, user2, 0); ///User 1 has min limit of 1
        testCaseNFT.safeTransferFrom(user1, user3, 1);
        assertEq(testCaseNFT.balanceOf(user1), 1);

        vm.startPrank(user2, user2);
        testCaseNFT.safeTransferFrom(user2, user1, 0); ///User 2 has min limit of 2
        testCaseNFT.safeTransferFrom(user2, user3, 3);
        assertEq(testCaseNFT.balanceOf(user2), 2);

        vm.startPrank(user3, user3);
        testCaseNFT.safeTransferFrom(user3, user2, 3); ///User 3 has min limit of 3
        testCaseNFT.safeTransferFrom(user3, user1, 1);
        assertEq(testCaseNFT.balanceOf(user3), 3);
    }

    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalance_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceSetup(true);
        /// Transfers failing (below min value limit)
        vm.startPrank(user1, user1);
        testCaseNFT.safeTransferFrom(user1, rich_user, 0); ///User 1 has min limit of 1
        testCaseNFT.safeTransferFrom(user1, rich_user, 1);
        vm.expectRevert(0xa7fb7b4b);
        testCaseNFT.safeTransferFrom(user1, rich_user, 2);
        assertEq(testCaseNFT.balanceOf(user1), 1);

        vm.startPrank(user2, user2);
        testCaseNFT.safeTransferFrom(user2, rich_user, 3); ///User 2 has min limit of 2
        vm.expectRevert(0xa7fb7b4b);
        testCaseNFT.safeTransferFrom(user2, rich_user, 4);
        assertEq(testCaseNFT.balanceOf(user2), 2);

        vm.startPrank(user3, user3);
        vm.expectRevert(0xa7fb7b4b);
        testCaseNFT.safeTransferFrom(user3, rich_user, 6); ///User 3 has min limit of 3
        assertEq(testCaseNFT.balanceOf(user3), 3);
    }

    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalance_Period() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceSetup(true);

        /// Expire time restrictions for users and transfer below rule
        vm.warp(Blocktime + 17525 hours);

        vm.startPrank(user1, user1);
        testCaseNFT.safeTransferFrom(user1, rich_user, 2);

        vm.startPrank(user2, user2);
        testCaseNFT.safeTransferFrom(user2, rich_user, 4);

        vm.startPrank(user3, user3);
        testCaseNFT.safeTransferFrom(user3, rich_user, 6);
    }

    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalance_BlankTag_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceSetup(false);
        vm.startPrank(user1, user1);
        testCaseNFT.safeTransferFrom(user1, user2, 0);
    }

    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalance_BlankTag_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        // should fail since it puts user1 below min of 1
        _accountMinMaxTokenBalanceSetup(false);
        vm.startPrank(user1, user1);
        testCaseNFT.safeTransferFrom(user1, user2, 0);
        testCaseNFT.safeTransferFrom(user1, user3, 1);
        vm.expectRevert(0xa7fb7b4b);
        testCaseNFT.safeTransferFrom(user1, user3, 2);
    }

    function testERC721_ERC721CommonTests_TransferVolumeRule_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _transferVolumeRuleSetup();
        vm.startPrank(user1, user1);
        // transfer one that hits the percentage
        vm.expectRevert(0x009da0ce);
        testCaseNFT.safeTransferFrom(user1, user2, 1);
    }

    function testERC721_ERC721CommonTests_TransferVolumeRule_Period() public endWithStopPrank ifDeploymentTestsEnabled {
        _transferVolumeRuleSetup();
        vm.startPrank(user1, user1);
        /// now move a little over 2 hours into the future to make sure the next block will work
        vm.warp(Blocktime + 121 minutes);
        testCaseNFT.safeTransferFrom(user1, user2, 1);
        /// now violate the rule in this block and ensure revert
        vm.expectRevert(0x009da0ce);
        testCaseNFT.safeTransferFrom(user1, user2, 2);
        /// now move 1 day into the future and try again
        vm.warp(Blocktime + 1 days);
        testCaseNFT.safeTransferFrom(user1, user2, 2);
        /// once again, break the rule
        vm.expectRevert(0x009da0ce);
        testCaseNFT.safeTransferFrom(user1, user2, 3);
    }

    function testERC721_ERC721CommonTests_TransferVolumeRuleWithSupplySet_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _transferVolumeRuleWithSupplySet();
        vm.startPrank(user1, user1);
        testCaseNFT.safeTransferFrom(user1, user2, 0);
        //transfer one that hits the percentage
        vm.expectRevert(0x009da0ce);
        testCaseNFT.safeTransferFrom(user1, user2, 1);
    }

    function testERC721_ERC721CommonTests_TransferVolumeRuleWithSupplySet_Period() public endWithStopPrank ifDeploymentTestsEnabled {
        _transferVolumeRuleWithSupplySet();
        vm.startPrank(user1, user1);
        /// now move a little over 2 hours into the future to make sure the next block will work
        vm.warp(Blocktime + 121 minutes);
        // assertFalse(isWithinPeriod2(Blocktime, 2, Blocktime));
        testCaseNFT.safeTransferFrom(user1, user2, 1);
        /// now violate the rule in this block and ensure revert
        vm.expectRevert(0x009da0ce);
        testCaseNFT.safeTransferFrom(user1, user2, 2);
        /// now move 1 day into the future and try again
        vm.warp(Blocktime + 1 days);
        testCaseNFT.safeTransferFrom(user1, user2, 2);
        /// once again, break the rule
        vm.expectRevert(0x009da0ce);
        testCaseNFT.safeTransferFrom(user1, user2, 3);
    }

    function testERC721_ERC721CommonTests_TransferVolumeRuleWithSupplySet_Mint() public endWithStopPrank ifDeploymentTestsEnabled {
        _transferVolumeRuleWithSupplySet();
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
    }

    function testERC721_ERC721CommonTests_TransferVolumeRuleWithSupplySet_Mint_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _transferVolumeRuleWithSupplySet();
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
        vm.expectRevert(abi.encodeWithSignature("OverMaxTradingVolume()"));
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
    }

    function testERC721_ERC721CommonTests_TransferVolumeRuleWithSupplySet_Burn() public endWithStopPrank ifDeploymentTestsEnabled {
        _transferVolumeRuleWithSupplySet();
        vm.stopPrank();
        vm.startPrank(user1, user1);
        UtilApplicationERC721(address(testCaseNFT)).burn(2);
    }

    function testERC721_ERC721CommonTests_TransferVolumeRuleWithSupplySet_Burn_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _transferVolumeRuleWithSupplySet();
        vm.stopPrank();
        vm.startPrank(user1, user1);
        UtilApplicationERC721(address(testCaseNFT)).burn(2);
        vm.expectRevert(abi.encodeWithSignature("OverMaxTradingVolume()"));
        UtilApplicationERC721(address(testCaseNFT)).burn(3);
    }

    function testERC721_ERC721CommonTests_TransferVolumeRuleWithSupplySet__Buy() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _transferVolumeRuleWithSupplySet();
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 1, true);
    }

    function testERC721_ERC721CommonTests_TransferVolumeRuleWithSupplySet_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _transferVolumeRuleWithSupplySet();
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 2, true);
        vm.expectRevert(abi.encodeWithSignature("OverMaxTradingVolume()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 1, true);
    }

    function testERC721_ERC721CommonTests_TransferVolumeRuleWithSupplySet__Sell() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _transferVolumeRuleWithSupplySet();
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 11, false);
    }

    function testERC721_ERC721CommonTests_TransferVolumeRuleWithSupplySet__Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        _transferVolumeRuleWithSupplySet();
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 12, false);
        vm.expectRevert(abi.encodeWithSignature("OverMaxTradingVolume()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 11, false);
    }

    function testERC721_ERC721CommonTests_TokenMinHoldTime_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        /// set the rule for 24 hours
        switchToRuleAdmin();
        uint32 ruleId = createTokenMinHoldTimeRule(24);
        setTokenMinHoldTimeRule(ruleId);
        switchToAppAdministrator();
        // mint 1 nft to non admin user(this should set their ownership start time)
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user1); /// ensure mint works with rule active
        vm.startPrank(user1, user1);
        /// ensure that mint triggers the hold time clock and that applicable actions check the clock (p2p transfer)
        vm.expectRevert(0x5f98112f);
        testCaseNFT.safeTransferFrom(user1, user2, 0);
    }

    function testERC721_ERC721CommonTests_TokenMinHoldTime_Update_Pruning() public endWithStopPrank ifDeploymentTestsEnabled {
        vm.warp(Blocktime);
        /// set the rule for 24 hours
        switchToRuleAdmin();
        uint32 ruleId = createTokenMinHoldTimeRule(24);
        setTokenMinHoldTimeRule(ruleId);
        vm.warp(block.timestamp + 1);
        switchToAppAdministrator();
        // mint 1 nft to non admin user(this should set their ownership start time)
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user1); /// ensure mint works with rule active
        vm.warp(block.timestamp + 1);
        vm.startPrank(user1, user1);
        /// ensure that mint triggers the hold time clock and that applicable actions check the clock (p2p transfer)
        vm.expectRevert(0x5f98112f);
        testCaseNFT.safeTransferFrom(user1, user2, 0);
        vm.warp(block.timestamp + 1);
        // deactivate and reactivate which will prune accumulators
        switchToRuleAdmin();
        ruleId = createTokenMinHoldTimeRule(24);
        setTokenMinHoldTimeRule(ruleId);
        vm.warp(block.timestamp + 1);
        vm.startPrank(user1, user1);
        testCaseNFT.safeTransferFrom(user1, user2, 0);
    }

    function testERC721_ERC721CommonTests_TokenMinHoldTime_Burn() public endWithStopPrank ifDeploymentTestsEnabled {
        /// ensure that burn works while rule is active
        switchToRuleAdmin();
        uint32 ruleId = createTokenMinHoldTimeRule(24);
        setTokenMinHoldTimeRule(ruleId);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
        vm.warp(Blocktime + 24 hours);
        vm.startPrank(user1, user1);
        ERC721Burnable(address(testCaseNFT)).burn(0);
    }

    function testERC721_ERC721CommonTests_TokenMinHoldTime_Burn_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        /// ensure that transfers trigger the hold time clock and that the applicable action checks the clock (Burn)
        switchToRuleAdmin();
        uint32 ruleId = createTokenMinHoldTimeRule(24);
        setTokenMinHoldTimeRule(ruleId);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
        vm.expectRevert(abi.encodeWithSignature("UnderHoldPeriod()"));
        vm.startPrank(user1, user1);
        ERC721Burnable(address(testCaseNFT)).burn(0);
    }

    function testERC721_ERC721CommonTests_TokenMinHoldTime_Buy() public endWithStopPrank ifDeploymentTestsEnabled {
        /// ensure that buys work while rule is active
        _setUpNFTAMMForRuleChecks();
        uint32 ruleId = createTokenMinHoldTimeRule(24);
        setTokenMinHoldTimeRule(ruleId);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 1, true);
    }

    function testERC721_ERC721CommonTests_TokenMinHoldTime_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        /// ensure that buys trigger the hold time clock and that applicaple actions check the clock (p2p transfer)
        uint32 ruleId = createTokenMinHoldTimeRule(24);
        setTokenMinHoldTimeRule(ruleId);
        _setUpNFTAMMForRuleChecks();
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 1, true);
        vm.expectRevert(abi.encodeWithSignature("UnderHoldPeriod()"));
        testCaseNFT.safeTransferFrom(user, user2, 1);
    }

    function testERC721_ERC721CommonTests_TokenMinHoldTime_Buy_Burn_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        /// ensure that buys trigger the hold time clock and that applicable actions check the clock (Burn)
        uint32 ruleId = createTokenMinHoldTimeRule(24);
        setTokenMinHoldTimeRule(ruleId);
        _setUpNFTAMMForRuleChecks();
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 1, true);
        vm.expectRevert(abi.encodeWithSignature("UnderHoldPeriod()"));
        ERC721Burnable(address(testCaseNFT)).burn(1);
    }

    function testERC721_ERC721CommonTests_TokenMinHoldTime_Sell() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        vm.warp(Blocktime + 24 hours);
        uint32 ruleId = createTokenMinHoldTimeRule(24);
        setTokenMinHoldTimeRule(ruleId);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 12, false);
    }

    function testERC721_ERC721CommonTests_TokenMinHoldTime_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        vm.warp(Blocktime + 24 hours);
        uint32 ruleId = createTokenMinHoldTimeRule(24);
        setTokenMinHoldTimeRule(ruleId);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 12, false);
        /// buy token back from AMM (agnostic to how long AMM holds token)
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 12, true);
        /// resell token back to AMM
        vm.expectRevert(abi.encodeWithSignature("UnderHoldPeriod()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 12, false);
    }

    function testERC721_ERC721CommonTests_TokenMinHoldTime_Period() public endWithStopPrank ifDeploymentTestsEnabled {
        /// set the rule for 24 hours
        switchToRuleAdmin();
        uint32 ruleId = createTokenMinHoldTimeRule(24);
        setTokenMinHoldTimeRule(ruleId);
        switchToAppAdministrator();
        // mint 1 nft to non admin user(this should set their ownership start time)
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
        vm.startPrank(user1, user1);
        // move forward in time 1 day and it should pass
        Blocktime = Blocktime + 1 days;
        vm.warp(Blocktime);
        testCaseNFT.safeTransferFrom(user1, user2, 0);
        // the original owner was able to transfer but the new owner should not be able to because the time resets
        vm.startPrank(user2, user2);
        vm.expectRevert(0x5f98112f);
        testCaseNFT.safeTransferFrom(user2, user1, 0);
        // move forward under the threshold and ensure it fails
        Blocktime = Blocktime + 2 hours;
        vm.warp(Blocktime);
        vm.expectRevert(0x5f98112f);
        testCaseNFT.safeTransferFrom(user2, user1, 0);
    }
    /**
     * This test makes sure that the initial date is set correctly when the transfer from is a RuleBypass Account.
     */
    function testERC721_ERC721CommonTests_TokenMinHoldTime_FromTreasuryOrigin() public endWithStopPrank ifDeploymentTestsEnabled {
        /// set the rule for 24 hours
        switchToRuleAdmin();
        uint32 ruleId = createTokenMinHoldTimeRule(24);
        setTokenMinHoldTimeRule(ruleId);
        switchToAppAdministrator();
        // mint 1 nft to rule bypass
        UtilApplicationERC721(address(testCaseNFT)).safeMint(treasuryAccount);
        // move forward in time 2 day and transfer to regular users
        Blocktime = Blocktime + 2 days;
        vm.warp(Blocktime);
        switchToTreasuryAccount();
        testCaseNFT.safeTransferFrom(treasuryAccount, user1, 0);
        // Should not be able to transfer because the period started correctly.
        vm.startPrank(user1, user1);
        vm.expectRevert(0x5f98112f);
        testCaseNFT.safeTransferFrom(user1, user2, 0);
    }

    function testERC721_ERC721CommonTests_TokenMinHoldTime_UpdatedRule() public endWithStopPrank ifDeploymentTestsEnabled {
        // now change the rule hold hours to 2 and it should pass
        switchToRuleAdmin();
        uint32 ruleId = createTokenMinHoldTimeRule(24);
        setTokenMinHoldTimeRule(ruleId);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
        // move forward in time 1 day and it should pass
        Blocktime = Blocktime + 26 hours;
        vm.warp(Blocktime);

        vm.startPrank(user1, user1);
        testCaseNFT.safeTransferFrom(user1, user2, 0);
    }

    function testERC721_ERC721CommonTests_CollectionTokenMaxSupplyVolatility_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _collectionTokenMaxSupplyVolatilitySetup();
        switchToAppAdministrator();
        /// fail transactions (mint and burn with passing transfers)
        bytes4 selector = bytes4(keccak256("OverMaxSupplyVolatility()"));
        vm.expectRevert(abi.encodeWithSelector(selector));
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
    }

    function testERC721_ERC721CommonTests_CollectionTokenMaxSupplyVolatility_Burning() public endWithStopPrank ifDeploymentTestsEnabled {
        _collectionTokenMaxSupplyVolatilitySetup();
        vm.startPrank(user1, user1);
        ERC721Burnable(address(testCaseNFT)).burn(10);
        /// move out of rule period
        vm.warp(Blocktime + 36 hours);
        /// burn tokens (should pass)
        ERC721Burnable(address(testCaseNFT)).burn(11);
        /// mint
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
    }

    function testERC721_ERC721CommonTests_AccountMaxValueByRisk_Transfer() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpAccountMaxValueByRiskScoreRule(ActionTypes.P2P_TRANSFER);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user, 25);
        applicationAppManager.addRiskScore(user2, 25);
        switchToUser();
        UtilApplicationERC721(address(testCaseNFT)).safeTransferFrom(user, user2, 0);
    }

    function testERC721_ERC721CommonTests_AccountMaxValueByRisk_Transfer_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpAccountMaxValueByRiskScoreRule(ActionTypes.P2P_TRANSFER);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 0, 1 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 1, 1 * ATTO);
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user, 25);
        applicationAppManager.addRiskScore(user2, 75);
        switchToUser();
        UtilApplicationERC721(address(testCaseNFT)).safeTransferFrom(user, user2, 0);
        vm.expectRevert(abi.encodeWithSignature("OverMaxAccValueByRiskScore()"));
        UtilApplicationERC721(address(testCaseNFT)).safeTransferFrom(user, user2, 1);
    }

    function testERC721_ERC721CommonTests_AccountMaxValueByRisk_Mint() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpAccountMaxValueByRiskScoreRule(ActionTypes.MINT);
        switchToAppAdministrator();
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 0, 1 * ATTO);
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user, 75);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
    }

    function testERC721_ERC721CommonTests_AccountMaxValueByRisk_Mint_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpAccountMaxValueByRiskScoreRule(ActionTypes.MINT);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 0, 100 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 1, 100 * ATTO);
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user, 75);
        switchToAppAdministrator();
        vm.expectRevert(abi.encodeWithSignature("OverMaxAccValueByRiskScore()"));
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
    }

    function testERC721_ERC721CommonTests_AccountMaxValueByRisk_Burn() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpAccountMaxValueByRiskScoreRule(ActionTypes.P2P_TRANSFER);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 0, 1 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 1, 1 * ATTO);
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user, 25);
        applicationAppManager.addRiskScore(user2, 75);
        switchToUser();
        /// check that burns are not checked by the rule
        ERC721Burnable(address(testCaseNFT)).burn(0);
    }

    function testERC721_ERC721CommonTests_AccountMaxValueByRisk_Buy() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        switchToAppAdministrator();
        for (uint256 i; i < 15; i++) {
            /// set all NFTs up to tokenId 15 to valuation of $1
            erc721Pricer.setSingleNFTPrice(address(testCaseNFT), i, 1 * ATTO);
        }
        _setUpAccountMaxValueByRiskScoreRule(ActionTypes.BUY);
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user, 1);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 1, true);
    }

    function testERC721_ERC721CommonTests_AccountMaxValueByRisk_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        switchToAppAdministrator();
        for (uint256 i; i < 15; i++) {
            /// set all NFTs up to tokenId 15 to valuation of $1
            erc721Pricer.setSingleNFTPrice(address(testCaseNFT), i, 1 * ATTO);
        }
        _setUpAccountMaxValueByRiskScoreRule(ActionTypes.BUY);
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user, 25);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        vm.expectRevert(abi.encodeWithSignature("OverMaxAccValueByRiskScore()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 1, true);
    }

    function _setUpAccountMaxValueByRiskScoreRule(ActionTypes action) internal {
        uint32 ruleId = createAccountMaxValueByRiskRule(createUint8Array(25, 50, 75), createUint48Array(3, 2, 1));
        setAccountMaxValueByRiskRuleSingleAction(action, ruleId);
    }

    function testERC721_ERC721CommonTests_AccountMaxValueByAccessLevel_Transfer() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpAccountMaxValueByAccessLevelRule(ActionTypes.P2P_TRANSFER);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 0, 1 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 1, 1 * ATTO);
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user, 1);
        applicationAppManager.addAccessLevel(user2, 1);
        switchToUser();
        UtilApplicationERC721(address(testCaseNFT)).safeTransferFrom(user, user2, 0);
    }

    function testERC721_ERC721CommonTests_AccountMaxValueByAccessLevel_Transfer_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpAccountMaxValueByAccessLevelRule(ActionTypes.P2P_TRANSFER);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 0, 1 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 1, 1 * ATTO);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user, 2);
        applicationAppManager.addAccessLevel(user2, 0);
        switchToUser();
        vm.expectRevert(abi.encodeWithSignature("OverMaxValueByAccessLevel()"));
        UtilApplicationERC721(address(testCaseNFT)).safeTransferFrom(user, user2, 0);
    }

    function testERC721_ERC721CommonTests_AccountMaxValueByAccessLevel_Mint() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpAccountMaxValueByAccessLevelRule(ActionTypes.MINT);
        switchToAppAdministrator();
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 0, 1 * ATTO);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user, 2);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
    }

    function testERC721_ERC721CommonTests_AccountMaxValueByAccessLevel_Mint_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 0, 1 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 1, 1 * ATTO);
        _setUpAccountMaxValueByAccessLevelRule(ActionTypes.MINT);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user, 0);
        switchToAppAdministrator();
        vm.expectRevert(abi.encodeWithSignature("OverMaxValueByAccessLevel()"));
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
    }

    function testERC721_ERC721CommonTests_AccountMaxValueByAccessLevel_Burn() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpAccountMaxValueByAccessLevelRule(ActionTypes.P2P_TRANSFER);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 0, 1 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 1, 1 * ATTO);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user, 2);
        applicationAppManager.addAccessLevel(user2, 0);
        switchToUser();
        /// check that burns are not checked by the rule
        ERC721Burnable(address(testCaseNFT)).burn(0);
    }

    function testERC721_ERC721CommonTests_AccountMaxValueByAccessLevel_Buy() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        switchToAppAdministrator();
        for (uint256 i; i < 15; i++) {
            /// set all NFTs up to tokenId 15 to valuation of $1
            erc721Pricer.setSingleNFTPrice(address(testCaseNFT), i, 1 * ATTO);
        }
        _setUpAccountMaxValueByAccessLevelRule(ActionTypes.BUY);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user, 4);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 1, true);
    }

    function testERC721_ERC721CommonTests_AccountMaxValueByAccessLevel_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        switchToAppAdministrator();
        for (uint256 i; i < 15; i++) {
            /// set all NFTs up to tokenId 15 to valuation of $1
            erc721Pricer.setSingleNFTPrice(address(testCaseNFT), i, 1 * ATTO);
        }
        _setUpAccountMaxValueByAccessLevelRule(ActionTypes.BUY);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user, 0);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        vm.expectRevert(abi.encodeWithSignature("OverMaxValueByAccessLevel()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 0, 1, true);
    }

    function _setUpAccountMaxValueByAccessLevelRule(ActionTypes action) internal {
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, 100, 500, 750, 1500);
        setAccountMaxValueByAccessLevelRuleSingleAction(action, ruleId);
    }

    function testERC721_ERC721CommonTests_MaxValueOutByAccessLevel_Transfer_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpAccountMaxValueOutByAccessLevelRule(ActionTypes.P2P_TRANSFER);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 0, 1 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 1, 1 * ATTO);
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user, 1);
        applicationAppManager.addAccessLevel(user2, 1);
        switchToUser();
        UtilApplicationERC721(address(testCaseNFT)).safeTransferFrom(user, user2, 0);
    }

    function testERC721_ERC721CommonTests_MaxValueOutByAccessLevel_Transfer_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpAccountMaxValueOutByAccessLevelRule(ActionTypes.P2P_TRANSFER);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 0, 1 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 1, 1 * ATTO);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user, 0);
        applicationAppManager.addAccessLevel(user2, 2);
        switchToUser();
        UtilApplicationERC721(address(testCaseNFT)).safeTransferFrom(user, user2, 1);
        vm.expectRevert(abi.encodeWithSignature("OverMaxValueOutByAccessLevel()"));
        UtilApplicationERC721(address(testCaseNFT)).safeTransferFrom(user, user2, 0);
    }

    function testERC721_ERC721CommonTests_MaxValueOutByAccessLevel_Burn_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpAccountMaxValueOutByAccessLevelRule(ActionTypes.BURN);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 0, 1 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 1, 1 * ATTO);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user, 2);
        switchToUser();
        ERC721Burnable(address(testCaseNFT)).burn(0);
    }

    function testERC721_ERC721CommonTests_MaxValueOutByAccessLevel_Burn_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpAccountMaxValueOutByAccessLevelRule(ActionTypes.BURN);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 0, 1 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 1, 1 * ATTO);
        switchToUser();
        ERC721Burnable(address(testCaseNFT)).burn(1);
        vm.expectRevert(abi.encodeWithSignature("OverMaxValueOutByAccessLevel()"));
        ERC721Burnable(address(testCaseNFT)).burn(0);
    }

    function testERC721_ERC721CommonTests_MaxValueOutByAccessLevel_Sell_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        switchToAppAdministrator();
        for (uint256 i; i < 15; i++) {
            /// set all NFTs up to tokenId 15 to valuation of $1
            erc721Pricer.setSingleNFTPrice(address(testCaseNFT), i, 1 * ATTO);
        }
        _setUpAccountMaxValueOutByAccessLevelRule(ActionTypes.SELL);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user, 1);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 11, false);
    }

    function testERC721_ERC721CommonTests_MaxValueOutByAccessLevel_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        switchToAppAdministrator();
        for (uint256 i; i < 15; i++) {
            /// set all NFTs up to tokenId 15 to valuation of $1
            erc721Pricer.setSingleNFTPrice(address(testCaseNFT), i, 1 * ATTO);
        }
        _setUpAccountMaxValueOutByAccessLevelRule(ActionTypes.SELL);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 12, false);
        vm.expectRevert(abi.encodeWithSignature("OverMaxValueOutByAccessLevel()"));
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 11, false);
    }

    function testERC721_ERC721CommonTests_MaxValueOutByAccessLevel_Buy_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpNFTAMMForRuleChecks();
        switchToAppAdministrator();
        for (uint256 i; i < 15; i++) {
            /// set all NFTs up to tokenId 15 to valuation of $1
            erc721Pricer.setSingleNFTPrice(address(testCaseNFT), i, 1 * ATTO);
        }
        _setUpAccountMaxValueOutByAccessLevelRule(ActionTypes.SELL);
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        applicationCoin.approve(address(amm), 10 * ATTO);
        // ensure Buys do not trigger the rule (allow for accumulation through purchases)
        amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, 1, true);
    }

    function _setUpAccountMaxValueOutByAccessLevelRule(ActionTypes action) internal {
        uint32 ruleId = createAccountMaxValueOutByAccessLevelRule(1, 100, 500, 750, 1500);
        setAccountMaxValueOutByAccessLevelSingleAction(action, ruleId);
    }

    function testERC721_ERC721CommonTests_NFTValuationOrig_Fails() public endWithStopPrank ifDeploymentTestsEnabled {
        /// retest rule to ensure proper valuation totals
        /// user 2 has access level 1 and can hold balance of 1
        _NFTValuationOrigSetup();
        vm.startPrank(user1, user1);
        testCaseNFT.transferFrom(user1, user2, 1);
        /// user 1 has access level of 2 and can hold balance of 10 (currently above this after admin transfers)
        vm.startPrank(user2, user2);
        vm.expectRevert(0xaee8b993);
        testCaseNFT.transferFrom(user2, user1, 1);
    }

    function testERC721_ERC721CommonTests_NFTValuationOrig_IncreaseAccessLevel() public endWithStopPrank ifDeploymentTestsEnabled {
        _NFTValuationOrigSetup();
        vm.startPrank(user1, user1);
        testCaseNFT.transferFrom(user1, user2, 1);
        /// increase user 1 access level to allow for balance of $50 USD
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user1, 3);
        /**
        This passes because: 
        Handler Valuation limits are set at 20 
        Valuation will check collection price (Floor or ceiling) * tokens held by address 
        Actual valuation of user 1 is:
        9 PudgeyPenguins ($9USD) + 40 ToughTurtles ((37 * $1USD) + (1 * $100USD) + (1 * $50USD) + (1 * $25USD) = $221USD)
         */
        vm.startPrank(user2, user2);
        testCaseNFT.transferFrom(user2, user1, 1);
    }

    function testERC721_ERC721CommonTests_NFTValuationOrig_AdjustValuation() public endWithStopPrank ifDeploymentTestsEnabled {
        _NFTValuationOrigSetup();
        /// adjust nft valuation limit to ensure we revert back to individual pricing
        switchToAppAdministrator();
        ERC721HandlerMainFacet(address(applicationNFTHandler)).setNFTValuationLimit(50);
        vm.startPrank(user1, user1);
        testCaseNFT.transferFrom(user1, user2, 1);
        /// fails because valuation now prices each individual token so user 1 has $221USD account value
        vm.startPrank(user2, user2);
        vm.expectRevert(0xaee8b993);
        testCaseNFT.transferFrom(user2, user1, 1);
    }

    function testERC721_ERC721CommonTests_NFTValuationOrig_Burning() public endWithStopPrank ifDeploymentTestsEnabled {
        _NFTValuationOrigSetup();
        vm.startPrank(user1, user1);
        testCaseNFT.transferFrom(user1, user2, 1);
        vm.startPrank(user2, user2);
        /// test burn with rule active user 2
        ERC721Burnable(address(testCaseNFT)).burn(1);
        /// test burns with user 1
        vm.startPrank(user1, user1);
        ERC721Burnable(address(testCaseNFT)).burn(3);
        applicationNFTv2.burn(36);
    }

    function testERC721_ERC721CommonTests_UpgradeAppManager721_ZeroAddress() public endWithStopPrank ifDeploymentTestsEnabled {
        if (vm.envAddress("DEPLOYMENT_OWNER") != address(0x0)) {
            // Example ERC721 does not connect to the appManager through the token so this test is not relevant
            vm.skip(true);
        } else {
            _upgradeAppManager721Setup();
            switchToAppAdministrator();
            // zero address
            vm.expectRevert(0xd92e233d);

            ProtocolTokenCommon(address(testCaseNFT)).proposeAppManagerAddress(address(0));
        }
    }

    function testERC721_ERC721CommonTests_UpgradeAppManager721_NoProposedAddress() public endWithStopPrank ifDeploymentTestsEnabled {
        if (vm.envAddress("DEPLOYMENT_OWNER") != address(0x0)) {
            // Example ERC721 does not connect to the appManager through the token so this test is not relevant
            vm.skip(true);
        } else {
            _upgradeAppManager721Setup();
            switchToAppAdministrator();
            // no proposed address
            vm.expectRevert(0x821e0eeb);
            applicationAppManager2.confirmAppManager(address(testCaseNFT));
        }
    }

    function testERC721_ERC721CommonTests_UpgradeAppManager721_NonProposerConfirms() public endWithStopPrank ifDeploymentTestsEnabled {
        if (vm.envAddress("DEPLOYMENT_OWNER") != address(0x0)) {
            // Example ERC721 does not connect to the appManager through the token so this test is not relevant
            vm.skip(true);
        } else {
            _upgradeAppManager721Setup();
            switchToAppAdministrator();
            // non proposer tries to confirm
            ProtocolTokenCommon(address(testCaseNFT)).proposeAppManagerAddress(address(applicationAppManager2));
            ApplicationAppManager applicationAppManager3 = new ApplicationAppManager(newAdmin, "Castlevania3", false);
            switchToNewAdmin();
            applicationAppManager3.addAppAdministrator(address(appAdministrator));
            switchToAppAdministrator();
            vm.expectRevert(0x41284967);
            applicationAppManager3.confirmAppManager(address(testCaseNFT));
        }
    }

    function testERC721_ERC721CommonTests_TokenMaxBuySellVolumeRuleBuy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxBuySellVolumeRuleSetupBuyAction();
        uint16 tokenPercentage = 10; /// 1%
        vm.startPrank(user, user);
        vm.expectRevert(0xfa006f25);
        _testBuyNFT(tokenPercentage, amm);
        /// switch users and test rule still fails
        vm.startPrank(user1, user1);
        _approveTokens(amm, 5 * 10 ** 8 * ATTO, true);
        vm.expectRevert(0xfa006f25);
        _testBuyNFT(tokenPercentage + 1, amm);
    }

    function testERC721_ERC721CommonTests_TokenMaxBuySellVolumeRuleBuyAction_Period() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxBuySellVolumeRuleSetupBuyAction();
        uint16 tokenPercentage = 10; /// 1%

        /// let's go to another period
        vm.warp(Blocktime + 72 hours);
        switchToUser();
        /// now it should work
        _testBuyNFT(tokenPercentage + 1, amm);
        /// with another user
        vm.startPrank(user1, user1);
        _approveTokens(amm, 5 * 10 ** 8 * ATTO, true);
        /// we have to do this manually since the _testBuyNFT uses the *user* acccount
        _testBuyNFT(tokenPercentage + 2, amm);
    }

    function testERC721_ERC721CommonTests_TokenMaxBuySellVolumeRule_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxBuySellVolumeRuleSetupSellAction();
        uint16 tokenPercentageSell = 30; /// 0.30%
        /// If try to sell one more, it should fail in this period.
        vm.startPrank(user, user);
        vm.expectRevert(0xfa006f25);
        _testSellNFT(erc721Liq / 2 + tokenPercentageSell, amm);
        /// switch users and test rule still fails
        vm.startPrank(user1, user1);
        _approveTokens(amm, 5 * 10 ** 8 * ATTO, true);
        vm.expectRevert(0xfa006f25);
        _testSellNFT(erc721Liq / 2 + 100 + 1, amm);
    }

    function testERC721_ERC721CommonTests_TokenMaxBuySellVolumeRule_Period() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxBuySellVolumeRuleSetupBuyAction();
        uint16 tokenPercentageSell = 30; /// 0.30%
        /// let's go to another period
        vm.warp(Blocktime + 72 hours);
        switchToUser();
        /// now it should work
        _testSellNFT(erc721Liq / 2 + tokenPercentageSell + 1, amm);
        /// with another user
        vm.startPrank(user1, user1);
        _approveTokens(amm, 5 * 10 ** 8 * ATTO, true);
        _testSellNFT(erc721Liq / 2 + 100 + 2, amm);
    }

    function testERC721_ERC721CommonTests_AccountMaxTradeSizeSell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxTradeSizeSellSetup(true);
        switchToUser();
        /// Swap that fails
        vm.expectRevert(0x523976c2);
        _testSellNFT(erc721Liq / 2 + 2, amm);
    }

    function testERC721_ERC721CommonTests_AccountMaxTradeSizeSell_Period() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxTradeSizeSellSetup(true);
        switchToUser();
        /// we wait until the next period so user can swap again
        vm.warp(block.timestamp + 36 hours);
        _testSellNFT(erc721Liq / 2 + 2, amm);
    }

    function testERC721_ERC721CommonTests_AccountMaxTradeSizeSell_BlankTag_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxTradeSizeSellSetup(false);
        switchToUser();
        /// Swap that fails
        vm.expectRevert(0x523976c2);
        _testSellNFT(erc721Liq / 2 + 2, amm);
    }

    function testERC721_ERC721CommonTests_AccountMaxTradeSizeSell_BlankTag_Period() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxTradeSizeSellSetup(false);
        switchToUser();
        /// we wait until the next period so user can swap again
        vm.warp(block.timestamp + 36 hours);
        _testSellNFT(erc721Liq / 2 + 2, amm);
    }

    function testERC721_ERC721CommonTests_AccountMaxTradeSizeBuy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxTradeSizeBuyRuleSetup();
        switchToUser();
        /// Swap that fails
        vm.expectRevert(0x523976c2);
        _testBuyNFT(1, amm);
    }

    function testERC721_ERC721CommonTests_AccountMaxTradeSizeBuy_Period() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxTradeSizeBuyRuleSetup();
        switchToUser();
        /// we wait until the next period so user can swap again
        vm.warp(block.timestamp + 36 hours);
        _testBuyNFT(1, amm);
    }

    function testERC721_ERC721CommonTests_AccountMaxTradeSizeAtomicFull_ZeroLengthActions() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](2);
        // Set up rules
        ruleIds[1] = createAccountMaxTradeSizeRule("MaxSellSize", 1, 24);
        ruleIds[0] = createAccountMaxTradeSizeRule("MaxBuySize", 1, 24);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.SELL, ActionTypes.BUY);

        // Apply the rules to all actions
        setAccountMaxTradeSizeRuleFull(address(applicationNFTHandler), actions, ruleIds);

        // Verify that all the rule id's were set correctly
        for (uint i; i < ruleIds.length; i++) {
            assertEq(TradingRuleFacet(address(applicationNFTHandler)).getAccountMaxTradeSizeId(actions[i]), ruleIds[i]);
            assertTrue(TradingRuleFacet(address(applicationNFTHandler)).isAccountMaxTradeSizeActive(actions[i]));
        }

        // Create zero length arrays
        uint32[] memory ruleIdsZero = new uint32[](0);
        ActionTypes[] memory actionsZero = new ActionTypes[](0);

        // Apply the rules to all actions
        setAccountMaxTradeSizeRuleFull(address(applicationNFTHandler), actionsZero, ruleIdsZero);

        // Verify that all the rule id's were cleared correctly and actions deactivated
        for (uint i; i < ruleIds.length; i++) {
            assertEq(TradingRuleFacet(address(applicationNFTHandler)).getAccountMaxTradeSizeId(actions[i]), 0);
            assertFalse(TradingRuleFacet(address(applicationNFTHandler)).isAccountMaxTradeSizeActive(actions[i]));
        }
    }

    function testERC721_ERC721CommonTests_TokenMaxBuySellVolumeTreasuryerRule_AllowListPass() public endWithStopPrank ifDeploymentTestsEnabled {
        uint16 tokenPercentageSell = 30; /// 0.30%
        _tokenMaxBuySellVolumeTreasuryerRuleSetupSell();
        /// ALLOWLISTED USER
        switchToUser();
        _approveTokens(amm, 5 * 10 ** 8 * ATTO, true);
        /// we test going above rule percentage in the period is ok for user (... + 1)
        for (uint i = erc721Liq / 2; i < erc721Liq / 2 + (erc721Liq * tokenPercentageSell) / 10000 + 1; i++) {
            _testSellNFT(i, amm);
        }
    }

    function testERC721_ERC721CommonTests_TokenMaxBuySellVolumeTreasuryerRule_NotAllowListPass() public endWithStopPrank ifDeploymentTestsEnabled {
        uint16 tokenPercentageSell = 30; /// 0.30%
        _tokenMaxBuySellVolumeTreasuryerRuleSetupSell();
        /// NOT ALLOWLISTED USER
        vm.startPrank(user1, user1);
        _approveTokens(amm, 5 * 10 ** 8 * ATTO, true);
        /// we test going right below the rule percentage in the period (... - 1)
        for (uint i = erc721Liq / 2 + 100; i < erc721Liq / 2 + 100 + (erc721Liq * tokenPercentageSell) / 10000 - 1; i++) {
            _testSellNFT(i, amm);
        }
    }

    function testERC721_ERC721CommonTests_TokenMaxBuySellVolumeTreasuryerRule_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        uint16 tokenPercentageSell = 30; /// 0.30%
        _tokenMaxBuySellVolumeTreasuryerRuleSetupSell();
        vm.startPrank(user1, user1);
        _approveTokens(amm, 5 * 10 ** 8 * ATTO, true);
        /// we test going right below the rule percentage in the period (... - 1)
        for (uint i = erc721Liq / 2 + 100; i < erc721Liq / 2 + 100 + (erc721Liq * tokenPercentageSell) / 10000 - 1; i++) {
            _testSellNFT(i, amm);
        }
        /// and now we test the actual rule with a non-allowlisted address to check it will fail
        vm.expectRevert(0xfa006f25);
        _testSellNFT(erc721Liq / 2 + 100 + (erc721Liq * tokenPercentageSell) / 10000, amm);
    }

    function testERC721_ERC721CommonTests_TokenMaxBuySellVolumeFull_ZeroLengthActions() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](2);
        // Set up rules
        ruleIds[0] = createTokenMaxBuySellVolumeRule(25, 48, 0, Blocktime);
        ruleIds[1] = createTokenMaxBuySellVolumeRule(25, 24, 0, Blocktime);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.SELL, ActionTypes.BUY);

        // Apply the rules to all actions
        setTokenMaxBuySellVolumeIdFull(address(applicationNFTHandler), actions, ruleIds);

        // Verify that all the rule id's were set correctly
        for (uint i; i < ruleIds.length; ++i) {
            assertEq(TradingRuleFacet(address(applicationNFTHandler)).getTokenMaxBuySellVolumeId(actions[i]), ruleIds[i]);
            assertTrue(TradingRuleFacet(address(applicationNFTHandler)).isTokenMaxBuySellVolumeActive(actions[i]));
        }

        // Create zero length arrays
        uint32[] memory ruleIdsZero = new uint32[](0);
        ActionTypes[] memory actionsZero = new ActionTypes[](0);

        // Apply zero length actions
        setTokenMaxBuySellVolumeIdFull(address(applicationNFTHandler), actionsZero, ruleIdsZero);

        // Verify that all the rule id's were set correctly
        for (uint i; i < ruleIds.length; ++i) {
            assertEq(TradingRuleFacet(address(applicationNFTHandler)).getTokenMaxBuySellVolumeId(actions[i]), 0);
            assertFalse(TradingRuleFacet(address(applicationNFTHandler)).isTokenMaxBuySellVolumeActive(actions[i]));
        }
    }

    /* TokenMaxDailyTrades */
    function testERC721_ERC721CommonTests_TokenMaxDailyTradesAtomicFullSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](4);
        // Set up rule
        // for (uint i; i < ruleIds.length; i++) ruleIds[i] = createTokenMaxDailyTradesRule(bytes32(abi.encodePacked("BoredGrape", i)), bytes32("DiscoPunk"), uint8(1), uint8(5 + (uint8(i) * 10)));
        ruleIds[0] = createTokenMaxDailyTradesRule("BoredGrape1", "DiscoPunk", 1, 5);
        ruleIds[1] = createTokenMaxDailyTradesRule("BoredGrape2", "DiscoPunk", 1, 15);
        ruleIds[2] = createTokenMaxDailyTradesRule("BoredGrape3", "DiscoPunk", 1, 25);
        ruleIds[3] = createTokenMaxDailyTradesRule("BoredGrape4", "DiscoPunk", 1, 35);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BUY, ActionTypes.MINT);
        // Apply the rules to all actions
        setTokenMaxDailyTradesRuleFull(address(applicationNFTHandler), actions, ruleIds);
        // Verify that all the rule id's were set correctly
        for (uint i; i < ruleIds.length; i++) assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxDailyTradesId(actions[i]), ruleIds[i]);
        // Verify that all the rules were activated
        for (uint i; i < ruleIds.length; i++) assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMaxDailyTradesActive(actions[i]));
    }

    function testERC721_ERC721CommonTests_TokenMaxDailyTradesAtomicFullReSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](4);
        // Set up rule
        // for (uint i; i < ruleIds.length; i++) ruleIds[i] = createTokenMaxDailyTradesRule(string.concat("BoredGrape", vm.toString(i + 1)), "DiscoPunk", 1, 5 + (i * 10));
        ruleIds[0] = createTokenMaxDailyTradesRule("BoredGrape1", "DiscoPunk", 1, 5);
        ruleIds[1] = createTokenMaxDailyTradesRule("BoredGrape2", "DiscoPunk", 1, 15);
        ruleIds[2] = createTokenMaxDailyTradesRule("BoredGrape3", "DiscoPunk", 1, 25);
        ruleIds[3] = createTokenMaxDailyTradesRule("BoredGrape4", "DiscoPunk", 1, 35);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BUY, ActionTypes.MINT);
        // Apply the rules to all actions
        setTokenMaxDailyTradesRuleFull(address(applicationNFTHandler), actions, ruleIds);
        // Reset with a partial list of rules and insure that the changes are saved correctly
        ruleIds = new uint32[](2);
        ruleIds[0] = createTokenMaxDailyTradesRule("BoredGrape6", "DiscoPunk", 1, 65);
        ruleIds[1] = createTokenMaxDailyTradesRule("BoredGrape7", "DiscoPunk", 1, 75);
        actions = createActionTypeArray(ActionTypes.SELL, ActionTypes.BUY);
        // Apply the new set of rules
        setTokenMaxDailyTradesRuleFull(address(applicationNFTHandler), actions, ruleIds);
        // Verify that all the rule id's were set correctly
        for (uint i; i < ruleIds.length; i++) assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxDailyTradesId(actions[i]), ruleIds[i]);
        // Verify that the old ones were cleared
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxDailyTradesId(ActionTypes.P2P_TRANSFER), 0);
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxDailyTradesId(ActionTypes.MINT), 0);
        // Verify that the new rules were activated
        for (uint i; i < ruleIds.length; i++) assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMaxDailyTradesActive(actions[i]));
        // Verify that the old rules are not activated
        assertFalse(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMaxDailyTradesActive(ActionTypes.P2P_TRANSFER));
        assertFalse(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMaxDailyTradesActive(ActionTypes.MINT));
    }

    function testERC721_ERC721CommonTests_TokenMaxDailyTradesAtomicFull_ZeroLengthActions() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](4);
        // Set up rules
        ruleIds[0] = createTokenMaxDailyTradesRule("PudgyPlatypuses1", "Dudeles", 1, 5);
        ruleIds[1] = createTokenMaxDailyTradesRule("PudgyPlatypuses2", "Dudeles", 1, 15);
        ruleIds[2] = createTokenMaxDailyTradesRule("PudgyPlatypuses3", "Dudeles", 1, 25);
        ruleIds[3] = createTokenMaxDailyTradesRule("PudgyPlatypuses4", "Dudeles", 1, 35);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BUY, ActionTypes.MINT);

        // Apply the rules to all actions
        setTokenMaxDailyTradesRuleFull(address(applicationNFTHandler), actions, ruleIds);

        // Verify that all the rule id's were set correctly
        for (uint i; i < ruleIds.length; ++i) {
            assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxDailyTradesId(actions[i]), ruleIds[i]);
            assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMaxDailyTradesActive(actions[i]));
        }

        // Create zero length arrays
        uint32[] memory ruleIdsZero = new uint32[](0);
        ActionTypes[] memory actionsZero = new ActionTypes[](0);

        // Apply new zero length rules
        setTokenMaxDailyTradesRuleFull(address(applicationNFTHandler), actionsZero, ruleIdsZero);

        // Verify that all the rules were cleared and deactivated
        for (uint i; i < ruleIds.length; ++i) {
            assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxDailyTradesId(actions[i]), 0);
            assertFalse(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMaxDailyTradesActive(actions[i]));
        }
    }

    /* TokenMaxSupplyVolatility */
    function testERC721_ERC721CommonTests_TokenMaxSupplyVolatilityAtomicFullSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32 ruleId;
        // Set up rule
        ruleId = createTokenMaxSupplyVolatilityRule(2000, 4, Blocktime, 0);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.MINT, ActionTypes.BURN);
        // Apply the rules to all actions
        setTokenMaxSupplyVolatilityRuleFull(address(applicationNFTHandler), actions, ruleId);
        // Verify that all the rule id's were set correctly
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxSupplyVolatilityId(ActionTypes.MINT), ruleId);
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxSupplyVolatilityId(ActionTypes.BURN), ruleId);
        // Verify that all the rules were activated
        assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMaxSupplyVolatilityActive(ActionTypes.MINT));
        assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMaxSupplyVolatilityActive(ActionTypes.BURN));
    }

    function testERC721_ERC721CommonTests_TokenMaxSupplyVolatilityAtomicFullReSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32 ruleId;
        // Set up rule
        ruleId = createTokenMaxSupplyVolatilityRule(2000, 4, Blocktime, 0);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.MINT, ActionTypes.BURN);
        // Apply the rules to all actions
        setTokenMaxSupplyVolatilityRuleFull(address(applicationNFTHandler), actions, ruleId);
        // Reset with a partial list of rules and insure that the changes are saved correctly
        ruleId = createTokenMaxSupplyVolatilityRule(2011, 6, Blocktime, 0);
        actions = createActionTypeArray(ActionTypes.MINT);
        // Apply the new set of rules
        setTokenMaxSupplyVolatilityRuleFull(address(applicationNFTHandler), actions, ruleId);
        // Verify that all the rule id's were set correctly
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxSupplyVolatilityId(ActionTypes.MINT), ruleId);
        // Verify that the new rules were activated
        assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMaxSupplyVolatilityActive(ActionTypes.MINT));
        // Verify that the old rules are not activated
        assertFalse(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMaxSupplyVolatilityActive(ActionTypes.BURN));
    }

    /* TokenMaxTradingVolume */
    function testERC721_ERC721CommonTests_TokenMaxTradingVolumeAtomicFullSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32 ruleId;
        // Set up rule
        ruleId = createTokenMaxTradingVolumeRule(1000, 2, Blocktime, 100_000 * ATTO);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BUY, ActionTypes.MINT, ActionTypes.BURN);
        // Apply the rules to all actions
        setTokenMaxTradingVolumeRuleFull(address(applicationNFTHandler), actions, ruleId);
        // Verify that all the rule id's were set correctly
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxTradingVolumeId(ActionTypes.P2P_TRANSFER), ruleId);
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxTradingVolumeId(ActionTypes.SELL), ruleId);
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxTradingVolumeId(ActionTypes.BUY), ruleId);
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxTradingVolumeId(ActionTypes.MINT), ruleId);
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxTradingVolumeId(ActionTypes.BURN), ruleId);
        // Verify that all the rules were activated
        for (uint i; i < 5; i++) assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMaxTradingVolumeActive(ActionTypes(i)));
    }

    function testERC721_ERC721CommonTests_TokenMaxTradingVolumeAtomicFullReSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32 ruleId;
        // Set up rule
        ruleId = createTokenMaxTradingVolumeRule(1000, 2, Blocktime, 100_000 * ATTO);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BUY, ActionTypes.MINT, ActionTypes.BURN);
        // Apply the rules to all actions
        setTokenMaxTradingVolumeRuleFull(address(applicationNFTHandler), actions, ruleId);
        // Reset with a partial list of rules and insure that the changes are saved correctly
        ruleId = createTokenMaxTradingVolumeRule(6000, 2, Blocktime, 200_000 * ATTO);
        actions = createActionTypeArray(ActionTypes.SELL, ActionTypes.BUY);
        // Apply the new set of rules
        setTokenMaxTradingVolumeRuleFull(address(applicationNFTHandler), actions, ruleId);
        // Verify that all the rule id's were set correctly
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxTradingVolumeId(ActionTypes.SELL), ruleId);
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxTradingVolumeId(ActionTypes.BUY), ruleId);
        // Verify that the old ones were cleared
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxTradingVolumeId(ActionTypes.P2P_TRANSFER), 0);
        // assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxTradingVolumeId(ActionTypes.MINT), 0);
        // assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMaxTradingVolumeId(ActionTypes.BURN), 0);
        // // Verify that the new rules were activated
        // assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMaxTradingVolumeActive(ActionTypes.SELL));
        // assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMaxTradingVolumeActive(ActionTypes.BUY));
        // // Verify that the old rules are not activated
        // assertFalse(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMaxTradingVolumeActive(ActionTypes.P2P_TRANSFER));
        // assertFalse(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMaxTradingVolumeActive(ActionTypes.MINT));
        // assertFalse(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMaxTradingVolumeActive(ActionTypes.BURN));
    }

    /* TokenMinHoldTime */
    function testERC721_ERC721CommonTests_TokenMinHoldTimeAtomicFullSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory rules = new uint32[](3);
        // Set up rule
        for (uint i; i < rules.length; i++) {
            rules[i] = createTokenMinHoldTimeRule(uint32(i + 1));
        }
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BURN);
        // Apply the rules to all actions
        setTokenMinHoldTimeRuleFull(address(applicationNFTHandler), actions, rules);
        // Verify that all the rule id's were set correctly
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinHoldTimePeriod(ActionTypes.P2P_TRANSFER), rules[0]);
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinHoldTimePeriod(ActionTypes.SELL), rules[1]);
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinHoldTimePeriod(ActionTypes.BURN), rules[2]);
        // Verify that all the rules were activated
        assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMinHoldTimeActive(ActionTypes(actions[0])));
        assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMinHoldTimeActive(ActionTypes(actions[1])));
        assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMinHoldTimeActive(ActionTypes(actions[2])));
    }

    function testERC721_ERC721CommonTests_TokenMinHoldTimeAtomicFullReSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory rules = new uint32[](3);
        // Set up rule
        for (uint i; i < rules.length; i++) rules[i] = createTokenMinHoldTimeRule(uint32(i + 1));
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BURN);
        // Apply the rules to all actions
        setTokenMinHoldTimeRuleFull(address(applicationNFTHandler), actions, rules);
        // Reset with a partial list of rules and insure that the changes are saved correctly
        rules = new uint32[](2);
        rules[0] = createTokenMinHoldTimeRule(6);
        rules[1] = createTokenMinHoldTimeRule(7);
        actions = createActionTypeArray(ActionTypes.SELL, ActionTypes.BURN);
        // Apply the new set of rules

        setTokenMinHoldTimeRuleFull(address(applicationNFTHandler), actions, rules);
        // Verify that all the rule id's were set correctly
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinHoldTimePeriod(ActionTypes.SELL), rules[0]);
        // Verify that the old ones were cleared
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinHoldTimePeriod(ActionTypes.P2P_TRANSFER), 0);
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinHoldTimePeriod(ActionTypes.BURN), rules[1]);
        // Verify that the new rules were activated
        assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMinHoldTimeActive(ActionTypes.SELL));
        // Verify that the old rules are not activated
        assertFalse(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMinHoldTimeActive(ActionTypes.P2P_TRANSFER));
    }

    function testERC721_ERC721CommonTests_TokenMinHoldTimeAtomicFull_ZeroLengthActions() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();

        uint32[] memory periods = new uint32[](3);
        // Set up rules
        for (uint i; i < periods.length; i++) periods[i] = createTokenMinHoldTimeRule(uint32(i + 1));
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BURN);

        // Apply the rules to all actions
        setTokenMinHoldTimeRuleFull(address(applicationNFTHandler), actions, periods);

        // Verify that all the rule id's were set correctly and activated
        for (uint i; i < periods.length; ++i) {
            assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinHoldTimePeriod(actions[i]), periods[i]);
            assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMinHoldTimeActive(actions[i]));
        }

        // Create zero length arrays
        uint32[] memory periodsZero = new uint32[](0);
        ActionTypes[] memory actionsZero = new ActionTypes[](0);

        // Apply new zero length rules
        setTokenMinHoldTimeRuleFull(address(applicationNFTHandler), actionsZero, periodsZero);

        // Verify that all rules were cleared and actions deactivated
        for (uint i; i < periods.length; ++i) {
            assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinHoldTimePeriod(actions[i]), 0);
            assertFalse(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMinHoldTimeActive(actions[i]));
        }
    }

    /* AccountApproveDenyOracle */
    function testERC721_ERC721CommonTests_AccountApproveDenyOracleAtomicFullSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](25);
        ActionTypes[] memory actions = new ActionTypes[](25);
        // Set up rule
        uint256 actionIndex;
        uint256 mainIndex;
        for (uint i; i < 5; i++) {
            for (uint j; j < 5; j++) {
                actions[mainIndex] = ActionTypes(actionIndex);
                ruleIds[mainIndex] = createAccountApproveDenyOracleRule(0);
                mainIndex++;
            }
            actionIndex++;
        }

        // Apply the rules to all actions
        setAccountApproveDenyOracleRuleFull(address(applicationNFTHandler), actions, ruleIds);
        // Verify that all the rule id's were set correctly and are active(Had to go old school with control break logic)
        mainIndex = 0;
        uint256 internalIndex;
        ActionTypes lastAction;
        for (uint i; i < 5; i++) {
            if (actions[mainIndex] != lastAction) {
                internalIndex = 0;
            }
            for (uint j; j < 5; j++) {
                assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getAccountApproveDenyOracleIds(actions[mainIndex])[internalIndex], ruleIds[mainIndex]);
                assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isAccountApproveDenyOracleActive(actions[mainIndex], ruleIds[mainIndex]));
                lastAction = actions[mainIndex];
                internalIndex++;
                mainIndex++;
            }
        }
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracleAtomicFullReSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](25);
        ActionTypes[] memory actions = new ActionTypes[](25);
        // Set up rule
        uint256 actionIndex;
        uint256 mainIndex;
        for (uint i; i < 5; i++) {
            for (uint j; j < 5; j++) {
                actions[mainIndex] = ActionTypes(actionIndex);
                ruleIds[mainIndex] = createAccountApproveDenyOracleRule(0);
                mainIndex++;
            }
            actionIndex++;
        }

        // Apply the rules to all actions
        setAccountApproveDenyOracleRuleFull(address(applicationNFTHandler), actions, ruleIds);
        // Reset with a partial list of rules and insure that the changes are saved correctly
        uint32[] memory ruleIds2 = new uint32[](24);
        ActionTypes[] memory actions2 = new ActionTypes[](24);
        actionIndex = 0;
        mainIndex = 0;
        for (uint i; i < 3; i++) {
            for (uint j; j < 8; j++) {
                actions2[mainIndex] = ActionTypes(actionIndex);
                ruleIds2[mainIndex] = createAccountApproveDenyOracleRule(0);
                mainIndex++;
            }
            actionIndex++;
        }
        // Apply the new set of rules
        setAccountApproveDenyOracleRuleFull(address(applicationNFTHandler), actions2, ruleIds2);
        // Verify that all the rule id's were set correctly and are active(Had to go old school with control break logic)
        mainIndex = 0;
        uint256 internalIndex;
        ActionTypes lastAction;
        for (uint i; i < 3; i++) {
            if (actions2[mainIndex] != lastAction) {
                internalIndex = 0;
            }
            for (uint j; j < 8; j++) {
                assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getAccountApproveDenyOracleIds(actions2[mainIndex])[internalIndex], ruleIds2[mainIndex]);
                assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isAccountApproveDenyOracleActive(actions2[mainIndex], ruleIds2[mainIndex]));
                lastAction = actions2[mainIndex];
                internalIndex++;
                mainIndex++;
            }
        }

        // Verify that all the rule id's were cleared for the previous set of rules(Had to go old school with control break logic)
        mainIndex = 0;
        internalIndex = 0;
        lastAction = ActionTypes(0);
        for (uint i; i < 5; i++) {
            if (actions[mainIndex] != lastAction) {
                internalIndex = 0;
            }
            for (uint j; j < 5; j++) {
                uint32[] memory ruleIds3 = ERC20NonTaggedRuleFacet(address(applicationNFTHandler)).getAccountApproveDenyOracleIds(actions[mainIndex]);
                // If a value was returned it must not match a previous rule
                if (ruleIds3.length > 0) {
                    assertFalse(ruleIds3[internalIndex] == ruleIds[mainIndex]);
                }
                assertFalse(ERC20NonTaggedRuleFacet(address(applicationNFTHandler)).isAccountApproveDenyOracleActive(actions[mainIndex], ruleIds[mainIndex]));
                lastAction = actions[mainIndex];
                internalIndex++;
                mainIndex++;
            }
        }
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracleRulefull_ZeroLengthActions() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](25);
        ActionTypes[] memory actions = new ActionTypes[](25);

        // Set up rules
        uint256 actionIndex;
        uint256 mainIndex;
        for (uint i; i < 5; i++) {
            for (uint j; j < 5; j++) {
                actions[mainIndex] = ActionTypes(actionIndex);
                ruleIds[mainIndex] = createAccountApproveDenyOracleRule(0);
                mainIndex++;
            }
            actionIndex++;
        }

        // Apply the rules to all actions
        setAccountApproveDenyOracleRuleFull(address(applicationNFTHandler), actions, ruleIds);

        // Verify that all the rule id's were set correctly and are active
        for (uint i; i < 5; ++i) {
            assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getAccountApproveDenyOracleIds(actions[i])[i], ruleIds[i]);
            assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isAccountApproveDenyOracleActive(actions[i], ruleIds[i]));
        }

        // Create zero length arrays
        uint32[] memory ruleIdsZero = new uint32[](0);
        ActionTypes[] memory actionsZero = new ActionTypes[](0);

        // Apply zero length arrays
        setAccountApproveDenyOracleRuleFull(address(applicationNFTHandler), actionsZero, ruleIdsZero);

        // Verify that all the rule ids were cleared and not active
        for (uint i; i < 5; ++i) {
            assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getAccountApproveDenyOracleIds(actions[i]).length, 0);
            assertFalse(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isAccountApproveDenyOracleActive(actions[i], ruleIds[i]));
        }
    }

    /* AccountApproveDenyOracleFlexible */
    function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexibleAtomicFullSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](25);
        ActionTypes[] memory actions = new ActionTypes[](25);
        // Set up rule
        uint256 actionIndex;
        uint256 mainIndex;
        for (uint i; i < 5; i++) {
            for (uint j; j < 5; j++) {
                actions[mainIndex] = ActionTypes(actionIndex);
                ruleIds[mainIndex] = createAccountApproveDenyOracleFlexibleRule(0, 0);
                mainIndex++;
            }
            actionIndex++;
        }

        // Apply the rules to all actions
        setAccountApproveDenyOracleFlexibleRuleFull(address(applicationNFTHandler), actions, ruleIds);
        // Verify that all the rule id's were set correctly and are active(Had to go old school with control break logic)
        mainIndex = 0;
        uint256 internalIndex;
        ActionTypes lastAction;
        for (uint i; i < 5; i++) {
            if (actions[mainIndex] != lastAction) {
                internalIndex = 0;
            }
            for (uint j; j < 5; j++) {
                assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getAccountApproveDenyOracleFlexibleIds(actions[mainIndex])[internalIndex], ruleIds[mainIndex]);
                assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isAccountApproveDenyOracleFlexibleActive(actions[mainIndex], ruleIds[mainIndex]));
                lastAction = actions[mainIndex];
                internalIndex++;
                mainIndex++;
            }
        }
    }

    function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexibleAtomicFullReSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](25);
        ActionTypes[] memory actions = new ActionTypes[](25);
        // Set up rule
        uint256 actionIndex;
        uint256 mainIndex;
        for (uint i; i < 5; i++) {
            for (uint j; j < 5; j++) {
                actions[mainIndex] = ActionTypes(actionIndex);
                ruleIds[mainIndex] = createAccountApproveDenyOracleFlexibleRule(0, 0);
                mainIndex++;
            }
            actionIndex++;
        }

        // Apply the rules to all actions
        setAccountApproveDenyOracleFlexibleRuleFull(address(applicationNFTHandler), actions, ruleIds);
        // Reset with a partial list of rules and insure that the changes are saved correctly
        uint32[] memory ruleIds2 = new uint32[](24);
        ActionTypes[] memory actions2 = new ActionTypes[](24);
        actionIndex = 0;
        mainIndex = 0;
        for (uint i; i < 3; i++) {
            for (uint j; j < 8; j++) {
                actions2[mainIndex] = ActionTypes(actionIndex);
                ruleIds2[mainIndex] = createAccountApproveDenyOracleFlexibleRule(0, 0);
                mainIndex++;
            }
            actionIndex++;
        }
        // Apply the new set of rules
        setAccountApproveDenyOracleFlexibleRuleFull(address(applicationNFTHandler), actions2, ruleIds2);
        // Verify that all the rule id's were set correctly and are active(Had to go old school with control break logic)
        mainIndex = 0;
        uint256 internalIndex;
        ActionTypes lastAction;
        for (uint i; i < 3; i++) {
            if (actions2[mainIndex] != lastAction) {
                internalIndex = 0;
            }
            for (uint j; j < 8; j++) {
                assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getAccountApproveDenyOracleFlexibleIds(actions2[mainIndex])[internalIndex], ruleIds2[mainIndex]);
                assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isAccountApproveDenyOracleFlexibleActive(actions2[mainIndex], ruleIds2[mainIndex]));
                lastAction = actions2[mainIndex];
                internalIndex++;
                mainIndex++;
            }
        }

        // Verify that all the rule id's were cleared for the previous set of rules(Had to go old school with control break logic)
        mainIndex = 0;
        internalIndex = 0;
        lastAction = ActionTypes(0);
        for (uint i; i < 5; i++) {
            if (actions[mainIndex] != lastAction) {
                internalIndex = 0;
            }
            for (uint j; j < 5; j++) {
                uint32[] memory ruleIds3 = ERC20NonTaggedRuleFacet(address(applicationNFTHandler)).getAccountApproveDenyOracleFlexibleIds(actions[mainIndex]);
                // If a value was returned it must not match a previous rule
                if (ruleIds3.length > 0) {
                    assertFalse(ruleIds3[internalIndex] == ruleIds[mainIndex]);
                }
                assertFalse(ERC20NonTaggedRuleFacet(address(applicationNFTHandler)).isAccountApproveDenyOracleFlexibleActive(actions[mainIndex], ruleIds[mainIndex]));
                lastAction = actions[mainIndex];
                internalIndex++;
                mainIndex++;
            }
        }
    }

      function testERC721_ERC721CommonTests_AccountApproveDenyOracleFlexibleRulefull_ZeroLengthActions() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](25);
        ActionTypes[] memory actions = new ActionTypes[](25);

        // Set up rules
        uint256 actionIndex;
        uint256 mainIndex;
        for (uint i; i < 5; i++) {
            for (uint j; j < 5; j++) {
                actions[mainIndex] = ActionTypes(actionIndex);
                ruleIds[mainIndex] = createAccountApproveDenyOracleFlexibleRule(0, 0);
                mainIndex++;
            }
            actionIndex++;
        }

        // Apply the rules to all actions
        setAccountApproveDenyOracleFlexibleRuleFull(address(applicationNFTHandler), actions, ruleIds);
        
        // Verify that all the rule id's were set correctly and are active
        for (uint i; i < 5; ++i) {
            assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getAccountApproveDenyOracleFlexibleIds(actions[i])[i], ruleIds[i]);
            assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isAccountApproveDenyOracleFlexibleActive(actions[i], ruleIds[i]));
        }

        // Create zero length arrays
        uint32[] memory ruleIdsZero = new uint32[](0);
        ActionTypes[] memory actionsZero = new ActionTypes[](0);

        // Apply zero length arrays
        setAccountApproveDenyOracleFlexibleRuleFull(address(applicationNFTHandler), actionsZero, ruleIdsZero);
        
        // Verify that all the rule ids were cleared and not active
        for (uint i; i < 5; ++i) {
            assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getAccountApproveDenyOracleFlexibleIds(actions[i]).length, 0);
            assertFalse(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isAccountApproveDenyOracleFlexibleActive(actions[i], ruleIds[i]));
        }
    }

    /* TokenMinimumTransaction */
    function testERC721_ERC721CommonTests_TokenMinimumTransactionAtomicFullSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](5);
        // Set up rule
        for (uint i; i < ruleIds.length; i++) ruleIds[i] = createTokenMinimumTransactionRule(i + 1);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BUY, ActionTypes.MINT, ActionTypes.BURN);
        // Apply the rules to all actions
        setTokenMinimumTransactionRuleFull(address(applicationNFTHandler), actions, ruleIds);
        // Verify that all the rule id's were set correctly
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinTxSizeId(ActionTypes.P2P_TRANSFER), ruleIds[0]);
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinTxSizeId(ActionTypes.SELL), ruleIds[1]);
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinTxSizeId(ActionTypes.BUY), ruleIds[2]);
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinTxSizeId(ActionTypes.MINT), ruleIds[3]);
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinTxSizeId(ActionTypes.BURN), ruleIds[4]);
        // Verify that all the rules were activated
        for (uint i; i < 5; i++) assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMinTxSizeActive(ActionTypes(i)));
    }

    function testERC721_ERC721CommonTests_TokenMinimumTransactionAtomicFullReSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](5);
        // Set up rule
        for (uint i; i < ruleIds.length; i++) ruleIds[i] = createTokenMinimumTransactionRule(i + 1);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BUY, ActionTypes.MINT, ActionTypes.BURN);
        // Apply the rules to all actions
        setTokenMinimumTransactionRuleFull(address(applicationNFTHandler), actions, ruleIds);
        // Reset with a partial list of rules and insure that the changes are saved correctly
        ruleIds = new uint32[](2);
        ruleIds[0] = createTokenMinimumTransactionRule(6);
        ruleIds[1] = createTokenMinimumTransactionRule(7);
        actions = createActionTypeArray(ActionTypes.SELL, ActionTypes.BUY);
        // Apply the new set of rules
        setTokenMinimumTransactionRuleFull(address(applicationNFTHandler), actions, ruleIds);
        // Verify that all the rule id's were set correctly
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinTxSizeId(ActionTypes.SELL), ruleIds[0]);
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinTxSizeId(ActionTypes.BUY), ruleIds[1]);
        // Verify that the old ones were cleared
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinTxSizeId(ActionTypes.P2P_TRANSFER), 0);
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinTxSizeId(ActionTypes.MINT), 0);
        assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinTxSizeId(ActionTypes.BURN), 0);
        // Verify that the new rules were activated
        assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMinTxSizeActive(ActionTypes.SELL));
        assertTrue(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMinTxSizeActive(ActionTypes.BUY));
        // Verify that the old rules are not activated
        assertFalse(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMinTxSizeActive(ActionTypes.P2P_TRANSFER));
        assertFalse(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMinTxSizeActive(ActionTypes.MINT));
        assertFalse(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).isTokenMinTxSizeActive(ActionTypes.BURN));
    }

    /* MinMaxTokenBalance */
    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalanceAtomicFullSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](5);
        // Set up rule
        bytes32[5] memory tags = [bytes32("Oscar"), bytes32("RJ"), bytes32("Tayler"), bytes32("Michael"), bytes32("Shane")];
        for (uint i; i < ruleIds.length; i++) createAccountMinMaxTokenBalanceRule(createBytes32Array(tags[i]), createUint256Array(i + 1), createUint256Array((i + 1) * 1000));

        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BUY, ActionTypes.MINT, ActionTypes.BURN);
        // Apply the rules to all actions
        setAccountMinMaxTokenBalanceRuleFull(address(applicationCoinHandler), actions, ruleIds);
        // Verify that all the rule id's were set correctly
        assertEq(ERC721TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.P2P_TRANSFER), ruleIds[0]);
        assertEq(ERC721TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.SELL), ruleIds[1]);
        assertEq(ERC721TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.BUY), ruleIds[2]);
        assertEq(ERC721TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.MINT), ruleIds[3]);
        assertEq(ERC721TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.BURN), ruleIds[4]);
        // Verify that all the rules were activated
        for (uint i; i < 5; i++) assertTrue(ERC721TaggedRuleFacet(address(applicationCoinHandler)).isAccountMinMaxTokenBalanceActive(ActionTypes(i)));
    }

    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalanceAtomicFullReSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](5);
        // Set up rule
        bytes32[5] memory tags = [bytes32("Oscar"), bytes32("RJ"), bytes32("Tayler"), bytes32("Michael"), bytes32("Shane")];
        for (uint i; i < ruleIds.length; i++) createAccountMinMaxTokenBalanceRule(createBytes32Array(tags[i]), createUint256Array(i + 1), createUint256Array((i + 1) * 1000));
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BUY, ActionTypes.MINT, ActionTypes.BURN);
        // Apply the rules to all actions
        setAccountMinMaxTokenBalanceRuleFull(address(applicationCoinHandler), actions, ruleIds);

        // Reset with a partial list of rules and insure that the changes are saved correctly
        ruleIds = new uint32[](2);
        ruleIds[0] = createAccountMinMaxTokenBalanceRule(createBytes32Array("Oscar"), createUint256Array(1), createUint256Array(10000));
        ruleIds[1] = createAccountMinMaxTokenBalanceRule(createBytes32Array("RJ"), createUint256Array(1), createUint256Array(20000));
        actions = createActionTypeArray(ActionTypes.SELL, ActionTypes.BUY);
        // Apply the new set of rules
        setAccountMinMaxTokenBalanceRuleFull(address(applicationCoinHandler), actions, ruleIds);
        // Verify that all the rule id's were set correctly
        assertEq(ERC721TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.SELL), ruleIds[0]);
        assertEq(ERC721TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.BUY), ruleIds[1]);
        // Verify that the old ones were cleared
        assertEq(ERC721TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.P2P_TRANSFER), 0);
        assertEq(ERC721TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.MINT), 0);
        assertEq(ERC721TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.BURN), 0);
        // Verify that the new rules were activated
        assertTrue(ERC721TaggedRuleFacet(address(applicationCoinHandler)).isAccountMinMaxTokenBalanceActive(ActionTypes.SELL));
        assertTrue(ERC721TaggedRuleFacet(address(applicationCoinHandler)).isAccountMinMaxTokenBalanceActive(ActionTypes.BUY));
        // Verify that the old rules are not activated
        assertFalse(ERC721TaggedRuleFacet(address(applicationCoinHandler)).isAccountMinMaxTokenBalanceActive(ActionTypes.P2P_TRANSFER));
        assertFalse(ERC721TaggedRuleFacet(address(applicationCoinHandler)).isAccountMinMaxTokenBalanceActive(ActionTypes.MINT));
        assertFalse(ERC721TaggedRuleFacet(address(applicationCoinHandler)).isAccountMinMaxTokenBalanceActive(ActionTypes.BURN));
    }

    function testERC721_ERC721CommonTests_AccountMinMaxTokenBalanceAtomicFull_ZeroLengthActions() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](5);
        // Set up rule
        bytes32[5] memory tags = [bytes32("Oscar"), bytes32("RJ"), bytes32("Tayler"), bytes32("Michael"), bytes32("Shane")];
        for (uint i; i < ruleIds.length; i++) createAccountMinMaxTokenBalanceRule(createBytes32Array(tags[i]), createUint256Array(i + 1), createUint256Array((i + 1) * 1000));
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BUY, ActionTypes.MINT, ActionTypes.BURN);

        // Apply the rules to all actions
        setAccountMinMaxTokenBalanceRuleFull(address(applicationCoinHandler), actions, ruleIds);

        // Verify that all the rule id's were set correctly
        for (uint i; i < 5; i++) {
            assertEq(ERC721TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(actions[i]), ruleIds[i]);
            assertTrue(ERC721TaggedRuleFacet(address(applicationCoinHandler)).isAccountMinMaxTokenBalanceActive(actions[i]));
        }

        // Create zero length arrays
        uint32[] memory ruleIdsZero = new uint32[](0);
        ActionTypes[] memory actionsZero = new ActionTypes[](0);

        // Apply the rules to all actions
        setAccountMinMaxTokenBalanceRuleFull(address(applicationCoinHandler), actionsZero, ruleIdsZero);

        // Verify that all the rule ids were cleared and not active
        for (uint i; i < 5; i++) {
            assertEq(ERC721TaggedRuleFacet(address(applicationNFTHandler)).getAccountMinMaxTokenBalanceId(actions[i]), 0);
            assertFalse(ERC721TaggedRuleFacet(address(applicationNFTHandler)).isAccountMinMaxTokenBalanceActive(actions[i]));
        }
    }

    function testERC721_ERC721CommonTests_getAccTotalValuation_TestGasLimitBreakageNFTsValueLimitLow() public endWithStopPrank ifDeploymentTestsEnabled {
        // fill an account with NFTs and try to break the gas limit
        switchToAppAdministrator();
        _safeMintERC721(20000);

        erc721Pricer.setNFTCollectionPrice(address(testCaseNFT), 1 * ATTO);

        ERC721HandlerMainFacet(address(applicationNFTHandler)).setNFTValuationLimit(20);
        uint gasBegin = gasleft();
        applicationHandler.getAccTotalValuation(appAdministrator, 20);
        uint gasEnd = gasleft();
        assertLt(gasBegin - gasEnd, 50000);
    }

    function testERC721_ERC721CommonTests_getAccTotalValuation_TestGasLimitBreakageNFTsValueLimitHigh() public endWithStopPrank ifDeploymentTestsEnabled {
        // fill an account with NFTs and try to break the gas limit
        switchToAppAdministrator();
        _safeMintERC721(20000);

        erc721Pricer.setNFTCollectionPrice(address(testCaseNFT), 1 * ATTO);

        switchToAppAdministrator();
        ERC721HandlerMainFacet(address(applicationNFTHandler)).setNFTValuationLimit(20000);
        uint gasBegin = gasleft();
        applicationHandler.getAccTotalValuation(appAdministrator, 20000);
        uint gasEnd = gasleft();

        assertLt(gasBegin - gasEnd, 50000);
    }

    function testERC721_ERC721CommonTests_getAccTotalValuation_TestGasLimitBreakageMultipleNFTsValueLimitHigh() public endWithStopPrank ifDeploymentTestsEnabled {
        // fill an account with NFTs and try to break the gas limit
        switchToAppAdministrator();

        // deploy its always sunny nfts
        (UtilApplicationERC721 FrankCoin, ) = deployAndSetupERC721("Frankcoin", "FRANK");
        (UtilApplicationERC721 DennisCoin, ) = deployAndSetupERC721("Denniscoin", "DENNIS");
        (UtilApplicationERC721 DeeCoin, ) = deployAndSetupERC721("Deecoin", "DEE");
        (UtilApplicationERC721 MacCoin, ) = deployAndSetupERC721("Maccoin", "MAC");
        (UtilApplicationERC721 CharlieCoin, ) = deployAndSetupERC721("Charliecoin", "CHARLIE");
        (UtilApplicationERC721 WaitressCoin, ) = deployAndSetupERC721("Waitresscoin", "WAITRESS");
        (UtilApplicationERC721 CricketCoin, ) = deployAndSetupERC721("Cricketcoin", "CRICKET");

        // mint a crapload of nfts
        switchToAppAdministrator();
        _safeMintERC721(10000);
        _safeMintERC721TokenDefined(address(FrankCoin), 1000);
        _safeMintERC721TokenDefined(address(DennisCoin), 500);
        _safeMintERC721TokenDefined(address(DeeCoin), 300);
        _safeMintERC721TokenDefined(address(MacCoin), 200);
        _safeMintERC721TokenDefined(address(CharlieCoin), 140);
        _safeMintERC721TokenDefined(address(WaitressCoin), 140);
        _safeMintERC721TokenDefined(address(CricketCoin), 140);

        // set pricing
        switchToAppAdministrator();
        erc721Pricer.setNFTCollectionPrice(address(testCaseNFT), 1 * ATTO);
        erc721Pricer.setNFTCollectionPrice(address(FrankCoin), 10000 * ATTO);
        erc721Pricer.setNFTCollectionPrice(address(DennisCoin), 69 * ATTO);
        erc721Pricer.setNFTCollectionPrice(address(DeeCoin), 2 * ATTO);
        erc721Pricer.setNFTCollectionPrice(address(MacCoin), 7 * ATTO);
        erc721Pricer.setNFTCollectionPrice(address(CharlieCoin), 42 * ATTO);
        erc721Pricer.setNFTCollectionPrice(address(CricketCoin), 666 * ATTO);
        erc721Pricer.setNFTCollectionPrice(address(WaitressCoin), 200 * ATTO);

        /// set the nftHandler nftValuationLimit variable
        switchToAppAdministrator();
        ERC721HandlerMainFacet(address(applicationNFTHandler)).setNFTValuationLimit(20000);

        // track the gas
        uint gasBegin = gasleft();
        uint totalValuation = applicationHandler.getAccTotalValuation(appAdministrator, 10000);
        uint gasEnd = gasleft();

        assertLt(gasBegin - gasEnd, 30000000); // assert that this is less than the block gas limit on polygon pos
        assertEq(totalValuation, 10173620000000000000000000); // get a free valuation assertion while we're here
    }

    function testERC721_ERC721CommonTests_getAccTotalValuation_TestGasLimitBreakageMultipleNFTsValueLimitLow() public endWithStopPrank ifDeploymentTestsEnabled {
        // fill an account with NFTs and try to break the gas limit
        switchToAppAdministrator();

        // deploy its always sunny nfts
        (UtilApplicationERC721 FrankCoin, ) = deployAndSetupERC721("Frankcoin", "FRANK");
        (UtilApplicationERC721 DennisCoin, ) = deployAndSetupERC721("Denniscoin", "DENNIS");
        (UtilApplicationERC721 DeeCoin, ) = deployAndSetupERC721("Deecoin", "DEE");
        (UtilApplicationERC721 MacCoin, ) = deployAndSetupERC721("Maccoin", "MAC");
        (UtilApplicationERC721 CharlieCoin, ) = deployAndSetupERC721("Charliecoin", "CHARLIE");
        (UtilApplicationERC721 WaitressCoin, ) = deployAndSetupERC721("Waitresscoin", "WAITRESS");
        (UtilApplicationERC721 CricketCoin, ) = deployAndSetupERC721("Cricketcoin", "CRICKET");

        // mint a crapload of nfts
        switchToAppAdministrator();
        _safeMintERC721(10000);
        _safeMintERC721TokenDefined(address(FrankCoin), 1000);
        _safeMintERC721TokenDefined(address(DennisCoin), 500);
        _safeMintERC721TokenDefined(address(DeeCoin), 300);
        _safeMintERC721TokenDefined(address(MacCoin), 200);
        _safeMintERC721TokenDefined(address(CharlieCoin), 140);
        _safeMintERC721TokenDefined(address(WaitressCoin), 140);
        _safeMintERC721TokenDefined(address(CricketCoin), 140);

        // set pricing
        switchToAppAdministrator();
        erc721Pricer.setNFTCollectionPrice(address(testCaseNFT), 1 * ATTO);
        erc721Pricer.setNFTCollectionPrice(address(FrankCoin), 10000 * ATTO);
        erc721Pricer.setNFTCollectionPrice(address(DennisCoin), 69 * ATTO);
        erc721Pricer.setNFTCollectionPrice(address(DeeCoin), 2 * ATTO);
        erc721Pricer.setNFTCollectionPrice(address(MacCoin), 7 * ATTO);
        erc721Pricer.setNFTCollectionPrice(address(CharlieCoin), 42 * ATTO);
        erc721Pricer.setNFTCollectionPrice(address(CricketCoin), 666 * ATTO);
        erc721Pricer.setNFTCollectionPrice(address(WaitressCoin), 200 * ATTO);

        /// set the nftHandler nftValuationLimit variable
        switchToAppAdministrator();
        ERC721HandlerMainFacet(address(applicationNFTHandler)).setNFTValuationLimit(10);

        // track the gas
        uint gasBegin = gasleft();
        uint totalValuation = applicationHandler.getAccTotalValuation(appAdministrator, 10);
        uint gasEnd = gasleft();

        //console2.log("Gas: ", gasBegin - gasEnd);

        console.log(gasBegin - gasEnd); // Log this value to not changes over time. As a baseline the expectation is to be right around 70k.
        assertEq(totalValuation, 10173620000000000000000000); // get a free valuation assertion while we're here
    }

    function testERC721_ERC721CommonTests_Toggle_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        // Set up the Max Value Out rule and make sure it reverts
        _setUpAccountMaxValueOutByAccessLevelRule(ActionTypes.P2P_TRANSFER);
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 0, 1 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(testCaseNFT), 1, 1 * ATTO);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user, 0);
        applicationAppManager.addAccessLevel(user2, 2);
        switchToUser();
        UtilApplicationERC721(address(testCaseNFT)).safeTransferFrom(user, user2, 1);
        vm.expectRevert(abi.encodeWithSignature("OverMaxValueOutByAccessLevel()"));
        UtilApplicationERC721(address(testCaseNFT)).safeTransferFrom(user, user2, 0);
        // Toggle protocol and make sure it works
        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).connectHandlerToToken(address(0));
        switchToUser();
        UtilApplicationERC721(address(testCaseNFT)).safeTransferFrom(user, user2, 0);
    }

    /// INTERNAL HELPER FUNCTIONS
    function _approveTokens(DummyNFTAMM _amm, uint256 amountERC20, bool _isApprovalERC721) internal {
        applicationCoin.approve(address(_amm), amountERC20);
        testCaseNFT.setApprovalForAll(address(_amm), _isApprovalERC721);
    }

    function _safeMintERC721(uint256 amount) internal {
        for (uint256 i; i < amount; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(appAdministrator);
        }
    }

    function _safeMintERC721TokenDefined(address token, uint256 amount) internal endWithStopPrank {
        switchToAppAdministrator();
        for (uint256 i = 0; i < amount; i++) {
            UtilApplicationERC721(address(token)).safeMint(appAdministrator);
        }
    }

    function _addLiquidityInBatchERC721(DummyNFTAMM _amm, uint256 amount) private {
        for (uint256 i; i < amount; i++) {
            testCaseNFT.safeTransferFrom(appAdministrator, address(_amm), i);
        }
    }

    function _testBuyNFT(uint256 _tokenId, DummyNFTAMM _amm) internal {
        _amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, _tokenId, true);
    }

    function _testSellNFT(uint256 _tokenId, DummyNFTAMM _amm) internal {
        _amm.dummyTrade(address(applicationCoin), address(testCaseNFT), 1, _tokenId, false);
    }

    function _fundThreeAccounts() internal endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.transfer(user, 1000 * ATTO);
        applicationCoin.transfer(user2, 1000 * ATTO);
        applicationCoin.transfer(user1, 1000 * ATTO);
        for (uint i = erc721Liq / 2; i < erc721Liq / 2 + 50; i++) {
            testCaseNFT.safeTransferFrom(appAdministrator, user, i);
        }
        for (uint i = erc721Liq / 2 + 100; i < erc721Liq / 2 + 150; i++) {
            testCaseNFT.safeTransferFrom(appAdministrator, user1, i);
        }
        for (uint i = erc721Liq / 2 + 200; i < erc721Liq / 2 + 250; i++) {
            testCaseNFT.safeTransferFrom(appAdministrator, user2, i);
        }
    }

    function _accountMinMaxTokenBalanceRuleSetup(bool tag) public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// mint 6 NFTs to appAdministrator for transfer
        for (uint i; i < 7; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(appAdministrator);
        }

        /// set up a non admin user with tokens
        switchToAppAdministrator();
        ///transfer tokenId 1 and 2 to rich_user
        testCaseNFT.transferFrom(appAdministrator, rich_user, 0);
        testCaseNFT.transferFrom(appAdministrator, rich_user, 1);
        assertEq(testCaseNFT.balanceOf(rich_user), 2);

        ///transfer tokenId 3 and 4 to user1
        testCaseNFT.transferFrom(appAdministrator, user1, 3);
        testCaseNFT.transferFrom(appAdministrator, user1, 4);
        assertEq(testCaseNFT.balanceOf(user1), 2);

        switchToAppAdministrator();
        if (tag) {
            ///Add Tag to account
            applicationAppManager.addTag(user1, "Oscar"); ///add tag
            assertTrue(applicationAppManager.hasTag(user1, "Oscar"));
            applicationAppManager.addTag(user2, "Oscar"); ///add tag
            assertTrue(applicationAppManager.hasTag(user2, "Oscar"));
            applicationAppManager.addTag(user3, "Oscar"); ///add tag
            assertTrue(applicationAppManager.hasTag(user3, "Oscar"));
            applicationAppManager.addTag(rich_user, "Oscar"); ///add tag
            assertTrue(applicationAppManager.hasTag(rich_user, "Oscar"));
            switchToRuleAdmin();
            ///update ruleId in application NFT handler
            uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array("Oscar"), createUint256Array(1), createUint256Array(6));
            setAccountMinMaxTokenBalanceRule(address(applicationNFTHandler), ruleId);
        } else {
            switchToRuleAdmin();
            uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array(""), createUint256Array(1), createUint256Array(3));
            setAccountMinMaxTokenBalanceRule(address(applicationNFTHandler), ruleId);
        }

        vm.startPrank(user1, user1);
        testCaseNFT.transferFrom(user1, user2, 3);
        assertEq(testCaseNFT.balanceOf(user2), 1);
        assertEq(testCaseNFT.balanceOf(user1), 1);
    }

    function _accountApproveDenyOracleSetup(bool deny) public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// set up a non admin user an nft
        for (uint i; i < 5; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
        }
        assertEq(testCaseNFT.balanceOf(user1), 5);
        if (deny) {
            // add the rule.
            uint32 ruleId = createAccountApproveDenyOracleRule(0);
            setAccountApproveDenyOracleRule(address(applicationNFTHandler), ruleId);
            // add a blocked address
            switchToAppAdministrator();
            badBoys.push(address(69));
            oracleDenied.addToDeniedList(badBoys);
        } else {
            uint32 ruleId = createAccountApproveDenyOracleRule(1);
            setAccountApproveDenyOracleRule(address(applicationNFTHandler), ruleId);
            // add an allowed address
            switchToAppAdministrator();
            goodBoys.push(address(user1));
            goodBoys.push(address(user2));
            goodBoys.push(address(user));
            oracleApproved.addToApprovedList(goodBoys);
        }
        vm.startPrank(user1, user1);
        testCaseNFT.transferFrom(user1, user2, 0);
        assertEq(testCaseNFT.balanceOf(user2), 1);
    }

    function _accountApproveDenyOracleSetupNoMints(bool deny) public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        if (deny) {
            // add the rule.
            uint32 ruleId = createAccountApproveDenyOracleRule(0);
            setAccountApproveDenyOracleRule(address(applicationNFTHandler), ruleId);
            // add a blocked address
            switchToAppAdministrator();
            badBoys.push(rich_user);
            oracleDenied.addToDeniedList(badBoys);
        } else {
            uint32 ruleId = createAccountApproveDenyOracleRule(1);
            setAccountApproveDenyOracleRule(address(applicationNFTHandler), ruleId);
            // add an allowed address
            switchToAppAdministrator();
            goodBoys.push(address(user2));
            goodBoys.push(address(user));
            oracleApproved.addToApprovedList(goodBoys);
        }
    }

    function _accountApproveDenyOracleFlexibleSetup(bool deny, uint8 addressToggle) public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// set up a non admin user an nft
        for (uint i; i < 5; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
        }
        assertEq(testCaseNFT.balanceOf(user1), 5);
        if (deny) {
            // add the rule.
            uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(0, addressToggle);
            setAccountApproveDenyOracleFlexibleRule(address(applicationNFTHandler), ruleId);
            // add a blocked address
            switchToAppAdministrator();
            badBoys.push(address(69));
            oracleDenied.addToDeniedList(badBoys);
        } else {
            uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(1, addressToggle);
            setAccountApproveDenyOracleFlexibleRule(address(applicationNFTHandler), ruleId);
            // add an allowed address
            switchToAppAdministrator();
            goodBoys.push(address(user1));
            goodBoys.push(address(user2));
            goodBoys.push(address(user));
            oracleApproved.addToApprovedList(goodBoys);
        }
        vm.startPrank(user1, user1);
        testCaseNFT.transferFrom(user1, user2, 0);
        assertEq(testCaseNFT.balanceOf(user2), 1);
    }

    function _accountApproveDenyOracleFlexibleSetupNoMints(bool deny, uint8 addressToggle) public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        if (deny) {
            // add the rule.
            uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(0, addressToggle);
            setAccountApproveDenyOracleFlexibleRule(address(applicationNFTHandler), ruleId);
            // add a blocked address
            switchToAppAdministrator();
            badBoys.push(rich_user);
            oracleDenied.addToDeniedList(badBoys);
        } else {
            uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(1, addressToggle);
            setAccountApproveDenyOracleFlexibleRule(address(applicationNFTHandler), ruleId);
            // add an allowed address
            switchToAppAdministrator();
            goodBoys.push(address(user2));
            goodBoys.push(address(user));
            oracleApproved.addToApprovedList(goodBoys);
        }
    }

    function _tokenMaxDailyTradesSetup(bool tag) public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// set up a non admin user an nft
        for (uint i; i < 5; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
        }

        // add the rule.
        switchToRuleAdmin();
        if (tag) {
            uint32 ruleId = createTokenMaxDailyTradesRule("BoredGrape", "DiscoPunk", 1, 5);
            setTokenMaxDailyTradesRule(address(applicationNFTHandler), ruleId);
        } else {
            uint32 ruleId = createTokenMaxDailyTradesRule("", 1);
            setTokenMaxDailyTradesRule(address(applicationNFTHandler), ruleId);
        }
        // tag the NFT collection
        switchToAppAdministrator();
        applicationAppManager.addTag(address(testCaseNFT), "BoredGrape"); ///add tag

        // perform 1 transfer
        vm.startPrank(user1, user1);
        testCaseNFT.transferFrom(user1, user2, 1);
    }

    function _tokenMaxDailyTradesSetupNoBurns() public endWithStopPrank ifDeploymentTestsEnabled {
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createTokenMaxDailyTradesRule("", 1);
        setTokenMaxDailyTradesRule(address(applicationNFTHandler), ruleId);
        // tag the NFT collection
        switchToAppAdministrator();
        applicationAppManager.addTag(address(testCaseNFT), "BoredGrape"); ///add tag
    }

    function _tokenMaxDailyTradesSetupMultipleRuleIds() public endWithStopPrank ifDeploymentTestsEnabled {
        // add the rule.
        switchToRuleAdmin();
        // setTokenMaxDailyTradesRuleSingleAction(address(applicationNFTHandler),createActionTypeArray(ActionTypes.BUY), createTokenMaxDailyTradesRule("", 1));
        setTokenMaxDailyTradesRuleSingleAction(address(applicationNFTHandler), createActionTypeArray(ActionTypes.SELL), createTokenMaxDailyTradesRule("", 3));
        setTokenMaxDailyTradesRuleSingleAction(address(applicationNFTHandler), createActionTypeArray(ActionTypes.P2P_TRANSFER), createTokenMaxDailyTradesRule("", 10));

        // tag the NFT collection
        switchToAppAdministrator();
        applicationAppManager.addTag(address(testCaseNFT), "BoredGrape"); ///add tag
    }

    function _accountMaxTransactionValueByRiskScoreSetup(bool period) public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        uint8[] memory riskScores = createUint8Array(0, 10, 40, 80);
        ///Mint NFT's (user1,2,3)
        for (uint i; i < 5; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
        }
        assertEq(testCaseNFT.balanceOf(user1), 5);

        for (uint i; i < 3; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(user2);
        }
        assertEq(testCaseNFT.balanceOf(user2), 3);

        switchToRuleAdmin();
        if (period) {
            ///Set Rule in NFTHandler
            uint8 _period = 24;
            uint32 ruleId = createAccountMaxTxValueByRiskRule(riskScores, createUint48Array(17, 15, 12, 11), _period);
            setAccountMaxTxValueByRiskRule(ruleId);
        } else {
            ///Set Rule in NFTHandler
            uint32 ruleId = createAccountMaxTxValueByRiskRule(riskScores, createUint48Array(17, 15, 12, 11));
            setAccountMaxTxValueByRiskRule(ruleId);
        }
        ///Set Risk Scores for users
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, riskScores[0]);
        applicationAppManager.addRiskScore(user2, riskScores[1]);
        applicationAppManager.addRiskScore(user3, riskScores[2]);

        ///Set Pricing for NFTs 0-7
        switchToAppAdministrator();
        for (uint i; i < 8; i++) {
            erc721Pricer.setSingleNFTPrice(address(testCaseNFT), i, (10 + i) * ATTO);
        }
    }

    function _accountMaxTransactionValueByRiskScoreSetupNoMints() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        uint8[] memory riskScores = createUint8Array(0, 10, 40, 80);
        switchToRuleAdmin();
        ///Set Rule in NFTHandler
        uint32 ruleId = createAccountMaxTxValueByRiskRule(riskScores, createUint48Array(17, 15, 12, 11));
        setAccountMaxTxValueByRiskRule(ruleId);
        ///Set Risk Scores for users
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, riskScores[0]);
        applicationAppManager.addRiskScore(user2, riskScores[1]);
        applicationAppManager.addRiskScore(user3, riskScores[2]);
        ///Set Pricing for NFTs 0-25
        switchToAppAdministrator();
        for (uint i; i < 25; i++) {
            erc721Pricer.setSingleNFTPrice(address(testCaseNFT), i, (10 + i) * ATTO);
        }
    }

    function _accountDenyForNoAccessLevelInNFTSetup() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// set up a non admin user an nft
        for (uint i; i < 5; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
        }

        assertEq(testCaseNFT.balanceOf(user1), 5);

        // apply the rule to the ApplicationERC721Handler
        switchToRuleAdmin();
        createAccountDenyForNoAccessLevelRule();
    }

    function _accountMinMaxTokenBalanceSetup(bool tag) public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// Mint NFTs for users 1, 2, 3
        for (uint i; i < 3; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
        }

        for (uint i; i < 3; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(user2);
        }

        for (uint i; i < 3; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(user3);
        }

        /// Create Rule Params and create rule
        // Set up the rule conditions
        vm.warp(Blocktime);
        bytes32[] memory accs = createBytes32Array("MIN1", "MIN2", "MIN3");
        uint256[] memory minAmounts = createUint256Array(1, 2, 3); /// Represent min number of tokens held by user for Collection address
        uint256[] memory maxAmounts = createUint256Array(
            999999000000000000000000000000000000000000000000000000000000000000000000000,
            999990000000000000000000000000000000000000000000000000000000000000000000000,
            999990000000000000000000000000000000000000000000000000000000000000000000000
        );
        // 720 = one month 4380 = six months 17520 = two years
        uint16[] memory periods = createUint16Array(720, 4380, 17520);
        /// Add Tags to users
        switchToAppAdministrator();
        applicationAppManager.addTag(user1, "MIN1"); ///add tag
        assertTrue(applicationAppManager.hasTag(user1, "MIN1"));
        applicationAppManager.addTag(user2, "MIN2"); ///add tag
        assertTrue(applicationAppManager.hasTag(user2, "MIN2"));
        applicationAppManager.addTag(user3, "MIN3"); ///add tag
        assertTrue(applicationAppManager.hasTag(user3, "MIN3"));
        /// Set rule bool to active
        switchToRuleAdmin();
        if (tag) {
            uint32 ruleId = createAccountMinMaxTokenBalanceRule(accs, minAmounts, maxAmounts, periods);
            setAccountMinMaxTokenBalanceRule(address(applicationNFTHandler), ruleId);
        } else {
            uint32 ruleId = createAccountMinMaxTokenBalanceRule(
                createBytes32Array(""),
                createUint256Array(1),
                createUint256Array(999999000000000000000000000000000000000000000000000000000000000000000000000),
                createUint16Array(720)
            );
            setAccountMinMaxTokenBalanceRule(address(applicationNFTHandler), ruleId);
        }

        /// Transfers passing (above min value limit)
        vm.startPrank(user1, user1);
        testCaseNFT.safeTransferFrom(user1, user2, 0); ///User 1 has min limit of 1
        testCaseNFT.safeTransferFrom(user1, user3, 1);
        assertEq(testCaseNFT.balanceOf(user1), 1);

        vm.startPrank(user2, user2);
        testCaseNFT.safeTransferFrom(user2, user1, 0); ///User 2 has min limit of 2
        testCaseNFT.safeTransferFrom(user2, user3, 3);
        assertEq(testCaseNFT.balanceOf(user2), 2);

        vm.startPrank(user3, user3);
        testCaseNFT.safeTransferFrom(user3, user2, 3); ///User 3 has min limit of 3
        testCaseNFT.safeTransferFrom(user3, user1, 1);
        assertEq(testCaseNFT.balanceOf(user3), 3);
    }

    function _transferVolumeRuleSetup() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        // mint 10 nft's to non admin user
        for (uint i = 0; i < 10; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
        }
        // apply the rule
        uint32 ruleId = createTokenMaxTradingVolumeRule(200, 2, Blocktime, 100);
        setTokenMaxTradingVolumeRule(address(applicationNFTHandler), ruleId);
        vm.startPrank(user1, user1);
        // transfer under the threshold
        testCaseNFT.safeTransferFrom(user1, user2, 0);
    }

    function _transferVolumeRuleWithSupplySet() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        // mint 10 nft's to non admin user
        for (uint i = 0; i < 10; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
        }
        // apply the rule
        uint32 ruleId = createTokenMaxTradingVolumeRule(200, 2, Blocktime, 100);
        setTokenMaxTradingVolumeRule(address(applicationNFTHandler), ruleId);
    }

    function _collectionTokenMaxSupplyVolatilitySetup() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// Mint tokens to specific supply
        for (uint i = 0; i < 10; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(appAdministrator);
        }

        /// set rule id and activate
        switchToRuleAdmin();
        uint32 ruleId = createTokenMaxSupplyVolatilityRule(2000, 24, Blocktime, 0);
        setTokenMaxSupplyVolatilityRule(address(applicationNFTHandler), ruleId);
        /// set blocktime to within rule period
        vm.warp(Blocktime + 13 hours);

        switchToAppAdministrator();
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
        /// mint tokens to the cap
        UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
    }

    function _NFTValuationOrigSetup() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// mint NFTs and set price to $1USD for each token
        for (uint i = 0; i < 10; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(user1);
            erc721Pricer.setSingleNFTPrice(address(testCaseNFT), i, 1 * ATTO);
        }
        uint256 testPrice = erc721Pricer.getNFTPrice(address(testCaseNFT), 1);
        assertEq(testPrice, 1 * ATTO);
        erc721Pricer.setNFTCollectionPrice(address(testCaseNFT), 1 * ATTO);
        /// set the nftHandler nftValuationLimit variable
        switchToRuleAdmin();
        switchToAppAdministrator();
        ERC721HandlerMainFacet(address(applicationNFTHandler)).setNFTValuationLimit(20);
        /// activate rule that calls valuation
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, 1, 10, 50, 100);
        setAccountMaxValueByAccessLevelRule(ruleId);
        /// calc expected valuation based on tokenId's
        /**
         total valuation for user1 should be $10 USD
         10 tokens * 1 USD for each token 
         */

        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user1, 2);
        applicationAppManager.addAccessLevel(user2, 1);

        vm.startPrank(user1, user1);
        testCaseNFT.transferFrom(user1, user2, 1);

        vm.startPrank(user2, user2);
        testCaseNFT.transferFrom(user2, user1, 1);

        /// switch to rule admin to deactive rule for set up
        switchToRuleAdmin();
        applicationHandler.activateAccountMaxValueByAccessLevel(createActionTypeArrayAll(), false);

        switchToAppAdministrator();
        /// create new collection and mint enough tokens to exceed the nftValuationLimit set in handler
        applicationNFTv2 = new UtilApplicationERC721("ToughTurtles", "THTR", address(applicationAppManager), "https://SampleApp.io");
        console.log("applicationNFTv2", address(applicationNFTv2));
        applicationNFTHandler2 = _createERC721HandlerDiamond();
        ERC721HandlerMainFacet(address(applicationNFTHandler2)).initialize(address(ruleProcessor), address(applicationAppManager), address(applicationNFTv2));
        applicationNFTv2.connectHandlerToToken(address(applicationNFTHandler2));
        /// register the token
        applicationAppManager.registerToken("THTR", address(applicationNFTv2));

        for (uint i = 0; i < 40; i++) {
            applicationNFTv2.safeMint(appAdministrator);
            applicationNFTv2.transferFrom(appAdministrator, user1, i);
            erc721Pricer.setSingleNFTPrice(address(applicationNFTv2), i, 1 * ATTO);
        }
        uint256 testPrice2 = erc721Pricer.getNFTPrice(address(applicationNFTv2), 35);
        assertEq(testPrice2, 1 * ATTO);
        /// set the nftHandler nftValuationLimit variable
        switchToAppAdministrator();
        ERC721HandlerMainFacet(address(applicationNFTHandler2)).setNFTValuationLimit(20);
        /// set specific tokens in NFT 2 to higher prices. Expect this value to be ignored by rule check as it is checking collection price.
        erc721Pricer.setSingleNFTPrice(address(applicationNFTv2), 36, 100 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(applicationNFTv2), 37, 50 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(applicationNFTv2), 40, 25 * ATTO);
        erc721Pricer.setNFTCollectionPrice(address(applicationNFTv2), 1 * ATTO);

        ///reactivate rule
        switchToRuleAdmin();
        applicationHandler.activateAccountMaxValueByAccessLevel(createActionTypeArrayAll(), true);
        /// calc expected valuation for user based on tokens * collection price
        /** 
        expected calculated total should be $50 USD since we take total number of tokens owned * collection price 
        10 PuddgyPenguins 
        40 ToughTurtles 
        50 total * collection prices of $1 usd each 
        */
    }

    function _upgradeAppManager721Setup() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        address _newAdmin = address(75);
        /// create a new app manager
        applicationAppManager2 = new ApplicationAppManager(_newAdmin, "Castlevania2", false);
        /// propose a new AppManager
        ProtocolTokenCommon(address(testCaseNFT)).proposeAppManagerAddress(address(applicationAppManager2));
        switchToNewAdmin();
        applicationAppManager2.addAppAdministrator(address(appAdministrator));

        /// confirm the app manager
        switchToAppAdministrator();
        applicationAppManager2.confirmAppManager(address(testCaseNFT));
        /// test to ensure it still works
        UtilApplicationERC721(address(testCaseNFT)).safeMint(appAdministrator);
        switchToAppAdministrator();
        testCaseNFT.transferFrom(appAdministrator, user, 0);
        assertEq(testCaseNFT.balanceOf(appAdministrator), 0);
        assertEq(testCaseNFT.balanceOf(user), 1);
    }

    function setupTradingRuleTests() internal returns (DummyNFTAMM) {
        amm = new DummyNFTAMM();
        _safeMintERC721(erc721Liq);
        _approveTokens(amm, erc20Liq, true);
        _addLiquidityInBatchERC721(amm, erc721Liq / 2); /// half of total supply
        applicationCoin.mint(appAdministrator, 1_000_000 * ATTO);
        applicationCoin.transfer(address(amm), erc20Liq);
        return amm;
    }

    function _tokenMaxBuySellVolumeRuleSetupSellAction() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        amm = setupTradingRuleTests();
        _fundThreeAccounts();
        /// now we setup the sell percentage rule
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.SELL);
        uint32 ruleId = createTokenMaxBuySellVolumeRule(30, 24, 0, Blocktime);
        setTokenMaxBuySellVolumeRule(address(applicationNFTHandler), actionTypes, ruleId);
        vm.warp(Blocktime + 36 hours);
        /// now we test
        switchToUser();
        _approveTokens(amm, 5 * 10 ** 8 * ATTO, true);

        uint16 tokenPercentageSell = 30; /// 0.30%
        /// we test selling the *tokenPercentage* of the NFTs total supply -1 to get to the limit of the rule
        for (uint i = erc721Liq / 2; i < erc721Liq / 2 + (erc721Liq * tokenPercentageSell) / 10000 - 1; i++) {
            _testSellNFT(i, amm);
        }
    }

    function _accountMaxTradeSizeSellSetup(bool tag) public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        amm = setupTradingRuleTests();
        _fundThreeAccounts();
        /// set the rule
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.SELL);
        if (tag) {
            uint32 ruleId = createAccountMaxTradeSizeRule("AccountMaxSellSize", 1, 36); /// tag, maxNFtsPerPeriod, period
            setAccountMaxTradeSizeRule(address(applicationNFTHandler), actionTypes, ruleId);
        } else {
            uint32 ruleId = createAccountMaxTradeSizeRule("", 1, 36); /// tag, maxNFtsPerPeriod, period
            setAccountMaxTradeSizeRule(address(applicationNFTHandler), actionTypes, ruleId);
        }

        /// apply tag to user
        switchToAppAdministrator();
        applicationAppManager.addTag(user, "AccountMaxSellSize");

        /// Swap that passes rule check
        switchToUser();
        testCaseNFT.setApprovalForAll(address(amm), true);
        _testSellNFT(erc721Liq / 2 + 1, amm);
    }

    function _tokenMaxBuySellVolumeTreasuryerRuleSetupSell() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        amm = setupTradingRuleTests();
        _fundThreeAccounts();
        switchToAppAdministrator();
        applicationAppManager.approveAddressToTradingRuleAllowlist(user, true);

        /// SELL PERCENTAGE RULE
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.SELL);
        uint32 ruleId = createTokenMaxBuySellVolumeRule(30, 24, 0, Blocktime);
        setTokenMaxBuySellVolumeRule(address(applicationNFTHandler), actionTypes, ruleId);
        vm.warp(Blocktime + 36 hours);
    }

    function _tokenMaxBuySellVolumeRuleSetupBuyAction() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        amm = setupTradingRuleTests();
        _fundThreeAccounts();
        /// set up rule
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.BUY);
        uint32 ruleId = createTokenMaxBuySellVolumeRule(10, 24, 0, Blocktime);
        setTokenMaxBuySellVolumeRule(address(applicationNFTHandler), actionTypes, ruleId);
        /// we make sure we are in a new period
        vm.warp(Blocktime + 36 hours);

        /// test swap below percentage
        switchToUser();
        _approveTokens(amm, 5 * 10 ** 8 * ATTO, true);

        uint16 tokenPercentage = 10; /// 1%
        /// we test buying the *tokenPercentage* of the NFTs total supply -1 to get to the limit of the rule
        for (uint i; i < (erc721Liq * tokenPercentage) / 10000 - 1; i++) {
            _testBuyNFT(i, amm);
        }
    }

    function _accountMaxTradeSizeBuyRuleSetup() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        amm = setupTradingRuleTests();
        _fundThreeAccounts();
        /// set the rule
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.BUY);
        uint32 ruleId = createAccountMaxTradeSizeRule("MaxBuySize", 1, 36); /// tag, maxNFtsPerPeriod, period
        setAccountMaxTradeSizeRule(address(applicationNFTHandler), actionTypes, ruleId);
        /// apply tag to user
        switchToAppAdministrator();
        applicationAppManager.addTag(user, "MaxBuySize");
        testCaseNFT.setApprovalForAll(address(amm), true);

        /// Swap that passes rule check
        switchToUser();
        _approveTokens(amm, 5 * 10 ** 8 * ATTO, true);
        _testBuyNFT(0, amm);
    }
    function _mintNFTsToAddress(uint256 _amount, address _address, address _nftAddress) internal {
        switchToAppAdministrator();
        for (uint i; i < _amount; i++) {
            UtilApplicationERC721(_nftAddress).safeMint(_address);
        }
    }

    function _setUpNFTAMMForRuleChecks() internal {
        switchToAppAdministrator();
        amm = new DummyNFTAMM();
        for (uint i; i < 10; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(address(amm));
        }
        applicationCoin.mint(appAdministrator, 1_000_000 * ATTO);
        applicationCoin.transfer(address(amm), 1_000_000 * ATTO);
        applicationCoin.mint(user, 1000 * ATTO);
        for (uint i; i < 3; i++) {
            UtilApplicationERC721(address(testCaseNFT)).safeMint(user); // tokenId 10,11,12
        }
    }

    function testERC721_ERC721CommonTests_FacetOwnershipModifiers_ERC721NonTaggedRulesFacet_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        /// create facet and test that onlyOwner modifer prevents calls from non owners
        ERC721NonTaggedRuleFacet erc721NonTaggedTestFacet = new ERC721NonTaggedRuleFacet();
        switchToUser();
        vm.expectRevert("UNAUTHORIZED");
        erc721NonTaggedTestFacet.checkNonTaggedRules(ActionTypes.P2P_TRANSFER, user1, user, user, 10, 0);
        /// test that users cannot call the facets directly through the proxy address
        vm.expectRevert("UNAUTHORIZED");
        ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).checkNonTaggedRules(ActionTypes.P2P_TRANSFER, user1, user, user, 10, 0);
    }

    function testERC721_ERC721CommonTests_FacetOwnershipModifiers_ERC721TaggedRuleFacet_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        /// create facet and test that onlyOwner modifer prevents calls from non owners
        ERC721TaggedRuleFacet erc721TaggedTestFacet = new ERC721TaggedRuleFacet();
        switchToUser();
        vm.expectRevert("UNAUTHORIZED");
        erc721TaggedTestFacet.checkTaggedAndTradingRules(10, 10, user1, user, user, 10, ActionTypes.P2P_TRANSFER);
        /// test that users cannot call the facets directly through the proxy address
        vm.expectRevert("UNAUTHORIZED");
        ERC721TaggedRuleFacet(address(applicationNFTHandler)).checkTaggedAndTradingRules(10, 10, user1, user, user, 10, ActionTypes.P2P_TRANSFER);
    }

    function testERC721_ERC721CommonTests_FacetOwnershipModifiers_TradingRulesFacet_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        /// create facet and test that onlyOwner modifer prevents calls from non owners
        TradingRuleFacet tradeRuleTestFacet = new TradingRuleFacet();
        switchToUser();
        vm.expectRevert("UNAUTHORIZED");
        tradeRuleTestFacet.checkTradingRules(user1, user, user, createBytes32Array("Oscar"), createBytes32Array("Shane"), 10, ActionTypes.P2P_TRANSFER);
        /// test that users cannot call the facets directly through the proxy address
        vm.expectRevert("UNAUTHORIZED");
        TradingRuleFacet(address(applicationNFTHandler)).checkTradingRules(user1, user, user, createBytes32Array("Tayler"), createBytes32Array("Michael"), 10, ActionTypes.P2P_TRANSFER);
    }
}
