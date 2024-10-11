// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/util/TestCommonFoundry.sol";
import "../../TestTokenCommon.sol";
import "test/client/token/ERC20/util/ERC20Util.sol";
import "src/client/token/handler/ruleContracts/HandlerAccountMinMaxTokenBalance.sol";

abstract contract ERC20CommonTests is TestCommonFoundry, DummyAMM, ERC20Util {
    IERC20 testCaseToken;

    function testERC20_ERC20CommonTests_ERC20AndHandlerVersions() public view ifDeploymentTestsEnabled {
        string memory version = HandlerVersionFacet(address(applicationCoinHandler)).version();
        assertEq(version, "2.1.0");
    }

    function testERC20_ERC20CommonTests_ERC20Handler_RuleProcessorGetter() public view ifDeploymentTestsEnabled {
        address ruleProcessorAddress = ERC20HandlerMainFacet(address(applicationCoinHandler)).getRuleProcessorAddress();
        assertEq(address(ruleProcessor), ruleProcessorAddress);
    }

    function testERC20_ERC20CommonTests_ERC20Handler_AssetAddressGetter() public view ifDeploymentTestsEnabled {
        address assetAddress = ERC20HandlerMainFacet(address(applicationCoinHandler)).getAssetAddress();
        assertEq(address(testCaseToken), assetAddress);
    }

    function testERC20_ERC20CommonTests_ERC20Handler_AppManagerAddressGetter() public view ifDeploymentTestsEnabled {
        address appManagerAddress = ERC20HandlerMainFacet(address(applicationCoinHandler)).getAppManagerAddress();
        assertEq(address(applicationAppManager), appManagerAddress);
    }

    function testERC20_ERC20CommonTests_DeregisterTokenEmission_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        vm.expectEmit(true, true, false, false);
        emit AD1467_RemoveFromRegistry("FRANK", address(testCaseToken));
        applicationAppManager.deregisterToken("FRANK");
    }

    function testERC20_ERC20CommonTests_DeregisterTokenEmission_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        vm.expectRevert(0x7de8c17d);
        // Using a token name that is not already registered.
        applicationAppManager.deregisterToken("FRANKYBOY");
    }

    function testERC20_ERC20CommonTests_UpdateTokenEmission_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        vm.expectEmit(true, true, false, false);
        emit AD1467_TokenNameUpdated("FRANK", address(testCaseToken));
        applicationAppManager.registerToken("FRANK", address(testCaseToken));
    }

    function testERC20_ERC20CommonTests_UpdateTokenEmission_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        vm.expectRevert(0xd92e233d);
        // Attempting to register the zero address
        applicationAppManager.registerToken("FRANK", address(0));
    }

    function testERC20_ERC20CommonTests_ProposeAndConfirmAppManager_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        vm.expectEmit(true, false, false, false);
        emit AD1467_AppManagerAddressProposed(address(applicationAppManager));
        HandlerBase(address(applicationCoinHandler)).proposeAppManagerAddress(address(applicationAppManager));

        vm.expectEmit(true, false, false, false);
        emit AD1467_AppManagerAddressSet(address(applicationAppManager));
        applicationAppManager.confirmAppManager(address(applicationCoinHandler));
    }

    function testERC20_ERC20CommonTests_ProposeAndConfirmAppManager_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        if (vm.envAddress("DEPLOYMENT_OWNER") != address(0x0)) {
            // Example ERC721 does not connect to the appManager through the token so this test is not relevant 
            vm.skip(true); 
        } else { 
            switchToAppAdministrator();
            vm.expectEmit(true, false, false, false);
            emit AD1467_AppManagerAddressProposed(address(applicationAppManager));
            HandlerBase(address(applicationCoinHandler)).proposeAppManagerAddress(address(applicationAppManager));

            vm.expectRevert(0x821e0eeb);
            // confirming a different address than was proposed.
            ApplicationAppManager(address(applicationAppManager)).confirmAppManager(address(testCaseToken));
        }
    }

    function testERC20_ERC20CommonTests_OracleApproveEventEmission_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        vm.expectEmit(true, false, false, false);
        emit AD1467_OracleListChanged(true, ADDRESSES);
        oracleApproved.addToApprovedList(ADDRESSES);
    }

    function testERC20_ERC20CommonTests_OracleApproveEventEmission_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        // switch to an address other than the owner
        switchToSuperAdmin();
        vm.expectRevert("Ownable: caller is not the owner");
        oracleApproved.addToApprovedList(ADDRESSES);
    }

    function testERC20_ERC20CommonTests_ActionAppliedEventEmission_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array("Oscar"), createUint256Array(10), createUint256Array(1000));
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.P2P_TRANSFER);
        switchToRuleAdmin();
        vm.expectEmit(true, true, true, false);
        emit AD1467_ApplicationHandlerActionApplied(ACCOUNT_MIN_MAX_TOKEN_BALANCE, ActionTypes.P2P_TRANSFER, ruleId);
        ERC20TaggedRuleFacet(address(applicationCoinHandler)).setAccountMinMaxTokenBalanceId(actionTypes, ruleId);
    }

    function testERC20_ERC20CommonTests_ActionAppliedEventEmission_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        createAccountMinMaxTokenBalanceRule(createBytes32Array("Oscar"), createUint256Array(10), createUint256Array(1000));
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.P2P_TRANSFER);
        switchToRuleAdmin();
        vm.expectRevert(0x4bdf3b46);
        // Use a rule id that doesn't map to an actual rule
        ERC20TaggedRuleFacet(address(applicationCoinHandler)).setAccountMinMaxTokenBalanceId(actionTypes, 123);
    }

    function testERC20_ERC20CommonTests_OracleDeniedEventEmission_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        vm.expectEmit(true, false, false, false);
        emit AD1467_OracleListChanged(true, ADDRESSES);
        oracleDenied.addToDeniedList(ADDRESSES);
    }

    function testERC20_ERC20CommonTests_OracleDeniedEventEmission_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        // switch to an address other than the owner
        switchToSuperAdmin();
        vm.expectRevert("Ownable: caller is not the owner");
        oracleDenied.addToDeniedList(ADDRESSES);
    }

    function testERC20_ERC20CommonTests_AddFeeEventEmission() public endWithStopPrank ifDeploymentTestsEnabled {
        uint256 minBalance = 10 * ATTO;
        uint256 maxBalance = 10000000 * ATTO;
        int24 feePercentage = 300;
        address targetAccount = rich_user;
        // create a fee
        switchToRuleAdmin();
        vm.expectEmit(true, true, true, true);
        emit AD1467_FeeType("cheap", true, minBalance, maxBalance, feePercentage, targetAccount);
        FeesFacet(address(applicationCoinHandler)).addFee("cheap", minBalance, maxBalance, feePercentage, targetAccount);
    }

    function testERC20_ERC20CommonTests_SetFeeEventEmission() public endWithStopPrank ifDeploymentTestsEnabled {
        uint256 minBalance = 10 * ATTO;
        uint256 maxBalance = 10000000 * ATTO;
        int24 feePercentage = 300;
        address targetAccount = rich_user;
        // create a fee
        switchToRuleAdmin();
        FeesFacet(address(applicationCoinHandler)).addFee("cheap", minBalance, maxBalance, feePercentage, targetAccount);

        vm.expectEmit(true, true, true, true);
        emit AD1467_FeeActivationSet(false);
        FeesFacet(address(applicationCoinHandler)).setFeeActivation(false);
    }

    function testERC20_ERC20CommonTests_OnlyTokenCanCallCheckAllRules() public endWithStopPrank ifDeploymentTestsEnabled {
        address handler = IProtocolToken(address(testCaseToken)).getHandlerAddress();
        assertEq(handler, address(applicationCoinHandler));
        address owner = ERC173Facet(address(applicationCoinHandler)).owner();
        assertEq(owner, address(testCaseToken));
        vm.expectRevert("UNAUTHORIZED");
        ERC20HandlerMainFacet(handler).checkAllRules(0, 0, user1, user2, user3, 0);
    }

    function testERC20_ERC20CommonTests_AlreadyInitialized() public endWithStopPrank ifDeploymentTestsEnabled {
        vm.startPrank(address(testCaseToken));
        vm.expectRevert(abi.encodeWithSignature("AlreadyInitialized()"));
        ERC20HandlerMainFacet(address(applicationCoinHandler)).initialize(user1, user2, user3);
    }

    /// Test balance
    function testERC20_ERC20CommonTests_Balance_Positive() public view ifDeploymentTestsEnabled {
        console.logUint(testCaseToken.totalSupply());
        assertEq(testCaseToken.balanceOf(appAdministrator), 10000000000000000000000 * ATTO);
    }

    function testERC20_ERC20CommonTests_Balance_Negative() public view ifDeploymentTestsEnabled {
        console.logUint(testCaseToken.totalSupply());
        assertFalse(testCaseToken.balanceOf(appAdministrator) == (10000000000000000000 * ATTO));
    }

    function testERC20_ERC20CommonTests_Mint() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        UtilApplicationERC20(address(testCaseToken)).mint(superAdmin, 1000);
        assertEq(testCaseToken.balanceOf(superAdmin), 1000);
    }

    /// Test token transfer
    function testERC20_ERC20CommonTests_Transfer_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        testCaseToken.transfer(user, 10 * ATTO);
        assertEq(testCaseToken.balanceOf(user), 10 * ATTO);
        assertEq(testCaseToken.balanceOf(appAdministrator), 9999999999999999999990 * ATTO);
    }

    function testERC20_ERC20CommonTests_Transfer_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        vm.expectRevert("ERC20: transfer amount exceeds balance");
        testCaseToken.transfer(user, 10000000000000000000001 * ATTO);
    }

    function testERC20_ERC20CommonTests_ZeroAddressCheckERC20Token() public endWithStopPrank ifDeploymentTestsEnabled {
        vm.expectRevert(0xd92e233d);
        new UtilApplicationERC20("Dracula Coin", "DRAC", address(0x0));
    }

    function testERC20_ERC20CommonTests_ZeroAddressCheckERC20HandlerConnection() public endWithStopPrank ifDeploymentTestsEnabled {
        if (vm.envAddress("DEPLOYMENT_OWNER") != address(0x0)) {
            vm.expectRevert(abi.encodePacked("AccessControl: account ", Strings.toHexString(appAdministrator), " is missing role 0x9e262e26e9d5bf97da5c389e15529a31bb2b13d89967a4f6eab01792567d5fd6"));
            UtilApplicationERC20(address(testCaseToken)).connectHandlerToToken(address(0));
        } else {
        vm.expectRevert(0xba80c9e5);
        IProtocolToken(address(testCaseToken)).connectHandlerToToken(address(0));
        }
    }

    /// Token Minimum Transaction Size Tests
    function testERC20_ERC20CommonTests_testTokenMinTransactionSize_P2PTransfer_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMinTransactionSetup(ActionTypes.P2P_TRANSFER);
        vm.startPrank(rich_user, rich_user);
        // now we check for an allowed transfer
        testCaseToken.transfer(user3, 10);
        assertEq(testCaseToken.balanceOf(user3), 10);
    }

    function testERC20_ERC20CommonTests_testTokenMinTransactionSize_P2PTransfer_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMinTransactionSetup(ActionTypes.P2P_TRANSFER);
        vm.startPrank(rich_user, rich_user);
        // now we check for proper failure
        vm.expectRevert(0x7a78c901);
        testCaseToken.transfer(user3, 5);
    }

    function testERC20_ERC20CommonTests_testTokenMinTransactionSize_Buy_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _tokenMinTransactionSetup(ActionTypes.BUY);

        vm.startPrank(rich_user, rich_user);
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 10, true);
    }

    function testERC20_ERC20CommonTests_testTokenMinTransactionSize_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _tokenMinTransactionSetup(ActionTypes.BUY);

        vm.startPrank(rich_user, rich_user);
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        vm.expectRevert(0x7a78c901);
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 5, 5, true);
    }

    function testERC20_ERC20CommonTests_testTokenMinTransactionSize_Sell_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _tokenMinTransactionSetup(ActionTypes.SELL);
        vm.startPrank(rich_user, rich_user);
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10, 10, true);
    }

    function testERC20_ERC20CommonTests_testTokenMinTransactionSize_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _tokenMinTransactionSetup(ActionTypes.SELL);
        vm.startPrank(rich_user, rich_user);
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        vm.expectRevert(0x7a78c901);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 5, 5, true);
    }

    function testERC20_ERC20CommonTests_testTokenMinTransactionSize_Mint_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMinTransactionSetup(ActionTypes.MINT);
        switchToAppAdministrator();
        UtilApplicationERC20(address(testCaseToken)).mint(user3, 10);
        assertEq(testCaseToken.balanceOf(user3), 10);
    }

    function testERC20_ERC20CommonTests_testTokenMinTransactionSize_Mint_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMinTransactionSetup(ActionTypes.MINT);
        switchToAppAdministrator();
        vm.expectRevert(0x7a78c901);
        UtilApplicationERC20(address(testCaseToken)).mint(user3, 5);
    }

    function testERC20_ERC20CommonTests_testTokenMinTransactionSize_Burn_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMinTransactionSetup(ActionTypes.BURN);
        vm.startPrank(rich_user, rich_user);
        ERC20Burnable(address(testCaseToken)).burn(10);
        assertEq(testCaseToken.balanceOf(rich_user), 999990);
    }

    function testERC20_ERC20CommonTests_testTokenMinTransactionSize_Burn_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMinTransactionSetup(ActionTypes.BURN);
        vm.startPrank(rich_user, rich_user);
        vm.expectRevert(0x7a78c901);
        ERC20Burnable(address(testCaseToken)).burn(5);
    }

    /// Account Min Max Token Balance Tests
    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalance_P2PTransfer_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceIndividualActionSetup(ActionTypes.P2P_TRANSFER);
        ///perform transfer that checks rule but is allowed
        vm.startPrank(user1, user1);
        testCaseToken.transfer(user2, 10);
        assertEq(testCaseToken.balanceOf(user2), 10);
        assertEq(testCaseToken.balanceOf(user1), 90);
    }

    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalance_P2PTransfer_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceIndividualActionSetup(ActionTypes.P2P_TRANSFER);
        vm.startPrank(user1, user1);
        vm.expectRevert(0x3e237976);
        testCaseToken.transfer(user2, 99);
    }

    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalance_Buy_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountMinMaxTokenBalanceIndividualActionSetup(ActionTypes.BUY);
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 10, true);
    }

    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalance_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountMinMaxTokenBalanceIndividualActionSetup(ActionTypes.BUY);
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        vm.expectRevert(abi.encodeWithSignature("OverMaxBalance()"));
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 901, true);
    }

    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalance_Sell_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountMinMaxTokenBalanceIndividualActionSetup(ActionTypes.SELL);
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10, 10, true);
    }

    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalance_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountMinMaxTokenBalanceIndividualActionSetup(ActionTypes.SELL);
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        vm.expectRevert(abi.encodeWithSignature("UnderMinBalance()"));
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 100, 100, true);
    }

    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalance_Mint_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceIndividualActionSetup(ActionTypes.MINT);
        ///perform transfer that checks rule but is allowed
        switchToAppAdministrator();
        UtilApplicationERC20(address(testCaseToken)).mint(user2, 10);
        assertEq(testCaseToken.balanceOf(user2), 10);
        assertEq(testCaseToken.balanceOf(user1), 100);
    }

    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalance_Mint_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceIndividualActionSetup(ActionTypes.MINT);
        ///perform transfer that checks rule but is allowed
        switchToAppAdministrator();
        vm.expectRevert(abi.encodeWithSignature("OverMaxBalance()"));
        UtilApplicationERC20(address(testCaseToken)).mint(user2, 1001);
    }

    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalance_Burn_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceIndividualActionSetup(ActionTypes.BURN);
        ///perform transfer that checks rule but is allowed
        vm.startPrank(user1, user1);
        ERC20Burnable(address(testCaseToken)).burn(10);
        assertEq(testCaseToken.balanceOf(user1), 90);
    }

    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalance_Burn_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceIndividualActionSetup(ActionTypes.BURN);
        ///perform transfer that checks rule but is allowed
        vm.startPrank(user1, user1);
        vm.expectRevert(abi.encodeWithSignature("UnderMinBalance()"));
        ERC20Burnable(address(testCaseToken)).burn(100);
    }

    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalance_AllActionsEnabled() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceSetup(true, false);
        ///perform transfer that checks rule but is allowed
        vm.startPrank(user1, user1);
        testCaseToken.transfer(user2, 10);
        assertEq(testCaseToken.balanceOf(user2), 10);
        assertEq(testCaseToken.balanceOf(user1), 990);
    }

    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalance_AllActionsEnabled_Minimum() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceSetup(true, false);
        vm.startPrank(user1, user1);
        // make sure the minimum rules fail results in revert
        vm.expectRevert(0x3e237976);
        testCaseToken.transfer(user3, 999);
        // see if approving for another user bypasses rule
        testCaseToken.approve(address(888), 999);
    }

    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalance_AllActionsEnabled_Maximum() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceSetup(true, false);
        /// make sure the maximum rule fail results in revert
        vm.startPrank(rich_user, rich_user);
        vm.expectRevert(abi.encodeWithSignature("OverMaxBalance()"));
        testCaseToken.transfer(user2, 10091);
    }

    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalance_AllActionsEnabled_Period() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceSetup(true, true);
        vm.startPrank(rich_user, rich_user);
        /// make sure a transfer that is acceptable will still pass within the freeze window.
        testCaseToken.transfer(user1, 1000);
        vm.expectRevert(0xa7fb7b4b);
        testCaseToken.transfer(user1, 1);
        /// add enough time so that it should pass
        vm.warp(Blocktime + (720 * 1 hours));
        testCaseToken.transfer(user1, 1);
    }

    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalance_AllActionsEnabled_BlankTag() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceSetup(false, false);
        ///perform transfer that checks rule
        vm.startPrank(user1, user1);
        testCaseToken.transfer(user2, 10);
        assertEq(testCaseToken.balanceOf(user2), 10);
        assertEq(testCaseToken.balanceOf(user1), 990);
    }

    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalance_AllActionsEnabled_BlankTag_Minimum() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceSetup(false, false);
        ///perform transfer that checks rule
        vm.startPrank(user1, user1);

        // make sure the minimum rules fail results in revert
        vm.expectRevert(0x3e237976);
        testCaseToken.transfer(user3, 999);
        // see if approving for another user bypasses rule
        testCaseToken.approve(address(888), 999);
    }

    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalance_AllActionsEnabled_BlankTag_Maximum() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMinMaxTokenBalanceSetup(false, false);
        /// make sure the maximum rule fail results in revert
        vm.startPrank(rich_user, rich_user);
        vm.expectRevert(abi.encodeWithSignature("OverMaxBalance()"));
        testCaseToken.transfer(user2, 10091);
    }

    /// Account Approve Deny Oracle Tests
    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_DeniedList_Transfer_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracle_Setup(ActionTypes.P2P_TRANSFER, true);
        ///perform transfer that checks rule
        vm.startPrank(user1, user1);
        testCaseToken.transfer(user2, 10);
        assertEq(testCaseToken.balanceOf(user2), 10);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_DeniedList_Transfer_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracle_Setup(ActionTypes.P2P_TRANSFER, true);
        vm.startPrank(user1, user1);
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        testCaseToken.transfer(address(69), 10);
        assertEq(testCaseToken.balanceOf(address(69)), 1000);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_ApprovedList_Transfer_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracle_Setup(ActionTypes.P2P_TRANSFER, false);
        ///perform transfer that checks rule
        vm.startPrank(user1, user1);
        testCaseToken.transfer(address(59), 10);
        assertEq(testCaseToken.balanceOf(address(59)), 10);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_ApprovedList_Transfer_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracle_Setup(ActionTypes.P2P_TRANSFER, false);
        vm.startPrank(user1, user1);
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        testCaseToken.transfer(address(69), 10);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_DeniedList_Buy_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountApproveDenyOracle_Setup(ActionTypes.BUY, true);
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 10, true);
        assertEq(testCaseToken.balanceOf(user1), 100010);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_DeniedList_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountApproveDenyOracle_Setup(ActionTypes.BUY, true);
        vm.startPrank(address(69), address(69));
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 10, true);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_ApprovedList_Buy_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountApproveDenyOracle_Setup(ActionTypes.BUY, false);
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 10, true);
        assertEq(testCaseToken.balanceOf(user1), 100010);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_ApprovedList_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountApproveDenyOracle_Setup(ActionTypes.BUY, false);
        vm.startPrank(address(69), address(69));
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 10, true);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_DeniedList_Sell_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountApproveDenyOracle_Setup(ActionTypes.SELL, true);
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10, 10, true);
        assertEq(testCaseToken.balanceOf(user1), 99990);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_DeniedList_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountApproveDenyOracle_Setup(ActionTypes.SELL, true);
        vm.startPrank(address(69), address(69));
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10, 10, true);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_ApprovedList_Sell_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountApproveDenyOracle_Setup(ActionTypes.SELL, false);
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10, 10, true);
        assertEq(testCaseToken.balanceOf(user1), 99990);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_ApprovedList_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountApproveDenyOracle_Setup(ActionTypes.SELL, false);
        vm.startPrank(address(69), address(69));
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10, 10, true);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_DeniedList_Burn_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracle_Setup(ActionTypes.BURN, true);
        vm.startPrank(user1, user1);
        ERC20Burnable(address(testCaseToken)).burn(100);
        assertEq(testCaseToken.balanceOf(user1), 99900);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_DeniedList_Burn_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracle_Setup(ActionTypes.BURN, true);
        vm.startPrank(address(69), address(69));
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        ERC20Burnable(address(testCaseToken)).burn(100);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_ApprovedList_Burn_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracle_Setup(ActionTypes.BURN, false);
        vm.startPrank(user1, user1);
        ERC20Burnable(address(testCaseToken)).burn(100);
        assertEq(testCaseToken.balanceOf(user1), 99900);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_ApprovedList_Burn_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracle_Setup(ActionTypes.BURN, false);
        vm.startPrank(address(69), address(69));
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        ERC20Burnable(address(testCaseToken)).burn(100);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_DeniedList_Mint_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracle_Setup(ActionTypes.MINT, true);
        vm.startPrank(user1, user1);
        UtilApplicationERC20(address(testCaseToken)).mint(user1, 100);
        assertEq(testCaseToken.balanceOf(user1), 100100);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_DeniedList_Mint_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracle_Setup(ActionTypes.MINT, true);
        vm.startPrank(address(user1));
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        UtilApplicationERC20(address(testCaseToken)).mint(address(69), 100);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_ApprovedList_Mint_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracle_Setup(ActionTypes.MINT, false);
        vm.startPrank(user1, user1);
        UtilApplicationERC20(address(testCaseToken)).mint(user1, 100);
        assertEq(testCaseToken.balanceOf(user1), 100100);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_ApprovedList_Mint_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracle_Setup(ActionTypes.MINT, false);
        vm.startPrank(address(user1));
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        UtilApplicationERC20(address(testCaseToken)).mint(address(69), 100);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_AllActionsEnabled_DeniedList() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// set up a non admin user with tokens
        testCaseToken.transfer(user1, 100000);
        assertEq(testCaseToken.balanceOf(user1), 100000);

        // add the rule.
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        setAccountApproveDenyOracleRule(address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(address(69));
        oracleDenied.addToDeniedList(badBoys);
        ///perform transfer that checks rule
        vm.startPrank(user1, user1);
        testCaseToken.transfer(user2, 10);
        assertEq(testCaseToken.balanceOf(user2), 10);
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        testCaseToken.transfer(address(69), 10);
        assertEq(testCaseToken.balanceOf(address(69)), 0);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_AllActionsEnabled_ApprovedList() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// set up a non admin user with tokens
        testCaseToken.transfer(user1, 100000);
        assertEq(testCaseToken.balanceOf(user1), 100000);

        uint32 ruleId = createAccountApproveDenyOracleRule(1);
        setAccountApproveDenyOracleRule(address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();

        // add approved addresses
        goodBoys.push(address(59));
        goodBoys.push(address(user5));
        goodBoys.push(address(user1));
        oracleApproved.addToApprovedList(goodBoys);
        vm.startPrank(user1, user1);
        // This one should pass
        testCaseToken.transfer(address(59), 10);
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        testCaseToken.transfer(address(88), 10);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_AllActionsEnabled_InvalidOracleType() public endWithStopPrank ifDeploymentTestsEnabled {
        // Finally, check the invalid type
        switchToRuleAdmin();
        vm.expectRevert("Oracle Type Invalid");
        createAccountApproveDenyOracleRule(2);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_AllActionsEnabled_Burning() public endWithStopPrank ifDeploymentTestsEnabled {
        /// test burning while oracle rule is active (allow list active)
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(1);
        setAccountApproveDenyOracleRule(address(applicationCoinHandler), ruleId);
        /// first mint to user
        switchToAppAdministrator();
        goodBoys.push(address(user5));
        goodBoys.push(appAdministrator);
        oracleApproved.addToApprovedList(goodBoys);
        switchToAppAdministrator();
        testCaseToken.transfer(user5, 10000);
        /// burn some tokens as user
        /// burns do not check for the recipient address as it is address(0)
        vm.startPrank(user5, user5);
        ERC20Burnable(address(testCaseToken)).burn(5000);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_AllActionsEnabled_ZeroAddress() public endWithStopPrank ifDeploymentTestsEnabled {
        /// add address(0) to deny list and switch oracle rule to deny list
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        setAccountApproveDenyOracleRule(address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        testCaseToken.transfer(user5, 10000);
        badBoys.push(address(user5));
        oracleDenied.addToDeniedList(badBoys);
        /// attempt to burn (should fail)
        vm.startPrank(user5, user5);
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        ERC20Burnable(address(testCaseToken)).burn(5000);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_AllActionsEnabled_AddSingleAddress_Approved() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        oracleApproved.addAddressToApprovedList(address(59));
        assertEq(oracleApproved.isApproved(address(59)), true);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracle_AllActionsEnabled_AddSingleAddress_Denied() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        oracleDenied.addAddressToDeniedList(address(69));
        assertEq(oracleDenied.isDenied(address(69)), true);
    }


    /// Account Approve Deny Oracle Flexible Tests
    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_DeniedList_Transfer_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleFlexible_Setup(ActionTypes.P2P_TRANSFER, true, 0);
        ///perform transfer that checks rule
        vm.startPrank(user1, user1);
        testCaseToken.transfer(user2, 10);
        assertEq(testCaseToken.balanceOf(user2), 10);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_DeniedList_Transfer_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleFlexible_Setup(ActionTypes.P2P_TRANSFER, true, 3);
        vm.startPrank(user1, user1);
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        testCaseToken.transfer(address(69), 10);
        assertEq(testCaseToken.balanceOf(address(69)), 1000);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_ApprovedList_Transfer_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleFlexible_Setup(ActionTypes.P2P_TRANSFER, false, 0);
        ///perform transfer that checks rule
        vm.startPrank(user1, user1);
        testCaseToken.transfer(address(59), 10);
        assertEq(testCaseToken.balanceOf(address(59)), 10);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_ApprovedList_Transfer_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleFlexible_Setup(ActionTypes.P2P_TRANSFER, false, 0);
        vm.startPrank(user1, user1);
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        testCaseToken.transfer(address(69), 10);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_DeniedList_Buy_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountApproveDenyOracleFlexible_Setup(ActionTypes.BUY, true, 0);
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 10, true);
        assertEq(testCaseToken.balanceOf(user1), 100010);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_DeniedList_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountApproveDenyOracleFlexible_Setup(ActionTypes.BUY, true, 3);
        vm.startPrank(address(69), address(69));
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 10, true);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_ApprovedList_Buy_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountApproveDenyOracleFlexible_Setup(ActionTypes.BUY, false, 0);
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 10, true);
        assertEq(testCaseToken.balanceOf(user1), 100010);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_ApprovedList_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountApproveDenyOracleFlexible_Setup(ActionTypes.BUY, false, 0);
        vm.startPrank(address(69), address(69));
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 10, true);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_DeniedList_Sell_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountApproveDenyOracleFlexible_Setup(ActionTypes.SELL, true, 0);
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10, 10, true);
        assertEq(testCaseToken.balanceOf(user1), 99990);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_DeniedList_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountApproveDenyOracleFlexible_Setup(ActionTypes.SELL, true, 3);
        vm.startPrank(address(69), address(69));
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10, 10, true);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_ApprovedList_Sell_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountApproveDenyOracleFlexible_Setup(ActionTypes.SELL, false, 0);
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10, 10, true);
        assertEq(testCaseToken.balanceOf(user1), 99990);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_ApprovedList_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountApproveDenyOracleFlexible_Setup(ActionTypes.SELL, false, 0);
        vm.startPrank(address(69), address(69));
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10, 10, true);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_DeniedList_Burn_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleFlexible_Setup(ActionTypes.BURN, true, 0);
        vm.startPrank(user1, user1);
        ERC20Burnable(address(testCaseToken)).burn(100);
        assertEq(testCaseToken.balanceOf(user1), 99900);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_DeniedList_Burn_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleFlexible_Setup(ActionTypes.BURN, true, 3);
        vm.startPrank(address(69), address(69));
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        ERC20Burnable(address(testCaseToken)).burn(100);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_ApprovedList_Burn_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleFlexible_Setup(ActionTypes.BURN, false, 2);
        vm.startPrank(user1, user1);
        ERC20Burnable(address(testCaseToken)).burn(100);
        assertEq(testCaseToken.balanceOf(user1), 99900);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_ApprovedList_Burn_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleFlexible_Setup(ActionTypes.BURN, false, 0);
        vm.startPrank(address(69), address(69));
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        ERC20Burnable(address(testCaseToken)).burn(100);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_DeniedList_Mint_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleFlexible_Setup(ActionTypes.MINT, true, 0);
        vm.startPrank(user1, user1);
        UtilApplicationERC20(address(testCaseToken)).mint(user1, 100);
        assertEq(testCaseToken.balanceOf(user1), 100100);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_DeniedList_Mint_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleFlexible_Setup(ActionTypes.MINT, true, 3);
        vm.startPrank(address(user1));
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        UtilApplicationERC20(address(testCaseToken)).mint(address(69), 100);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_ApprovedList_Mint_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleFlexible_Setup(ActionTypes.MINT, false, 1);
        vm.startPrank(user1, user1);
        UtilApplicationERC20(address(testCaseToken)).mint(user1, 100);
        assertEq(testCaseToken.balanceOf(user1), 100100);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_ApprovedList_Mint_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountApproveDenyOracleFlexible_Setup(ActionTypes.MINT, false, 0);
        vm.startPrank(address(user1));
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        UtilApplicationERC20(address(testCaseToken)).mint(address(69), 100);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_AllActionsEnabled_DeniedList() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// set up a non admin user with tokens
        testCaseToken.transfer(user1, 100000);
        assertEq(testCaseToken.balanceOf(user1), 100000);

        // add the rule.
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(0, 3);
        setAccountApproveDenyOracleFlexibleRule(address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(address(69));
        oracleDenied.addToDeniedList(badBoys);
        ///perform transfer that checks rule
        vm.startPrank(user1, user1);
        testCaseToken.transfer(user2, 10);
        assertEq(testCaseToken.balanceOf(user2), 10);
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        testCaseToken.transfer(address(69), 10);
        assertEq(testCaseToken.balanceOf(address(69)), 0);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_AllActionsEnabled_ApprovedList() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// set up a non admin user with tokens
        testCaseToken.transfer(user1, 100000);
        assertEq(testCaseToken.balanceOf(user1), 100000);

        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(1, 0);
        setAccountApproveDenyOracleFlexibleRule(address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();

        // add approved addresses
        goodBoys.push(address(59));
        goodBoys.push(address(user5));
        goodBoys.push(address(user1));
        oracleApproved.addToApprovedList(goodBoys);
        vm.startPrank(user1, user1);
        // This one should pass
        testCaseToken.transfer(address(59), 10);
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        testCaseToken.transfer(address(88), 10);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_AllActionsEnabled_InvalidOracleType() public endWithStopPrank ifDeploymentTestsEnabled {
        // Finally, check the invalid type
        switchToRuleAdmin();
        vm.expectRevert("Oracle Type Invalid");
        createAccountApproveDenyOracleFlexibleRule(2, 3);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_AllActionsEnabled_Burning() public endWithStopPrank ifDeploymentTestsEnabled {
        /// test burning while oracle rule is active (allow list active)
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(1, 2);
        setAccountApproveDenyOracleFlexibleRule(address(applicationCoinHandler), ruleId);
        /// first mint to user
        switchToAppAdministrator();
        goodBoys.push(address(user5));
        goodBoys.push(appAdministrator);
        oracleApproved.addToApprovedList(goodBoys);
        switchToAppAdministrator();
        testCaseToken.transfer(user5, 10000);
        /// burn some tokens as user
        /// burns do not check for the recipient address as it is address(0)
        vm.startPrank(user5, user5);
        ERC20Burnable(address(testCaseToken)).burn(5000);
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexible_AllActionsEnabled_ZeroAddress() public endWithStopPrank ifDeploymentTestsEnabled {
        /// add address(0) to deny list and switch oracle rule to deny list
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(0, 3);
        setAccountApproveDenyOracleFlexibleRule(address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        testCaseToken.transfer(user5, 10000);
        badBoys.push(address(user5));
        oracleDenied.addToDeniedList(badBoys);
        /// attempt to burn (should fail)
        vm.startPrank(user5, user5);
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        ERC20Burnable(address(testCaseToken)).burn(5000);
    }

    /// Account Max Value By Access Level Tests
    function testERC20_ERC20CommonTests_AccountMaxValueByAccessLevel_Transfer_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxValueByAccessLevelSetup(ActionTypes.P2P_TRANSFER);
        /// Add access level to whale
        address whale = address(99);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(whale, 4);

        /// perform transfer that checks user with AccessLevel and no balances
        vm.startPrank(user1, user1);
        /// this one is within the limit and should pass
        testCaseToken.transfer(whale, 10000 * ATTO);
    }

    function testERC20_ERC20CommonTests_AccountMaxValueByAccessLevel_Transfer_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxValueByAccessLevelSetup(ActionTypes.P2P_TRANSFER);
        /// Add access level to whale
        address whale = address(99);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(whale, 4);

        /// perform transfer that checks user with AccessLevel and no balances
        vm.startPrank(user1, user1);
        /// this one is over the limit and should fail
        vm.expectRevert(abi.encodeWithSignature("OverMaxValueByAccessLevel()"));
        testCaseToken.transfer(whale, 10001 * ATTO);
    }

    function testERC20_ERC20CommonTests_AccountMaxValueByAccessLevel_Mint_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxValueByAccessLevelSetup(ActionTypes.MINT);
        /// Add access level to whale
        address whale = address(99);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(whale, 4);

        /// perform transfer that checks user with AccessLevel and no balances
        vm.startPrank(user1, user1);
        /// this one is within the limit and should pass
        UtilApplicationERC20(address(testCaseToken)).mint(whale, 10000 * ATTO);
    }

    function testERC20_ERC20CommonTests_AccountMaxValueByAccessLevel_Mint_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxValueByAccessLevelSetup(ActionTypes.MINT);
        /// Add access level to whale
        address whale = address(99);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(whale, 4);

        /// perform transfer that checks user with AccessLevel and no balances
        vm.startPrank(user1, user1);
        /// this one is over the limit and should fail
        vm.expectRevert(abi.encodeWithSignature("OverMaxValueByAccessLevel()"));
        UtilApplicationERC20(address(testCaseToken)).mint(whale, 10001 * ATTO);
    }


    function testERC20_ERC20CommonTests_AccountMaxValueByAccessLevel_Buy_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountMaxValueByAccessLevelSetup(ActionTypes.BUY);
        /// Add access level to whale
        address whale = address(99);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(whale, 4);
        switchToAppAdministrator();
        applicationCoin2.transfer(address(whale), 10);

        /// perform transfer that checks user with AccessLevel and no balances
        vm.startPrank(whale, whale);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 50000);
        /// this one is within the limit and should pass
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 10000 * ATTO, true);
    }

    function testERC20_ERC20CommonTests_AccountMaxValueByAccessLevel_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountMaxValueByAccessLevelSetup(ActionTypes.BUY);
        /// Add access level to whale
        address whale = address(99);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(whale, 4);
        switchToAppAdministrator();
        applicationCoin2.transfer(address(whale), 10);

        /// perform transfer that checks user with AccessLevel and no balances
        vm.startPrank(whale, whale);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 50000);
        vm.expectRevert(abi.encodeWithSignature("OverMaxValueByAccessLevel()"));
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 10001 * ATTO, true);
    }

    function testERC20_ERC20CommonTests_AccountMaxValueByAccessLevel_NoAccessLevel() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxValueByAccessLevelSetup(ActionTypes.P2P_TRANSFER);
        ///perform transfer that checks rule when account does not have AccessLevel(should fail)
        vm.startPrank(user1, user1);
        vm.expectRevert(abi.encodeWithSignature("OverMaxValueByAccessLevel()"));
        testCaseToken.transfer(user2, 11 * ATTO);
    }

    function testERC20_ERC20CommonTests_AccountMaxValueByAccessLevel_Combination() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxValueByAccessLevelSetup(ActionTypes.P2P_TRANSFER);
        // set the access level for the user4
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user4, 3);

        vm.startPrank(user1, user1);
        /// perform transfer that checks user with AccessLevel and existing balances(should fail regardless of other balance)
        vm.expectRevert(0xaee8b993);
        testCaseToken.transfer(user4, 1001 * ATTO);
        /// perform transfer that checks user with AccessLevel and existing balances(should fail because of other balance)
        applicationCoin2.transfer(user4, 999 * ATTO);
        vm.expectRevert(0xaee8b993);
        testCaseToken.transfer(user4, 2 * ATTO);

        /// perform transfer that checks user with AccessLevel and existing balances(should pass)
        testCaseToken.transfer(user4, 1 * ATTO);
        assertEq(testCaseToken.balanceOf(user4), 1 * ATTO);
    }

    function testERC20_ERC20CommonTests_AccountMaxValueByAccessLevel_Burning() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxValueByAccessLevelSetup(ActionTypes.P2P_TRANSFER);
        address whale = address(99);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(whale, 4);
        applicationAppManager.addAccessLevel(user4, 3);
        vm.startPrank(user1, user1);
        /// this one is within the limit and should pass
        testCaseToken.transfer(whale, 10000 * ATTO);
        testCaseToken.transfer(user4, 1 * ATTO);

        /// test burning is allowed while rule is active
        ERC20Burnable(address(testCaseToken)).burn(1 * ATTO);
        /// burn remaining balance to ensure rule limit is not checked on burns
        ERC20Burnable(address(testCaseToken)).burn(79998000000000000010000);
        /// test burn with account that has access level assign
        vm.startPrank(user4, user4);
        ERC20Burnable(address(testCaseToken)).burn(1 * ATTO);
        assertEq(testCaseToken.balanceOf(user4), 0);
    }

    /// Pause Rule Tests
    function testERC20_ERC20CommonTests_PauseRulesViaAppManager() public endWithStopPrank ifDeploymentTestsEnabled {
        _pauseRuleSetup();
        vm.startPrank(user1, user1);
        bytes4 selector = bytes4(keccak256("ApplicationPaused(uint256,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, Blocktime + 1000, Blocktime + 1500));
        testCaseToken.transfer(user2, 1000);
    }

    function testERC20_ERC20CommonTests_PauseRulesViaAppManager_Bypass() public endWithStopPrank ifDeploymentTestsEnabled {
        _pauseRuleSetup();
        ///Check that Treasury accounts can still transfer within pausePeriod
        switchToTreasuryAccount();

        testCaseToken.transfer(superAdmin, 1000);
        assertEq(testCaseToken.balanceOf(superAdmin), 1000);
    }

    function testERC20_ERC20CommonTests_PauseRulesViaAppManager_MultipleWindows() public endWithStopPrank ifDeploymentTestsEnabled {
        _pauseRuleSetup();
        ///Set multiple pause rules
        switchToRuleAdmin();
        applicationAppManager.addPauseRule(Blocktime + 1700, Blocktime + 2000);
        applicationAppManager.addPauseRule(Blocktime + 2100, Blocktime + 2500);
        applicationAppManager.addPauseRule(Blocktime + 3000, Blocktime + 3500);

        ///warp between periods to test pause effect
        ///Pause window 1
        vm.warp(Blocktime + 1755);
        vm.startPrank(user1, user1);
        bytes4 selector = bytes4(keccak256("ApplicationPaused(uint256,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, Blocktime + 1700, Blocktime + 2000));
        testCaseToken.transfer(user2, 1200);
        ///Pause window 2
        vm.warp(Blocktime + 2150);
        selector = bytes4(keccak256("ApplicationPaused(uint256,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, Blocktime + 2100, Blocktime + 2500));
        testCaseToken.transfer(user2, 1300);
        ///In between 2 and 3
        vm.warp(Blocktime + 2675);
        testCaseToken.transfer(user2, 1000);
        ///Pause window 3
        vm.warp(Blocktime + 3333);
        selector = bytes4(keccak256("ApplicationPaused(uint256,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, Blocktime + 3000, Blocktime + 3500));
        testCaseToken.transfer(user2, 1400);
        ///After pause window 3
        vm.warp(Blocktime + 3775);
        testCaseToken.transfer(user2, 1000);

        assertEq(testCaseToken.balanceOf(user2), 3000);
    }

    /// Account Max Transaciton Value By Risk Score Tests
    function testERC20_ERC20CommonTests_AccountMaxTransactionValueByRiskScore_Transfer_Passes() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxTransactionValueByRiskScoreSetup(ActionTypes.P2P_TRANSFER);
        ///User2 sends User1 amount under transaction limit, expect passing
        vm.startPrank(user2, user2);
        testCaseToken.transfer(user1, 1 * (10 ** 18));
    }

    function testERC20_ERC20CommonTests_AccountMaxTransactionValueByRiskScore_Transfer_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxTransactionValueByRiskScoreSetup(ActionTypes.P2P_TRANSFER);
        ///Transfer expected to fail
        vm.startPrank(user1, user1);
        bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 10, 1000000000000000000000000));
        testCaseToken.transfer(user2, 1000001 * (10 ** 18));
    }

    function testERC20_ERC20CommonTests_AccountMaxTransactionValueByRiskScore_Buy_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountMaxTransactionValueByRiskScoreSetup(ActionTypes.BUY);
        vm.startPrank(user2, user2);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 50000);
        /// this one is within the limit and should pass
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 1 * (10 ** 18), true);
    }

    function testERC20_ERC20CommonTests_AccountMaxTransactionValueByRiskScore_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _accountMaxTransactionValueByRiskScoreSetup(ActionTypes.BUY);
        vm.startPrank(user2, user2);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 50000);
        bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 40, 100000000000000000000000));
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 1000001 * (10 ** 18), true);
    }

    function testERC20_ERC20CommonTests_AccountMaxTransactionValueByRiskScore_Mint_Passes() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxTransactionValueByRiskScoreSetup(ActionTypes.MINT);
        ///User2 sends User1 amount under transaction limit, expect passing
        vm.startPrank(user1, user1);
        UtilApplicationERC20(address(testCaseToken)).mint(user2, 1 * (10 ** 18));
    }

    function testERC20_ERC20CommonTests_AccountMaxTransactionValueByRiskScore_Mint_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxTransactionValueByRiskScoreSetup(ActionTypes.MINT);
        ///Transfer expected to fail
        vm.startPrank(user1, user1);
        bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 40, 100000000000000000000000));
        UtilApplicationERC20(address(testCaseToken)).mint(user2, 1000001 * (10 ** 18));
    }

    function testERC20_ERC20CommonTests_AccountMaxTransactionValueByRiskScore_Mixed() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxTransactionValueByRiskScoreSetup(ActionTypes.P2P_TRANSFER);
        switchToRiskAdmin();
        ///Test in between Risk Score Values
        applicationAppManager.addRiskScore(user3, 49);
        applicationAppManager.addRiskScore(user4, 81);

        vm.startPrank(user3, user3);
        bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 81, 10000000000000000000000));
        testCaseToken.transfer(user4, 10001 * (10 ** 18));

        vm.startPrank(user4, user4);
        testCaseToken.transfer(user3, 10 * (10 ** 18));

        testCaseToken.transfer(user3, 1001 * (10 ** 18));
    }

    function testERC20_ERC20CommonTests_AccountMaxTransactionValueByRiskScore_Burning() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxTransactionValueByRiskScoreSetup(ActionTypes.P2P_TRANSFER);
        /// test burning tokens while rule is active (burn is not a viable action for this rule)
        vm.startPrank(user5, user5);
        ERC20Burnable(address(testCaseToken)).burn(999 * (10 ** 18));
        ERC20Burnable(address(testCaseToken)).burn(1001 * (10 ** 18));
    }

  /// Account Max Transaction Value By Risk Score With Period Tests
    function testERC20_ERC20CommonTests_AccountMaxTransactionValueByRiskScoreWithPeriod_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        ///Transfer expected to fail in one large transaction
        _accountMaxTransactionValueByRiskScoreWithPeriodSetup();
        vm.startPrank(user1, user1);
        bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 10, 1000000000000000000000000));
        testCaseToken.transfer(user2, 1000001 * ATTO);
    }

    function testERC20_ERC20CommonTests_AccountMaxTransactionValueByRiskScoreWithPeriod_Mixed() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxTransactionValueByRiskScoreWithPeriodSetup();
        switchToRiskAdmin();
        ///Test in between Risk Score Values
        applicationAppManager.addRiskScore(user3, 49);
        applicationAppManager.addRiskScore(user4, 81);

        vm.startPrank(user3, user3);
        bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 81, 10000000000000000000000));
        testCaseToken.transfer(user4, 10001 * ATTO);

        vm.startPrank(user4, user4);
        testCaseToken.transfer(user3, 10 * ATTO);
    }

    function testERC20_ERC20CommonTests_AccountMaxTransactionValueByRiskScoreWithPeriod_Burning() public endWithStopPrank ifDeploymentTestsEnabled {
        /// test burning tokens while rule is active
        _accountMaxTransactionValueByRiskScoreWithPeriodSetup();
        vm.startPrank(user5, user5);
        ERC20Burnable(address(testCaseToken)).burn(999 * ATTO);
        bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 99, 1000000000000000000000));
        ERC20Burnable(address(testCaseToken)).burn(1001 * ATTO);
    }

    function testERC20_ERC20CommonTests_AccountMaxTransactionValueByRiskScoreWithPeriod_NewPeriod() public endWithStopPrank ifDeploymentTestsEnabled {
        _accountMaxTransactionValueByRiskScoreWithPeriodSetup();
        /// let's test in a new period with a couple small txs:
        vm.warp(block.timestamp + 48 hours);
        vm.startPrank(user1, user1);
        testCaseToken.transfer(user6, (1000002 / 2) * ATTO);
        bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 10, 1000000000000000000000000));
        testCaseToken.transfer(user6, (1000002 / 2) * ATTO);
    }

    // Account Deny For No Access Level Tests
    function testERC20_ERC20CommonTests_PassesAccountDenyForNoAccessLevelRuleCoin_Transfer_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _passesAccountDenyForNoAccessLevelRuleCoinSetup(ActionTypes.P2P_TRANSFER);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user3, 1);
        applicationAppManager.addAccessLevel(rich_user, 1);

        vm.startPrank(rich_user, rich_user);
        testCaseToken.transfer(user3, 5 * ATTO);
        assertEq(testCaseToken.balanceOf(user3), 10 * ATTO);

        vm.startPrank(user3, user3);
        testCaseToken.transfer(rich_user, 5 * ATTO);
    }

    function testERC20_ERC20CommonTests_PassesAccountDenyForNoAccessLevelRuleCoin_Transfer_NoAccessLevels() public endWithStopPrank ifDeploymentTestsEnabled {
        _passesAccountDenyForNoAccessLevelRuleCoinSetup(ActionTypes.P2P_TRANSFER);
        vm.startPrank(rich_user, rich_user);
        vm.expectRevert(0x3fac082d);
        testCaseToken.transfer(user3, 5 * ATTO);

        vm.startPrank(user3, user3);
        vm.expectRevert(0x3fac082d);
        testCaseToken.transfer(rich_user, 5 * ATTO);
    }

    function testERC20_ERC20CommonTests_PassesAccountDenyForNoAccessLevelRuleCoin_Transfer_OneSided() public endWithStopPrank ifDeploymentTestsEnabled {
        _passesAccountDenyForNoAccessLevelRuleCoinSetup(ActionTypes.P2P_TRANSFER);
        // set AccessLevel and try again
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user3, 1);

        vm.startPrank(rich_user, rich_user);
        vm.expectRevert(0x3fac082d); /// this fails because rich_user is still accessLevel0
        testCaseToken.transfer(user3, 5 * ATTO);

        vm.startPrank(user3, user3);
        vm.expectRevert(0x3fac082d); /// this fails because rich_user is still accessLevel0
        testCaseToken.transfer(rich_user, 5 * ATTO);
    }

    function testERC20_ERC20CommonTests_PassesAccountDenyForNoAccessLevelRuleCoin_Mint_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _passesAccountDenyForNoAccessLevelRuleCoinSetup(ActionTypes.MINT);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user3, 1);
        applicationAppManager.addAccessLevel(rich_user, 1);

        vm.startPrank(rich_user, rich_user);
        UtilApplicationERC20(address(testCaseToken)).mint(rich_user, 1 * ATTO);
    }

    function testERC20_ERC20CommonTests_PassesAccountDenyForNoAccessLevelRuleCoin_Mint_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _passesAccountDenyForNoAccessLevelRuleCoinSetup(ActionTypes.MINT);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user3, 1);

        vm.startPrank(user3, user3);
        vm.expectRevert(abi.encodeWithSignature("NotAllowedForAccessLevel()"));
        UtilApplicationERC20(address(testCaseToken)).mint(rich_user, 5 * ATTO);
    }

    function testERC20_ERC20CommonTests_PassesAccountDenyForNoAccessLevelRuleCoin_Buy_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _passesAccountDenyForNoAccessLevelRuleCoinSetup(ActionTypes.BUY);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user3, 1);
        applicationAppManager.addAccessLevel(rich_user, 1);

        vm.startPrank(user3, user3);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 50000);
        /// this one is within the limit and should pass
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 5 * ATTO, true);
    }

    function testERC20_ERC20CommonTests_PassesAccountDenyForNoAccessLevelRuleCoin_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _passesAccountDenyForNoAccessLevelRuleCoinSetup(ActionTypes.BUY);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(rich_user, 1);

        vm.startPrank(user3, user3);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 50000);
        vm.expectRevert(abi.encodeWithSignature("NotAllowedForAccessLevel()"));
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 5 * ATTO, true);
    }

    function testERC20_ERC20CommonTests_PassesAccountDenyForNoAccessLevelRuleCoin_Sell_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _passesAccountDenyForNoAccessLevelRuleCoinSetup(ActionTypes.SELL);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user3, 1);
        applicationAppManager.addAccessLevel(rich_user, 1);

        vm.startPrank(user3, user3);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 50000);
        /// this one is within the limit and should pass
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 5 * ATTO, 10, true);
    }

    function testERC20_ERC20CommonTests_PassesAccountDenyForNoAccessLevelRuleCoin_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _passesAccountDenyForNoAccessLevelRuleCoinSetup(ActionTypes.SELL);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(rich_user, 1);

        vm.startPrank(user3, user3);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 50000);
        vm.expectRevert(abi.encodeWithSignature("NotAllowedForAccessLevel()"));
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 5 * ATTO, 10, true);
    }

    function testERC20_ERC20CommonTests_PassesAccountDenyForNoAccessLevelRuleCoin_Burning() public endWithStopPrank ifDeploymentTestsEnabled {
        _passesAccountDenyForNoAccessLevelRuleCoinSetup(ActionTypes.BURN);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user3, 1);
        applicationAppManager.addAccessLevel(rich_user, 1);

        vm.startPrank(user3, user3);
        /// test that burn works when user has accessLevel above 0
        ERC20Burnable(address(testCaseToken)).burn(5 * ATTO);
        /// test burn fails when rule active and user has access level 0
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(rich_user, 0);

        vm.startPrank(rich_user, rich_user);
        vm.expectRevert(0x3fac082d);
        ERC20Burnable(address(testCaseToken)).burn(1 * ATTO);
    }

    /// Max Value Out
    function testERC20_ERC20CommonTests_MaxValueOutByAccessLevel_Transfer_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _maxValueOutByAccessLevelSetup(ActionTypes.P2P_TRANSFER);
        vm.startPrank(user1, user1);
        testCaseToken.transfer(user3, 50 * ATTO);
        testCaseToken.transfer(user4, 50 * ATTO);
        /// User 1 now at "withdrawal" limit for access level
        vm.startPrank(user3, user3);
        testCaseToken.transfer(user4, 10 * ATTO);
        assertEq(testCaseToken.balanceOf(user4), 60 * ATTO);
    }

    function testERC20_ERC20CommonTests_MaxValueOutByAccessLevel_Transfer_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        /// test transfers fail over rule value
        _maxValueOutByAccessLevelSetup(ActionTypes.P2P_TRANSFER);
        vm.startPrank(user1, user1);
        testCaseToken.transfer(user3, 50 * ATTO);
        testCaseToken.transfer(user4, 50 * ATTO);

        vm.expectRevert(0x8d857c50);
        testCaseToken.transfer(user3, 50 * ATTO);

        vm.startPrank(user3, user3);
        testCaseToken.transfer(user4, 10 * ATTO);
        vm.expectRevert(abi.encodeWithSignature("OverMaxValueOutByAccessLevel()"));
        testCaseToken.transfer(user4, 50 * ATTO);
    }

    function testERC20_ERC20CommonTests_MaxValueOutByAccessLevel_Sell_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _maxValueOutByAccessLevelSetup(ActionTypes.SELL);
        vm.startPrank(user1, user1);
        testCaseToken.transfer(user3, 50 * ATTO);
        testCaseToken.transfer(user4, 50 * ATTO);
        /// User 1 now at "withdrawal" limit for access level
        vm.startPrank(user3, user3);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 50000);
        /// this one is within the limit and should pass
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10 * ATTO, 10, true);
    }

    function testERC20_ERC20CommonTests_MaxValueOutByAccessLevel_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _maxValueOutByAccessLevelSetup(ActionTypes.SELL);
        vm.startPrank(user1, user1);
        testCaseToken.transfer(user3, 50 * ATTO);
        testCaseToken.transfer(user4, 50 * ATTO);
        /// User 1 now at "withdrawal" limit for access level
        vm.startPrank(user3, user3);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 50000);
        /// this one is within the limit and should pass
        vm.expectRevert(abi.encodeWithSignature("OverMaxValueOutByAccessLevel()"));
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 50 * ATTO, 10, true);
    }

    function testERC20_ERC20CommonTests_MaxValueOutByAccessLevel_ReducedPrice() public endWithStopPrank ifDeploymentTestsEnabled {
        /// reduce price and test pass fail situations
        _maxValueOutByAccessLevelSetup(ActionTypes.P2P_TRANSFER);
        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(testCaseToken), 5 * (10 ** 17));
        assertEq(erc20Pricer.getTokenPrice(address(testCaseToken)), 5 * (10 ** 17));

        vm.startPrank(user1, user1);
        testCaseToken.transfer(user4, 50 * ATTO);
        vm.startPrank(user3, user3);
        testCaseToken.transfer(user4, 10 * ATTO);

        vm.startPrank(user4, user4);
        /// successful transfer as the new price is $.50USD (can transfer up to $10)
        testCaseToken.transfer(user4, 20 * ATTO);
        /// transfer fails because user reached ACCESS limit
        vm.expectRevert(0x8d857c50);
        testCaseToken.transfer(user3, 10 * ATTO);
    }

    /// Token Max Trading Volume With Supply Set Tests
    function testERC20_ERC20CommonTests_TokenMaxTradingVolumeWithSupplySet_Transfer_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxTradingVolumeWithSupplySetSetup(ActionTypes.P2P_TRANSFER);
        vm.startPrank(rich_user, rich_user);
        /// make sure that transfer under the threshold works
        testCaseToken.transfer(user1, 39_000 * ATTO);
        assertEq(testCaseToken.balanceOf(user1), 39_000 * ATTO);
        /// now take it right up to the threshold(39,999)
        testCaseToken.transfer(user1, 999 * ATTO);
        assertEq(testCaseToken.balanceOf(user1), 39_999 * ATTO);
    }

    function testERC20_ERC20CommonTests_TokenMaxTradingVolumeWithSupplySet_Transfer_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxTradingVolumeWithSupplySetSetup(ActionTypes.P2P_TRANSFER);
        vm.startPrank(rich_user, rich_user);
        testCaseToken.transfer(user1, 39_000 * ATTO);
        testCaseToken.transfer(user1, 999 * ATTO);
        /// now violate the rule and ensure revert
        vm.expectRevert(0x009da0ce);
        testCaseToken.transfer(user1, 1 * ATTO);
        assertEq(testCaseToken.balanceOf(user1), 39_999 * ATTO);
    }

    function testERC20_ERC20CommonTests_TokenMaxTradingVolumeWithSupplySet_Transfer_Pruning() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxTradingVolumeWithSupplySetSetup(ActionTypes.P2P_TRANSFER);
        vm.startPrank(rich_user, rich_user);
        testCaseToken.transfer(user1, 39_000 * ATTO);
        testCaseToken.transfer(user1, 999 * ATTO);
        /// now violate the rule and ensure revert
        vm.expectRevert(0x009da0ce);
        testCaseToken.transfer(user1, 1 * ATTO);
        assertEq(testCaseToken.balanceOf(user1), 39_999 * ATTO);
        /// Now, we deactivate and reactivate the rule and try again
        switchToRuleAdmin();
        // check the event emission when deactivating
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationHandlerActionDeactivated(TOKEN_MAX_TRADING_VOLUME, _createActionsArray(ActionTypes.P2P_TRANSFER), 0);
        ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).activateTokenMaxTradingVolume(createActionTypeArray(ActionTypes.P2P_TRANSFER), false);
        // check the event emission when activating
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationHandlerActionActivated(TOKEN_MAX_TRADING_VOLUME, _createActionsArray(ActionTypes.P2P_TRANSFER), 0);
        ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).activateTokenMaxTradingVolume(createActionTypeArray(ActionTypes.P2P_TRANSFER), true);
        vm.startPrank(rich_user, rich_user);
        testCaseToken.transfer(user1, 1 * ATTO);
        assertEq(testCaseToken.balanceOf(user1), 40_000 * ATTO);
    }

    function testERC20_ERC20CommonTests_TokenMaxTradingVolumeWithSupplySet_Transfer_Update_Pruning() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxTradingVolumeWithSupplySetSetup(ActionTypes.P2P_TRANSFER);
        vm.startPrank(rich_user, rich_user);
        testCaseToken.transfer(user1, 39_000 * ATTO);
        testCaseToken.transfer(user1, 999 * ATTO);
        /// now violate the rule and ensure revert
        vm.expectRevert(0x009da0ce);
        testCaseToken.transfer(user1, 1 * ATTO);
        assertEq(testCaseToken.balanceOf(user1), 39_999 * ATTO);
        /// Now, we deactivate and reactivate the rule and try again
        switchToRuleAdmin();
        uint32 ruleId = createTokenMaxTradingVolumeRule(4000, 2, Blocktime, 100_000 * ATTO);
        setTokenMaxTradingVolumeRuleSingleAction(ActionTypes.P2P_TRANSFER, address(applicationCoinHandler), ruleId);
        vm.startPrank(rich_user, rich_user);
        testCaseToken.transfer(user1, 1 * ATTO);
        assertEq(testCaseToken.balanceOf(user1), 40_000 * ATTO);
    }

    function testERC20_ERC20CommonTests_TokenMaxTradingVolumeWithSupplySet_Mint_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxTradingVolumeWithSupplySetSetup(ActionTypes.MINT);
        vm.startPrank(rich_user, rich_user);
        /// make sure that transfer under the threshold works
        testCaseToken.transfer(user1, 39_000 * ATTO);
        assertEq(testCaseToken.balanceOf(user1), 39_000 * ATTO);
        /// now take it right up to the threshold(39,999)
        UtilApplicationERC20(address(testCaseToken)).mint(user1, 999 * ATTO);
    }

    function testERC20_ERC20CommonTests_TokenMaxTradingVolumeWithSupplySet_Mint_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxTradingVolumeWithSupplySetSetup(ActionTypes.MINT);
        vm.startPrank(rich_user, rich_user);
        /// make sure that transfer under the threshold works
        testCaseToken.transfer(user1, 39_000 * ATTO);
        assertEq(testCaseToken.balanceOf(user1), 39_000 * ATTO);
        vm.expectRevert(abi.encodeWithSignature("OverMaxTradingVolume()"));
        UtilApplicationERC20(address(testCaseToken)).mint(user1, 40_000 * ATTO);
    }

    function testERC20_ERC20CommonTests_TokenMaxTradingVolumeWithSupplySet_Buy_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _tokenMaxTradingVolumeWithSupplySetSetup(ActionTypes.BUY);
        vm.startPrank(rich_user, rich_user);
        /// make sure that transfer under the threshold works
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 50000);
        /// this one is within the limit and should pass
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 5 * ATTO, true);
    }

        function testERC20_ERC20CommonTests_TokenMaxTradingVolumeWithSupplySet_Buy_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _tokenMaxTradingVolumeWithSupplySetSetup(ActionTypes.BUY);
        vm.startPrank(rich_user, rich_user);
        /// make sure that transfer under the threshold works
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 50000);
        vm.expectRevert(abi.encodeWithSignature("OverMaxTradingVolume()"));
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 10, 40_000 * ATTO, true);
    }

    function testERC20_ERC20CommonTests_TokenMaxTradingVolumeWithSupplySet_Sell_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _tokenMaxTradingVolumeWithSupplySetSetup(ActionTypes.SELL);
        vm.startPrank(rich_user, rich_user);
        /// make sure that transfer under the threshold works
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 50000);
        /// this one is within the limit and should pass
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 5 * ATTO, 10,  true);
    }

        function testERC20_ERC20CommonTests_TokenMaxTradingVolumeWithSupplySet_Sell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        DummyAMM amm = _tokenMaxTradingVolumeWithSupplySetSetup(ActionTypes.SELL);
        vm.startPrank(rich_user, rich_user);
        /// make sure that transfer under the threshold works
        testCaseToken.approve(address(amm), 40000 * ATTO);
        applicationCoin2.approve(address(amm), 50000);
        vm.expectRevert(abi.encodeWithSignature("OverMaxTradingVolume()"));
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 40_000 * ATTO, 10, true);
    }

    function testERC20_ERC20CommonTests_TokenMaxTradingVolumeWithSupplySet_Period() public endWithStopPrank ifDeploymentTestsEnabled {
        _tokenMaxTradingVolumeWithSupplySetSetup(ActionTypes.P2P_TRANSFER);
        vm.startPrank(rich_user, rich_user);
        testCaseToken.transfer(user1, 39_000 * ATTO);
        testCaseToken.transfer(user1, 999 * ATTO);
        /// now move a little over 2 hours into the future to make sure the next block will work
        vm.warp(Blocktime + 121 minutes);
        testCaseToken.transfer(user1, 1 * ATTO);
        assertEq(testCaseToken.balanceOf(user1), 40_000 * ATTO);
        /// now violate the rule in this block and ensure revert
        vm.expectRevert(0x009da0ce);
        testCaseToken.transfer(user1, 39_999 * ATTO);
        assertEq(testCaseToken.balanceOf(user1), 40_000 * ATTO);
    }

    /// Account Max Sell Size Tests
    function testERC20_ERC20CommonTests_AccountMaxTradeSizeSell_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 50000);
        _setupAccountMaxTradeSizeSell();
        /// Swap that passes rule check
        vm.startPrank(user1, user1);
        /// Approve transfer(1M)
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 500, 500, true);
    }

    /// Account Max Sell Size test to ensure data is properly pruned 
    function testERC20_ERC20CommonTests_AccountMaxTradeSizeSell_Pruning() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 50000);
        _setupAccountMaxTradeSizeSell();
        vm.warp(block.timestamp + 1);
        // This one will pass so we know it is good
        vm.startPrank(user1, user1);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 500, 500, true);
        /// This one violates the rule
        vm.expectRevert(0x523976c2);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 500, 500, true);
        vm.warp(block.timestamp + 1);
        /// Now, we deactivate and reactivate the rule and try again
        switchToRuleAdmin();
        // check the event emission when deactivating
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationHandlerActionDeactivated(ACCOUNT_MAX_TRADE_SIZE, _createActionsArray(ActionTypes.SELL), 0);
        TradingRuleFacet(address(applicationCoinHandler)).activateAccountMaxTradeSize(createActionTypeArray(ActionTypes.SELL), false);
        // check the event emission when activating
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationHandlerActionActivated(ACCOUNT_MAX_TRADE_SIZE, _createActionsArray(ActionTypes.SELL), 0);
        TradingRuleFacet(address(applicationCoinHandler)).activateAccountMaxTradeSize(createActionTypeArray(ActionTypes.SELL), true);
        vm.warp(block.timestamp + 1);
        vm.startPrank(user1, user1);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 500, 500, true);
    }

    /// Account Max Sell Size test to ensure data is properly pruned 
    function testERC20_ERC20CommonTests_AccountMaxTradeSizeSell_Update_Pruning() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 50000);
        _setupAccountMaxTradeSizeSell();
        vm.warp(block.timestamp + 1);
        // This one will pass so we know it is good
        vm.startPrank(user1, user1);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 500, 500, true);
        vm.warp(block.timestamp + 1);
        /// This one violates the rule
        vm.expectRevert(0x523976c2);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 500, 500, true);
        vm.warp(block.timestamp + 1);
        /// Now, we deactivate and reactivate the rule and try again
        switchToRuleAdmin();
        _setupAccountMaxTradeSizeSell();
        vm.warp(block.timestamp + 1);
        vm.startPrank(user1, user1);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 500, 500, true);
    }

    /// Account Max Sell Size test to ensure data is properly pruned 
    function testERC20_ERC20CommonTests_AccountMaxTradeSizeBuy_Pruning() public endWithStopPrank ifDeploymentTestsEnabled {
        vm.warp(Blocktime);
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        vm.startPrank(user1, user1);
        applicationCoin2.approve(address(amm), 50000);
        _setupAccountMaxTradeSizeBuyRuleBlankTag();
        vm.warp(Blocktime+1);
        vm.startPrank(user1, user1);
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 500, 500, true);
        vm.warp(Blocktime+2);
        /// Swap that fails
        vm.expectRevert(0x523976c2);
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 500, 500, true);
        /// Now, we deactivate and reactivate the rule and try again
        switchToRuleAdmin();
        // check the event emission when deactivating
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationHandlerActionDeactivated(ACCOUNT_MAX_TRADE_SIZE, createActionTypeArray(ActionTypes.BUY, ActionTypes.SELL), 0);
        TradingRuleFacet(address(applicationCoinHandler)).activateAccountMaxTradeSize(createActionTypeArray(ActionTypes.BUY, ActionTypes.SELL), false);
        // check the event emission when activating
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationHandlerActionActivated(ACCOUNT_MAX_TRADE_SIZE, createActionTypeArray(ActionTypes.BUY, ActionTypes.SELL), 0);
        TradingRuleFacet(address(applicationCoinHandler)).activateAccountMaxTradeSize(createActionTypeArray(ActionTypes.BUY, ActionTypes.SELL), true);
        vm.warp(Blocktime+3);
        vm.startPrank(user1, user1);
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 500, 500, true);
    }
    
    function testERC20_ERC20CommonTests_AccountMaxTradeSizeSell_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 50000);
        _setupAccountMaxTradeSizeSell();
        vm.startPrank(user1, user1);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 500, 500, true);
        /// Swap that fails
        vm.expectRevert(0x523976c2);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 500, 500, true);
    }

    function testERC20_ERC20CommonTests_AccountMaxTradeSizeSell_BlankTag_Passes() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 50000);
        _setupAccountMaxTradeSizeSellBlankTag();
        /// Swap that passes rule check
        vm.startPrank(user1, user1);
        /// Approve transfer(1M)
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 500, 500, true);
    }

    function testERC20_ERC20CommonTests_AccountMaxTradeSizeSell_BlankTag_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 50000);
        _setupAccountMaxTradeSizeSellBlankTag();
        vm.startPrank(user1, user1);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 500, 500, true);
        /// Swap that fails
        vm.expectRevert(0x523976c2);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 500, 500, true);
    }

    // Account Max Buy Size Tests
    function testERC20_ERC20CommonTests_AccountMaxTradeSizeBuyRule_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        vm.startPrank(user1, user1);
        applicationCoin2.approve(address(amm), 50000);
        _setupAccountMaxTradeSizeBuyRule();
        /// Swap that passes rule check
        vm.startPrank(user1, user1);
        /// Approve transfer(1M)
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 500, 500, true);
    }

    function testERC20_ERC20CommonTests_AccountMaxTradeSizeBuyRule_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        vm.startPrank(user1, user1);
        applicationCoin2.approve(address(amm), 50000);
        _setupAccountMaxTradeSizeBuyRule();
        vm.startPrank(user1, user1);
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 500, 500, true);
        /// Swap that fails
        vm.expectRevert(0x523976c2);
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 500, 500, true);
    }

    function testERC20_ERC20CommonTests_AccountMaxTradeSizeRuleInvalidAction_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.MINT);
        uint32 ruleId = createAccountMaxTradeSizeRule("", 600, 36);
        switchToRuleAdmin();
        vm.expectRevert("Action Validation Failed");
        TradingRuleFacet(address(applicationCoinHandler)).setAccountMaxTradeSizeId(actionTypes, ruleId);
    }

    function testERC20_ERC20CommonTests_AccountMaxTradeSizeBuyRule_BlankTag_Passes() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        vm.startPrank(user1, user1);
        applicationCoin2.approve(address(amm), 50000);
        _setupAccountMaxTradeSizeBuyRuleBlankTag();
        /// Swap that passes rule check
        vm.startPrank(user1, user1);
        /// Approve transfer(1M)
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 500, 500, true);
    }

    function testERC20_ERC20CommonTests_AccountMaxTradeSizeBuyRule_BlankTag_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        vm.warp(Blocktime);
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        vm.startPrank(user1, user1);
        applicationCoin2.approve(address(amm), 50000);
        _setupAccountMaxTradeSizeBuyRuleBlankTag();
        vm.startPrank(user1, user1);
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 500, 500, true);
        /// Swap that fails
        vm.expectRevert(0x523976c2);
        amm.dummyTrade(address(applicationCoin2), address(testCaseToken), 500, 500, true);
    }

    function testERC20_ERC20CommonTests_TokenMaxBuySellVolumeRuleBuyAction_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        /// set up rule
        _setupTokenMaxBuySellVolumeRuleBuyAction();
        vm.warp(Blocktime + 36 hours);
        /// test swap below percentage
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 10000 * ATTO);
        uint256 initialCoinBalance = testCaseToken.balanceOf(user1);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 40_000_000, 40_000_000, false); /// percentage limit hit now
        assertEq(testCaseToken.balanceOf(user1), initialCoinBalance + 40_000_000);
        /// check that rule does not apply to coin 0 as this would be a sell
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 60_000_000, 60_000_000, true);
    }

    function testERC20_ERC20CommonTests_TokenMaxBuySellVolumeRuleBuyAction_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        /// set up rule
        _setupTokenMaxBuySellVolumeRuleBuyAction();
        vm.warp(Blocktime + 36 hours);
        /// test swap below percentage
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 10000 * ATTO);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 40_000_000, 40_000_000, false); /// percentage limit hit now
        /// test swaps after we hit limit
        vm.expectRevert(0xfa006f25);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10_000_000, 10_000_000, false);
        /// switch users and test rule still fails
        vm.startPrank(user2, user2);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 10000 * ATTO);
        vm.expectRevert(0xfa006f25);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10_000_000, 10_000_000, false);
    }

    function testERC20_ERC20CommonTests_TokenMaxBuySellVolumeRuleBuyAction_Pruning() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        /// set up rule
        _setupTokenMaxBuySellVolumeRuleBuyAction();
        vm.warp(Blocktime + 36 hours);
        /// test swap below percentage
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 10000 * ATTO);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 40_000_000, 40_000_000, false); /// percentage limit hit now
        /// test swaps after we hit limit
        vm.expectRevert(0xfa006f25);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10_000_000, 10_000_000, false);
        switchToRuleAdmin();
        // check the event emission when deactivating
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationHandlerActionDeactivated(TOKEN_MAX_BUY_SELL_VOLUME, createActionTypeArray(ActionTypes.SELL), 0);
        TradingRuleFacet(address(applicationCoinHandler)).activateTokenMaxBuySellVolume(createActionTypeArray(ActionTypes.SELL), false);
        // check the event emission when deactivating
        vm.expectEmit(true, true, true, true);
        emit AD1467_ApplicationHandlerActionActivated(TOKEN_MAX_BUY_SELL_VOLUME, createActionTypeArray(ActionTypes.SELL), 0);
        TradingRuleFacet(address(applicationCoinHandler)).activateTokenMaxBuySellVolume(createActionTypeArray(ActionTypes.SELL), true);
        // with all data reset, it should work
        vm.startPrank(user1, user1);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10_000_000, 10_000_000, false);
    }

    function testERC20_ERC20CommonTests_TokenMaxBuySellVolumeRuleBuyAction_Update_Pruning() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        /// set up rule
        _setupTokenMaxBuySellVolumeRuleBuyAction();
        vm.warp(Blocktime + 36 hours);
        /// test swap below percentage
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 10000 * ATTO);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 40_000_000, 40_000_000, false); /// percentage limit hit now
        /// test swaps after we hit limit
        vm.expectRevert(0xfa006f25);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10_000_000, 10_000_000, false);
        switchToRuleAdmin();
        _setupTokenMaxBuySellVolumeRuleBuyAction();
        // with all data reset, it should work
        vm.startPrank(user1, user1);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10_000_000, 10_000_000, false);
    }

    function testERC20_ERC20CommonTests_TokenMaxBuySellVolumeRule_Period() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        /// set up rule
        _setupTokenMaxBuySellVolumeRuleBuyAction();
        vm.warp(Blocktime + 36 hours);
        /// test swap below percentage
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 10000 * ATTO);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 40_000_000, 40_000_000, false); /// percentage limit hit now
        /// wait until new period
        vm.warp(Blocktime + 36 hours + 30 hours);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10_000_000, 10_000_000, false);
    }

    function testERC20_ERC20CommonTests_TokenMaxBuySellVolumeRule_NewRule() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        /// Low percentage rule checks
        switchToRuleAdmin();
        /// create new rule
        _setupTokenMaxBuySellVolumeRuleBuyActionB();
        vm.warp(Blocktime + 96 hours);
        /// test swap below percentage
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 10000 * ATTO);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 1, 1, false);

        vm.expectRevert(0xfa006f25);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 9, 9, false);
    }

    function testERC20_ERC20CommonTests_TokenMaxBuySellVolumeRuleSellAction_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        /// set up rule
        _setupTokenMaxBuySellVolumeRuleSellAction();
        vm.warp(Blocktime + 36 hours);
        /// test swap below percentage
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 10000 * ATTO);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 40_000_000, 40_000_000, true); /// percentage limit hit now
    }

    function testERC20_ERC20CommonTests_TokenMaxBuySellVolumeRuleSellAction_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        /// set up rule
        _setupTokenMaxBuySellVolumeRuleSellAction();
        vm.warp(Blocktime + 36 hours);
        /// test swap below percentage
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 10000 * ATTO);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 40_000_000, 40_000_000, true); /// percentage limit hit now
        /// test swaps after we hit limit
        vm.expectRevert(0xfa006f25);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10_000_000, 10_000_000, true);
        /// switch users and test rule still fails
        vm.startPrank(user2, user2);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 10000 * ATTO);
        vm.expectRevert(0xfa006f25);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10_000_000, 10_000_000, true);
    }

    function testERC20_ERC20CommonTests_TokenMaxBuySellVolumeRuleSellAction_Period() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        /// set up rule
        _setupTokenMaxBuySellVolumeRuleSellAction();
        vm.warp(Blocktime + 36 hours);
        /// test swap below percentage
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 10000 * ATTO);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 40_000_000, 40_000_000, true); /// percentage limit hit now
        /// wait until new period
        vm.warp(Blocktime + 36 hours + 30 hours);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10_000_000, 10_000_000, true);

        /// check that rule does not apply to coin 0 as this would be a sell
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 60_000_000, 60_000_000, false);
    }
    /**
     * In order to test the accumulator logic, set up the rule then perform a buy that puts the rule at the line of threshold. Then, attempt a sell that would put it over. If it does not go over, then the accumulator data is separated properly. 
     */
    function testERC20_ERC20CommonTests_TokenMaxBuySellVolumeRuleBuyAction_AccumulatorCheck_Buy() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        /// set up rule
        _setupTokenMaxBuySellVolumeRuleBuyAction();
        vm.warp(Blocktime + 36 hours);
        /// test swap below percentage
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 10000 * ATTO);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 40_000_000, 40_000_000, false); /// percentage limit hit now
        /// test swaps after we hit limit. This verifies the failure
        vm.expectRevert(0xfa006f25);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10_000_000, 10_000_000, false);
        /// Now check that rule does not apply to coin 0 as this would be a sell
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 60_000_000, 60_000_000, true);
    }

    /**
     * In order to test the accumulator logic, set up the rule then perform a sell that puts the rule at the line of threshold. Then, attempt a buy that would put it over. If it does not go over, then the accumulator data is separated properly. 
     */
    function testERC20_ERC20CommonTests_TokenMaxBuySellVolumeRuleBuyAction_AccumulatorCheck_Sell() public endWithStopPrank ifDeploymentTestsEnabled {
         switchToAppAdministrator();
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = _tradeRuleSetup();
        /// set up rule
        _setupTokenMaxBuySellVolumeRuleSellAction();
        vm.warp(Blocktime + 36 hours);
        /// test swap below percentage
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 10000 * ATTO);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 40_000_000, 40_000_000, true); /// percentage limit hit now
        /// Now check that rule does not apply to coin 1 as this would be a buy
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 10_000_000, 10_000_000, false);
    }

    function testERC20_ERC20CommonTests_TradeRuleByPasserRule_BuySellPercentage_Allowed() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        DummyAMM amm = _tradeRuleSetup();
        applicationAppManager.approveAddressToTradingRuleAllowlist(user1, true);

        /// SELL PERCENTAGE RULE
        _setupTokenMaxBuySellVolumeRuleSellAction();
        vm.warp(Blocktime + 36 hours);
        /// ALLOWLISTED USER
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 10000 * ATTO);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 60_000_000, 60_000_000, true);
    }

    function testERC20_ERC20CommonTests_TradeRuleByPasserRule_BuySellPercentageSellAction_NotAllowed() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        DummyAMM amm = _tradeRuleSetup();
        applicationAppManager.approveAddressToTradingRuleAllowlist(user1, true);

        /// SELL PERCENTAGE RULE
        _setupTokenMaxBuySellVolumeRuleSellAction();
        vm.warp(Blocktime + 36 hours);
        /// NOT ALLOWLISTED USER
        vm.startPrank(user2, user2);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 10000 * ATTO);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 40_000_000, 40_000_000, true);
        vm.expectRevert(0xfa006f25);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 20_000_000, 20_000_000, true);
    }

    function testERC20_ERC20CommonTests_TradeRuleByPasserRule_BuyPercentage_Allowed() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        DummyAMM amm = _tradeRuleSetup();
        applicationAppManager.approveAddressToTradingRuleAllowlist(user1, true);
        //BUY PERCENTAGE RULE
        _setupTokenMaxBuySellVolumeRuleBuyAction();
        vm.warp(Blocktime + 36 hours);
        /// ALLOWLISTED USER
        vm.startPrank(user1, user1);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 10000 * ATTO);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 60_000_000, 60_000_000, false);
    }

    function testERC20_ERC20CommonTests_TradeRuleByPasserRule_BuySellPercentage_NotAllowed() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        DummyAMM amm = _tradeRuleSetup();
        applicationAppManager.approveAddressToTradingRuleAllowlist(user1, true);
        _setupTokenMaxBuySellVolumeRuleBuyAction();
        vm.warp(Blocktime + 36 hours);
        /// NOT ALLOWLISTED USER
        vm.startPrank(user2, user2);
        testCaseToken.approve(address(amm), 10000 * ATTO);
        applicationCoin2.approve(address(amm), 10000 * ATTO);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 30_000_000, 30_000_000, false);
        vm.expectRevert(0xfa006f25);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 30_000_000, 30_000_000, false);
    }

    function testERC20_ERC20CommonTests_TradeRuleByPasserRule_SellPercentage() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        DummyAMM amm = _tradeRuleSetup();
        applicationAppManager.approveAddressToTradingRuleAllowlist(user1, true);
        /// SELL RULE
        _setupAccountMaxTradeSizeSell();
        vm.startPrank(user1, user1);
        /// Approve transfer(1M)
        testCaseToken.approve(address(amm), 50000);
        applicationCoin2.approve(address(amm), 50000);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 500, 500, true);
        amm.dummyTrade(address(testCaseToken), address(applicationCoin2), 500, 500, true);
    }

    /*********************** Atomic Rule Setting Tests ************************************/
    /* These tests ensure that the atomic setting/application of rules is functioning properly */

    /* MinMaxTokenBalance */
    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalanceAtomicFullSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](5);
        bytes32[5] memory tags = [bytes32("Oscar"), bytes32("RJ"), bytes32("Tayler"), bytes32("Michael"), bytes32("Michael")];
        for (uint i; i < ruleIds.length; i++) createAccountMinMaxTokenBalanceRule(createBytes32Array(tags[i]), createUint256Array(i + 1), createUint256Array((i + 1) * 1000));

        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BUY, ActionTypes.MINT, ActionTypes.BURN);
        // Apply the rules to all actions
        setAccountMinMaxTokenBalanceRuleFull(address(applicationCoinHandler), actions, ruleIds);
        // Verify that all the rule id's were set correctly
        assertEq(ERC20TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.P2P_TRANSFER), ruleIds[0]);
        assertEq(ERC20TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.SELL), ruleIds[1]);
        assertEq(ERC20TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.BUY), ruleIds[2]);
        assertEq(ERC20TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.MINT), ruleIds[3]);
        assertEq(ERC20TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.BURN), ruleIds[4]);
        // Verify that all the rules were activated
        for (uint i; i < 5; i++) assertTrue(ERC20TaggedRuleFacet(address(applicationCoinHandler)).isAccountMinMaxTokenBalanceActive(ActionTypes(i)));
    }

    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalanceAtomicFullReSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](5);
        bytes32[5] memory tags = [bytes32("Oscar"), bytes32("RJ"), bytes32("Tayler"), bytes32("Michael"), bytes32("Michael")];
        for (uint i; i < ruleIds.length; i++) createAccountMinMaxTokenBalanceRule(createBytes32Array(tags[i]), createUint256Array(i + 1), createUint256Array((i + 1) * 1000));
        // Set up rule
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
        assertEq(ERC20TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.SELL), ruleIds[0]);
        assertEq(ERC20TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.BUY), ruleIds[1]);
        // Verify that the old ones were cleared
        assertEq(ERC20TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.P2P_TRANSFER), 0);
        assertEq(ERC20TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.MINT), 0);
        assertEq(ERC20TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(ActionTypes.BURN), 0);
        // Verify that the new rules were activated
        assertTrue(ERC20TaggedRuleFacet(address(applicationCoinHandler)).isAccountMinMaxTokenBalanceActive(ActionTypes.SELL));
        assertTrue(ERC20TaggedRuleFacet(address(applicationCoinHandler)).isAccountMinMaxTokenBalanceActive(ActionTypes.BUY));
        // Verify that the old rules are not activated
        assertFalse(ERC20TaggedRuleFacet(address(applicationCoinHandler)).isAccountMinMaxTokenBalanceActive(ActionTypes.P2P_TRANSFER));
        assertFalse(ERC20TaggedRuleFacet(address(applicationCoinHandler)).isAccountMinMaxTokenBalanceActive(ActionTypes.MINT));
        assertFalse(ERC20TaggedRuleFacet(address(applicationCoinHandler)).isAccountMinMaxTokenBalanceActive(ActionTypes.BURN));
    }

    function testERC20_ERC20CommonTests_AccountMinMaxTokenBalanceAtomicFull_ZeroLengthActions() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](5);
        bytes32[5] memory tags = [bytes32("Shane"), bytes32("RJ"), bytes32("Tayler"), bytes32("Michael"), bytes32("Gordon")];
        for (uint i; i < ruleIds.length; i++) createAccountMinMaxTokenBalanceRule(createBytes32Array(tags[i]), createUint256Array(i + 1), createUint256Array((i + 1) * 1000));
        
        // Set up rules
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BUY, ActionTypes.MINT, ActionTypes.BURN);
        
        // Apply the rules to all actions
        setAccountMinMaxTokenBalanceRuleFull(address(applicationCoinHandler), actions, ruleIds);

        // Verify that all the rule id's were set correctly and actions activated
        for (uint i; i < ruleIds.length; ++i) {
            assertEq(ERC20TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(actions[i]), ruleIds[i]);
            assertTrue(ERC20TaggedRuleFacet(address(applicationCoinHandler)).isAccountMinMaxTokenBalanceActive(actions[i]));
        }
        
        // Create zero length arrays
        ActionTypes[] memory actionsZero = new ActionTypes[](0);
        uint32[] memory ruleIdsZero = new uint32[](0);

        // Clear the rule data with zero length actions array
        setAccountMinMaxTokenBalanceRuleFull(address(applicationCoinHandler), actionsZero, ruleIdsZero);

        // Verify that the old rules were cleared correctly and actions deactivated
        for (uint i; i < ruleIds.length; ++i) {
            assertEq(ERC20TaggedRuleFacet(address(applicationCoinHandler)).getAccountMinMaxTokenBalanceId(actions[i]), 0);
            assertFalse(ERC20TaggedRuleFacet(address(applicationCoinHandler)).isAccountMinMaxTokenBalanceActive(actions[i]));
        }
    }

    /* AccountMaxTradeSize */
    function testERC20_ERC20CommonTests_AccountMaxTradeSizeAtomicFullSetSell() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](1);
        // Set up rule(This one is different because it can only apply to buys)
        ruleIds[0] = createAccountMaxTradeSizeRule("Oscar", 1, 1);
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.SELL);
        // Apply the rules to all actions
        setAccountMaxTradeSizeRule(address(applicationCoinHandler), actionTypes, ruleIds[0]);
        // Verify that all the rule id's were set correctly
        assertEq(TradingRuleFacet(address(applicationCoinHandler)).getAccountMaxTradeSizeId(ActionTypes.SELL), ruleIds[0]);
        // Verify that all the rules were activated
        assertTrue(TradingRuleFacet(address(applicationCoinHandler)).isAccountMaxTradeSizeActive(ActionTypes.SELL));
    }

    function testERC20_ERC20CommonTests_AccountMaxTradeSizeAtomicFullReSetBuy() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32 ruleId = createAccountMaxTradeSizeRule("Oscar", 100, 5);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.BUY);
        // Apply the rules to all actions
        ruleId = createAccountMaxTradeSizeRule("Oscar", 100, 5);
        setAccountMaxTradeSizeRule(address(applicationCoinHandler), actions, ruleId);
        // Verify that all the rule id's were set correctly
        assertEq(TradingRuleFacet(address(applicationCoinHandler)).getAccountMaxTradeSizeId(ActionTypes.BUY), ruleId);
        // Verify that all the rule id's were set correctly
        assertEq(TradingRuleFacet(address(applicationCoinHandler)).getAccountMaxTradeSizeId(ActionTypes.BUY), ruleId);
        // Verify that the new rules were activated
        assertTrue(TradingRuleFacet(address(applicationCoinHandler)).isAccountMaxTradeSizeActive(ActionTypes.BUY));
    }

    /* AccountMaxTradeSize */
    function testERC20_ERC20CommonTests_AccountMaxTradeSizeAtomicFullSetBuy() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](1);
        // Set up rule(This one is different because it can only apply to buys)
        ruleIds[0] = createAccountMaxTradeSizeRule("Oscar", 1, 1);
        // Apply the rules to all actions
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.BUY);
        setAccountMaxTradeSizeRule(address(applicationCoinHandler), actionTypes, ruleIds[0]);
        // Verify that all the rule id's were set correctly
        assertEq(TradingRuleFacet(address(applicationCoinHandler)).getAccountMaxTradeSizeId(ActionTypes.BUY), ruleIds[0]);
        // Verify that all the rules were activated
        assertTrue(TradingRuleFacet(address(applicationCoinHandler)).isAccountMaxTradeSizeActive(ActionTypes.BUY));
    }

    function testERC20_ERC20CommonTests_AccountMaxTradeSizeAtomicFullReSetSell() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32 ruleId = createAccountMaxTradeSizeRule("Oscar", 100, 5);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.BUY);
        setAccountMaxTradeSizeRule(address(applicationCoinHandler), actions, ruleId);
        // Apply the rules to all actions
        ruleId = createAccountMaxTradeSizeRule("Oscar", 200, 5);
        // Apply the new set of rules
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.SELL);
        setAccountMaxTradeSizeRule(address(applicationCoinHandler), actionTypes, ruleId);
        // Verify that all the rule id's were set correctly
        assertEq(TradingRuleFacet(address(applicationCoinHandler)).getAccountMaxTradeSizeId(ActionTypes.SELL), ruleId);
        // Verify that the new rules were activated
        assertTrue(TradingRuleFacet(address(applicationCoinHandler)).isAccountMaxTradeSizeActive(ActionTypes.SELL));
    }

    function testERC20_ERC20CommonTests_AccountMaxTradeSizeAtomicFull_ZeroLengthActions() public endWithStopPrank ifDeploymentTestsEnabled {
        // Create rules
        uint32[] memory ruleIds = new uint32[](2);
        ruleIds[0] = createAccountMaxTradeSizeRule("Gordon", 100, 5);
        ruleIds[1] = createAccountMaxTradeSizeRule("Tayler", 200, 5);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.SELL, ActionTypes.BUY);

        // Apply rules
        setAccountMaxTradeSizeIdFull(address(applicationCoinHandler), actions, ruleIds);

        // Verify that all the rule id's were set correctly and actions activated
        for (uint i; i < ruleIds.length; ++i) {
            assertEq(TradingRuleFacet(address(applicationCoinHandler)).getAccountMaxTradeSizeId(actions[i]), ruleIds[i]);
            assertTrue(TradingRuleFacet(address(applicationCoinHandler)).isAccountMaxTradeSizeActive(actions[i]));
        }

        // Create zero length arrays
        ActionTypes[] memory actionsZero = new ActionTypes[](0);
        uint32[] memory ruleIdsZero = new uint32[](0);

        // Apply new zero length rules
        setAccountMaxTradeSizeIdFull(address(applicationCoinHandler), actionsZero, ruleIdsZero);

        // Verify that all the rule id's were cleared correctly and actions deactivated
        for (uint i; i < ruleIds.length; ++i) {
            assertEq(TradingRuleFacet(address(applicationCoinHandler)).getAccountMaxTradeSizeId(actions[i]), 0);
            assertFalse(TradingRuleFacet(address(applicationCoinHandler)).isAccountMaxTradeSizeActive(actions[i]));
        }
    }

    function testERC20_ERC20CommonTests_TokenMaxBuySellVolumeBuyActionAtomicFullReSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32 ruleId = createTokenMaxBuySellVolumeRule(10, 24, 0, Blocktime);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.BUY);
        setTokenMaxBuySellVolumeRule(address(applicationCoinHandler), actions, ruleId);
        // Apply the rules to all actions
        ruleId = createTokenMaxBuySellVolumeRule(10, 48, 0, Blocktime);
        actions = createActionTypeArray(ActionTypes.BUY);
        // Apply the new set of rules
        setTokenMaxBuySellVolumeRule(address(applicationCoinHandler), actions, ruleId);
        // Verify that all the rule id's were set correctly
        assertEq(TradingRuleFacet(address(applicationCoinHandler)).getTokenMaxBuySellVolumeId(ActionTypes.BUY), ruleId);
        // Verify that the new rules were activated
        assertTrue(TradingRuleFacet(address(applicationCoinHandler)).isTokenMaxBuySellVolumeActive(ActionTypes.BUY));
    }

    /* TokenMaxBuySellVolume */
    function testERC20_ERC20CommonTests_TokenMaxBuySellVolumeAtomicFullSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32 ruleId = createTokenMaxBuySellVolumeRule(10, 48, 0, Blocktime);
        // Apply the rules to all actions
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.BUY);
        setTokenMaxBuySellVolumeRule(address(applicationCoinHandler), actions, ruleId);
        // Verify that all the rule id's were set correctly
        assertEq(TradingRuleFacet(address(applicationCoinHandler)).getTokenMaxBuySellVolumeId(ActionTypes.BUY), ruleId);
        // Verify that all the rules were activated
        assertTrue(TradingRuleFacet(address(applicationCoinHandler)).isTokenMaxBuySellVolumeActive(ActionTypes.BUY));
    }

    function testERC20_ERC20CommonTests_TokenMaxBuySellVolumeAtomicFull_ZeroLengthActions() public endWithStopPrank ifDeploymentTestsEnabled {
        // Create rules
        uint32[] memory ruleIds = new uint32[](2);
        ruleIds[0] = createTokenMaxBuySellVolumeRule(10, 48, 0, Blocktime);
        ruleIds[1] = createTokenMaxBuySellVolumeRule(20, 68, 0, Blocktime);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.BUY, ActionTypes.SELL);

        // Apply rules
        setTokenMaxBuySellVolumeIdFull(address(applicationCoinHandler), actions, ruleIds);

        // Verify that all the rule id's were set correctly and actions activated
        for (uint i; i < ruleIds.length; ++i) {
            assertEq(TradingRuleFacet(address(applicationCoinHandler)).getTokenMaxBuySellVolumeId(actions[i]), ruleIds[i]);
            assertTrue(TradingRuleFacet(address(applicationCoinHandler)).isTokenMaxBuySellVolumeActive(actions[i]));
        }

        // Create zero length arrays
        uint32[] memory ruleIdsZero = new uint32[](0);
        ActionTypes[] memory actionsZero = new ActionTypes[](0);

        // Apply new zero length rules
        setTokenMaxBuySellVolumeIdFull(address(applicationCoinHandler), actionsZero, ruleIdsZero);

        // Verify that all the rule id's were cleared correctly and actions deactivated
        for (uint i; i < ruleIds.length; ++i) {
            assertEq(TradingRuleFacet(address(applicationCoinHandler)).getTokenMaxBuySellVolumeId(actions[i]), 0);
            assertFalse(TradingRuleFacet(address(applicationCoinHandler)).isTokenMaxBuySellVolumeActive(actions[i]));
        }
    }

    function testERC20_ERC20CommonTests_TokenMaxBuySellVolumeAtomicFullReSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32 ruleId = createTokenMaxBuySellVolumeRule(10, 24, 0, Blocktime);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.BUY);
        setTokenMaxBuySellVolumeRule(address(applicationCoinHandler), actions, ruleId);
        // Apply the rules to all actions
        ruleId = createTokenMaxBuySellVolumeRule(10, 48, 0, Blocktime);
        // Apply the new set of rules
        setTokenMaxBuySellVolumeRule(address(applicationCoinHandler), actions, ruleId);
        // Verify that all the rule id's were set correctly
        assertEq(TradingRuleFacet(address(applicationCoinHandler)).getTokenMaxBuySellVolumeId(ActionTypes.BUY), ruleId);
        // Verify that the new rules were activated
        assertTrue(TradingRuleFacet(address(applicationCoinHandler)).isTokenMaxBuySellVolumeActive(ActionTypes.BUY));
    }

    /* AccountApproveDenyOracle */
    function testERC20_ERC20CommonTests_AccountApproveDenyOracleAtomicFullSet() public endWithStopPrank ifDeploymentTestsEnabled {
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
        setAccountApproveDenyOracleRuleFull(address(applicationCoinHandler), actions, ruleIds);
        // Verify that all the rule id's were set correctly and are active(Had to go old school with control break logic)
        mainIndex = 0;
        uint256 internalIndex;
        ActionTypes lastAction;
        for (uint i; i < 5; i++) {
            if (actions[mainIndex] != lastAction) {
                internalIndex = 0;
            }
            for (uint j; j < 5; j++) {
                assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getAccountApproveDenyOracleIds(actions[mainIndex])[internalIndex], ruleIds[mainIndex]);
                assertTrue(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).isAccountApproveDenyOracleActive(actions[mainIndex], ruleIds[mainIndex]));
                lastAction = actions[mainIndex];
                internalIndex++;
                mainIndex++;
            }
        }
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleAtomicFullReSet() public endWithStopPrank ifDeploymentTestsEnabled {
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
        setAccountApproveDenyOracleRuleFull(address(applicationCoinHandler), actions, ruleIds);
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
        setAccountApproveDenyOracleRuleFull(address(applicationCoinHandler), actions2, ruleIds2);
        // Verify that all the rule id's were set correctly and are active(Had to go old school with control break logic)
        mainIndex = 0;
        uint256 internalIndex;
        ActionTypes lastAction;
        for (uint i; i < 3; i++) {
            if (actions2[mainIndex] != lastAction) {
                internalIndex = 0;
            }
            for (uint j; j < 8; j++) {
                assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getAccountApproveDenyOracleIds(actions2[mainIndex])[internalIndex], ruleIds2[mainIndex]);
                assertTrue(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).isAccountApproveDenyOracleActive(actions2[mainIndex], ruleIds2[mainIndex]));
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
                uint32[] memory ruleIds3 = ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getAccountApproveDenyOracleIds(actions[mainIndex]);
                // If a value was returned it must not match a previous rule
                if (ruleIds3.length > 0) {
                    assertFalse(ruleIds3[internalIndex] == ruleIds[mainIndex]);
                }
                assertFalse(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).isAccountApproveDenyOracleActive(actions[mainIndex], ruleIds[mainIndex]));
                lastAction = actions[mainIndex];
                internalIndex++;
                mainIndex++;
            }
        }
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleAtomicFull_ZeroLengthActions() public endWithStopPrank ifDeploymentTestsEnabled {
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
        setAccountApproveDenyOracleRuleFull(address(applicationCoinHandler), actions, ruleIds);
        
        // Verify that all the rule id's were set correctly and are active
        for (uint i; i < 5; i++) {
            assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getAccountApproveDenyOracleIds(actions[i])[i], ruleIds[i]);
            assertTrue(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).isAccountApproveDenyOracleActive(actions[i], ruleIds[i]));
        }
        // Create zero length arrays
        uint32[] memory ruleIdsZero = new uint32[](0);
        ActionTypes[] memory actionsZero = new ActionTypes[](0);

        // Apply zero length arrays
        setAccountApproveDenyOracleRuleFull(address(applicationCoinHandler), actionsZero, ruleIdsZero);

        // Verify that all the rule ids were cleared and not active
        for (uint i; i < 5; i++) {
            assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getAccountApproveDenyOracleIds(actions[i]).length, 0);
            assertFalse(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).isAccountApproveDenyOracleActive(actions[i], ruleIds[i]));
        }
    }

    /* AccountApproveDenyOracleFlexible */
    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexibleAtomicFullSet() public endWithStopPrank ifDeploymentTestsEnabled {
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
        setAccountApproveDenyOracleFlexibleRuleFull(address(applicationCoinHandler), actions, ruleIds);
        // Verify that all the rule id's were set correctly and are active(Had to go old school with control break logic)
        mainIndex = 0;
        uint256 internalIndex;
        ActionTypes lastAction;
        for (uint i; i < 5; i++) {
            if (actions[mainIndex] != lastAction) {
                internalIndex = 0;
            }
            for (uint j; j < 5; j++) {
                assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getAccountApproveDenyOracleFlexibleIds(actions[mainIndex])[internalIndex], ruleIds[mainIndex]);
                assertTrue(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).isAccountApproveDenyOracleFlexibleActive(actions[mainIndex], ruleIds[mainIndex]));
                lastAction = actions[mainIndex];
                internalIndex++;
                mainIndex++;
            }
        }
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexibleAtomicFullReSet() public endWithStopPrank ifDeploymentTestsEnabled {
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
        setAccountApproveDenyOracleFlexibleRuleFull(address(applicationCoinHandler), actions, ruleIds);
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
        setAccountApproveDenyOracleFlexibleRuleFull(address(applicationCoinHandler), actions2, ruleIds2);
        // Verify that all the rule id's were set correctly and are active(Had to go old school with control break logic)
        mainIndex = 0;
        uint256 internalIndex;
        ActionTypes lastAction;
        for (uint i; i < 3; i++) {
            if (actions2[mainIndex] != lastAction) {
                internalIndex = 0;
            }
            for (uint j; j < 8; j++) {
                assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getAccountApproveDenyOracleFlexibleIds(actions2[mainIndex])[internalIndex], ruleIds2[mainIndex]);
                assertTrue(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).isAccountApproveDenyOracleFlexibleActive(actions2[mainIndex], ruleIds2[mainIndex]));
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
                uint32[] memory ruleIds3 = ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getAccountApproveDenyOracleFlexibleIds(actions[mainIndex]);
                // If a value was returned it must not match a previous rule
                if (ruleIds3.length > 0) {
                    assertFalse(ruleIds3[internalIndex] == ruleIds[mainIndex]);
                }
                assertFalse(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).isAccountApproveDenyOracleFlexibleActive(actions[mainIndex], ruleIds[mainIndex]));
                lastAction = actions[mainIndex];
                internalIndex++;
                mainIndex++;
            }
        }
    }

    function testERC20_ERC20CommonTests_AccountApproveDenyOracleFlexibleAtomicFull_ZeroLengthActions() public endWithStopPrank ifDeploymentTestsEnabled {
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
        setAccountApproveDenyOracleFlexibleRuleFull(address(applicationCoinHandler), actions, ruleIds);
        
        // Verify that all the rule id's were set correctly and are active
        for (uint i; i < 5; i++) {
            assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getAccountApproveDenyOracleFlexibleIds(actions[i])[i], ruleIds[i]);
            assertTrue(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).isAccountApproveDenyOracleFlexibleActive(actions[i], ruleIds[i]));
        }
        // Create zero length arrays
        uint32[] memory ruleIdsZero = new uint32[](0);
        ActionTypes[] memory actionsZero = new ActionTypes[](0);

        // Apply zero length arrays
        setAccountApproveDenyOracleFlexibleRuleFull(address(applicationCoinHandler), actionsZero, ruleIdsZero);

        // Verify that all the rule ids were cleared and not active
        for (uint i; i < 5; i++) {
            assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getAccountApproveDenyOracleFlexibleIds(actions[i]).length, 0);
            assertFalse(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).isAccountApproveDenyOracleFlexibleActive(actions[i], ruleIds[i]));
        }
    }
    
    /* TokenMinimumTransaction */
    function testERC20_ERC20CommonTests_TokenMinimumTransactionAtomicFullSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](5);
        // Set up rule
        for (uint i; i < 5; i++) ruleIds[i] = createTokenMinimumTransactionRule(i + 1);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BUY, ActionTypes.MINT, ActionTypes.BURN);
        // Apply the rules to all actions
        setTokenMinimumTransactionRuleFull(address(applicationCoinHandler), actions, ruleIds);
        // Verify that all the rule id's were set correctly
        assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getTokenMinTxSizeId(ActionTypes.P2P_TRANSFER), ruleIds[0]);
        assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getTokenMinTxSizeId(ActionTypes.SELL), ruleIds[1]);
        assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getTokenMinTxSizeId(ActionTypes.BUY), ruleIds[2]);
        assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getTokenMinTxSizeId(ActionTypes.MINT), ruleIds[3]);
        assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getTokenMinTxSizeId(ActionTypes.BURN), ruleIds[4]);
        // Verify that all the rules were activated
        for (uint i; i < 5; i++) assertTrue(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).isTokenMinTxSizeActive(ActionTypes(i)));
    }

    function testERC20_ERC20CommonTests_TokenMinimumTransactionAtomicFullReSet() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](5);
        // Set up rule
        for (uint i; i < 5; i++) ruleIds[i] = createTokenMinimumTransactionRule(i + 1);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BUY, ActionTypes.MINT, ActionTypes.BURN);
        // Apply the rules to all actions
        setTokenMinimumTransactionRuleFull(address(applicationCoinHandler), actions, ruleIds);
        // Reset with a partial list of rules and insure that the changes are saved correctly
        ruleIds = new uint32[](2);
        ruleIds[0] = createTokenMinimumTransactionRule(6);
        ruleIds[1] = createTokenMinimumTransactionRule(7);
        actions = createActionTypeArray(ActionTypes.SELL, ActionTypes.BUY);
        // Apply the new set of rules
        setTokenMinimumTransactionRuleFull(address(applicationCoinHandler), actions, ruleIds);
        // Verify that all the rule id's were set correctly
        assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getTokenMinTxSizeId(ActionTypes.SELL), ruleIds[0]);
        assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getTokenMinTxSizeId(ActionTypes.BUY), ruleIds[1]);
        // Verify that the old ones were cleared
        assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getTokenMinTxSizeId(ActionTypes.P2P_TRANSFER), 0);
        assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getTokenMinTxSizeId(ActionTypes.MINT), 0);
        assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getTokenMinTxSizeId(ActionTypes.BURN), 0);
        // Verify that the new rules were activated
        assertTrue(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).isTokenMinTxSizeActive(ActionTypes.SELL));
        assertTrue(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).isTokenMinTxSizeActive(ActionTypes.BUY));
        // Verify that the old rules are not activated
        assertFalse(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).isTokenMinTxSizeActive(ActionTypes.P2P_TRANSFER));
        assertFalse(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).isTokenMinTxSizeActive(ActionTypes.MINT));
        assertFalse(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).isTokenMinTxSizeActive(ActionTypes.BURN));
    }

    function testERC20_ERC20CommonTests_TokenMinimumTransactionAtomicFull_ZeroLengthActions() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32[] memory ruleIds = new uint32[](5);
        // Set up rules
        for (uint i; i < 5; i++) ruleIds[i] = createTokenMinimumTransactionRule(i + 1);
        ActionTypes[] memory actions = createActionTypeArray(ActionTypes.P2P_TRANSFER, ActionTypes.SELL, ActionTypes.BUY, ActionTypes.MINT, ActionTypes.BURN);

        // Apply the rules to all actions
        setTokenMinimumTransactionRuleFull(address(applicationCoinHandler), actions, ruleIds);

        // Verify that all the rule id's were set correctly and actions activated
        for (uint i; i < ruleIds.length; ++i) {
            assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getTokenMinTxSizeId(actions[i]), ruleIds[i]);
            assertTrue(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).isTokenMinTxSizeActive(actions[i]));
        }
        
        // Create zero length arrays
        uint32[] memory ruleIdsZero = new uint32[](0);
        ActionTypes[] memory actionsZero = new ActionTypes[](0);

        // Apply the new zero length rules
        setTokenMinimumTransactionRuleFull(address(applicationCoinHandler), actionsZero, ruleIdsZero);

        // Verify that all the rule id's were cleared correctly and actions deacivated
        for (uint i; i < ruleIds.length; ++i) {
            assertEq(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).getTokenMinTxSizeId(actions[i]), 0);
            assertFalse(ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).isTokenMinTxSizeActive(actions[i]));
        }
    }

    function testERC20_ERC20CommonTests_Toggle_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        // set up a pause rule and make sure it works
        _pauseRuleSetup();
        vm.startPrank(user1, user1);
        bytes4 selector = bytes4(keccak256("ApplicationPaused(uint256,uint256)"));
        vm.expectRevert(abi.encodeWithSelector(selector, Blocktime + 1000, Blocktime + 1500));
        testCaseToken.transfer(user2, 1000);
        /// toggle the token and check again
        if (vm.envAddress("DEPLOYMENT_OWNER") != address(0x0)) {
            switchToSuperAdmin();
        } else {
            switchToAppAdministrator();
        }
        ApplicationERC20(address(testCaseToken)).connectHandlerToToken(address(0));
        switchToAppAdministrator();
        testCaseToken.transfer(user2, 1000);
    }
    /// Utility Helper Functions
    function _tokenMinTransactionSetup(ActionTypes action) private endWithStopPrank returns (DummyAMM) {
        /// We add the empty rule at index 0
        switchToRuleAdmin();
        uint32 ruleId = createTokenMinimumTransactionRule(10);
        setTokenMinimumTransactionRuleSingleAction(action, address(applicationCoinHandler), ruleId);
        /// we update the rule id in the token
        switchToRuleAdmin();
        ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).setTokenMinTxSizeId(_createActionsArray(action), ruleId);
        switchToAppAdministrator();
        applicationCoin2.mint(appAdministrator, 10000000000000000000000 * ATTO);
        applicationCoin2.mint(user1, 1000);
        DummyAMM amm = new DummyAMM();

        UtilApplicationERC20(address(testCaseToken)).mint(user1, 10000 * ATTO);
        ///perform buy that checks rule
        testCaseToken.approve(address(amm), 50);
        applicationCoin2.approve(address(amm), 50);
        vm.startPrank(user1, user1);
        testCaseToken.transfer(address(amm), 10000 * ATTO);
        applicationCoin2.transfer(address(amm), 900);

        switchToAppAdministrator();
        /// now we perform the transfer
        testCaseToken.transfer(rich_user, 1000000);
        applicationCoin2.transfer(rich_user, 1000000);

        return amm;
    }

    function _accountMaxValueByAccessLevelSetup(ActionTypes action) private endWithStopPrank returns (DummyAMM)  {
        switchToAppAdministrator();
        /// set up a non admin user with tokens
        testCaseToken.transfer(user1, 100000 * ATTO);
        assertEq(testCaseToken.balanceOf(user1), 100000 * ATTO);

        applicationCoin2.mint(appAdministrator, 10000000000000000000000 * ATTO);
        applicationCoin2.transfer(user1, 100000 * ATTO);
        assertEq(applicationCoin2.balanceOf(user1), 100000 * ATTO);
        applicationCoin2.transfer(user2, 1 * ATTO);
        erc20Pricer.setSingleTokenPrice(address(applicationCoin2), 1 * ATTO); //setting at $1
        assertEq(erc20Pricer.getTokenPrice(address(applicationCoin2)), 1 * ATTO);

        switchToAppAdministrator();
        DummyAMM amm = new DummyAMM();

        UtilApplicationERC20(address(testCaseToken)).mint(user1, 10000);
        ///perform buy that checks rule
        testCaseToken.approve(address(amm), 50);
        applicationCoin2.approve(address(amm), 50);
        vm.startPrank(user1, user1);
        testCaseToken.transfer(address(amm), 10000 * ATTO);
        applicationCoin2.transfer(address(amm), 900);
        
        switchToRuleAdmin();
        uint32[] memory ruleIds = new uint32[](1);
        ruleIds[0] = createAccountMaxValueByAccessLevelRule(0, 100, 500, 1000, 10000);
        setAccountMaxValueByAccessLevelRuleFull(createActionTypeArray(action), ruleIds);

        return amm;
    }

    function _accountMinMaxTokenBalanceSetup(bool tag, bool period) private endWithStopPrank {
        switchToAppAdministrator();
        /// set up a non admin user with tokens
        testCaseToken.transfer(rich_user, 100000);
        testCaseToken.transfer(user1, 1000);
        if (period) {
            vm.warp(Blocktime);
            uint16[] memory periods = createUint16Array(720);
            uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array("Oscar"), createUint256Array(10), createUint256Array(2000), periods);
            setAccountMinMaxTokenBalanceRule(address(applicationCoinHandler), ruleId);
        } else {
            if (tag) {
                uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array("Oscar"), createUint256Array(10), createUint256Array(1000));
                setAccountMinMaxTokenBalanceRule(address(applicationCoinHandler), ruleId);
            } else {
                uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array(""), createUint256Array(10), createUint256Array(1000));
                setAccountMinMaxTokenBalanceRule(address(applicationCoinHandler), ruleId);
            }
        }
        switchToAppAdministrator();

        if (tag) {
            ///Add Tag to account
            applicationAppManager.addTag(user1, "Oscar"); ///add tag
            assertTrue(applicationAppManager.hasTag(user1, "Oscar"));
            applicationAppManager.addTag(user2, "Oscar"); ///add tag
            assertTrue(applicationAppManager.hasTag(user2, "Oscar"));
            applicationAppManager.addTag(user3, "Oscar"); ///add tag
            assertTrue(applicationAppManager.hasTag(user3, "Oscar"));
        }
    }

    function _accountMinMaxTokenBalanceIndividualActionSetup(ActionTypes action) private endWithStopPrank returns (DummyAMM) {
        switchToAppAdministrator();
        /// set up a non admin user with tokens
        testCaseToken.transfer(rich_user, 100000);
        testCaseToken.transfer(user1, 100);

        applicationCoin2.mint(appAdministrator, 10000000000000000000000 * ATTO);
        applicationCoin2.mint(rich_user, 10000);

                /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = new DummyAMM();
        testCaseToken.approve(address(amm), 50);
        applicationCoin2.approve(address(amm), 50);
        vm.startPrank(rich_user, rich_user);
        testCaseToken.transfer(address(amm), 900);
        applicationCoin2.transfer(address(amm), 900);
        applicationCoin2.transfer(user1, 900);
        vm.startPrank(user1, user1);

        assertEq(testCaseToken.balanceOf(user1), 100);

        switchToAppAdministrator();
        uint32[] memory ruleIds = new uint32[](1);
        ruleIds[0] = createAccountMinMaxTokenBalanceRule(createBytes32Array(""), createUint256Array(10), createUint256Array(1000));
        setAccountMinMaxTokenBalanceRuleFull(address(applicationCoinHandler), createActionTypeArray(action), ruleIds);

        return amm;
    }

    function _accountApproveDenyOracle_Setup(ActionTypes action, bool deny) public endWithStopPrank returns (DummyAMM) {
        switchToAppAdministrator();
        /// set up a non admin user with tokens
        testCaseToken.transfer(user1, 100000);
        assertEq(testCaseToken.balanceOf(user1), 100000);
        testCaseToken.transfer(address(69), 1000);
        // add the rule.
        uint32[] memory ruleIds = new uint32[](1);
        if(deny) {
            ruleIds[0] = createAccountApproveDenyOracleRule(0);
        } else {
            ruleIds[0] = createAccountApproveDenyOracleRule(1);
        }
        setAccountApproveDenyOracleRuleFull(address(applicationCoinHandler), createActionTypeArray(action), ruleIds);

        switchToAppAdministrator();
        applicationCoin2.mint(appAdministrator, 10000000000000000000000 * ATTO);
        applicationCoin2.mint(rich_user, 10000);

        switchToAppAdministrator();
        DummyAMM amm = new DummyAMM();

        if(deny) {
            // add a blocked address
            badBoys.push(address(69));
            oracleDenied.addToDeniedList(badBoys);
        } else {
            // add approved addresses
            goodBoys.push(address(59));
            goodBoys.push(address(user1));
            goodBoys.push(address(rich_user));
            goodBoys.push(address(amm));
            oracleApproved.addToApprovedList(goodBoys);
        }

        UtilApplicationERC20(address(testCaseToken)).mint(rich_user, 10000);
        ///perform buy that checks rule
        testCaseToken.approve(address(amm), 50);
        applicationCoin2.approve(address(amm), 50);
        vm.startPrank(rich_user, rich_user);
        testCaseToken.transfer(address(amm), 900);
        applicationCoin2.transfer(address(amm), 900);
        applicationCoin2.transfer(user1, 900);
        applicationCoin2.transfer(address(69), 900);
        return amm;
    }

    function _accountApproveDenyOracleFlexible_Setup(ActionTypes action, bool deny, uint8 addressToggle) public endWithStopPrank returns (DummyAMM) {
        switchToAppAdministrator();
        /// set up a non admin user with tokens
        testCaseToken.transfer(user1, 100000);
        assertEq(testCaseToken.balanceOf(user1), 100000);
        testCaseToken.transfer(address(69), 1000);
        // add the rule.
        uint32[] memory ruleIds = new uint32[](1);
        if(deny) {
            ruleIds[0] = createAccountApproveDenyOracleFlexibleRule(0, addressToggle);
        } else {
            ruleIds[0] = createAccountApproveDenyOracleFlexibleRule(1, addressToggle);
        }
        
        switchToAppAdministrator();
        applicationCoin2.mint(appAdministrator, 10000000000000000000000 * ATTO);
        applicationCoin2.mint(rich_user, 10000);
        DummyAMM amm = new DummyAMM();
        UtilApplicationERC20(address(testCaseToken)).mint(rich_user, 10000);
        setAccountApproveDenyOracleFlexibleRuleFull(address(applicationCoinHandler), createActionTypeArray(action), ruleIds);
        switchToAppAdministrator();
        

        if(deny) {
            // add a blocked address
            badBoys.push(address(69));
            oracleDenied.addToDeniedList(badBoys);
        } else {
            // add approved addresses
            goodBoys.push(address(59));
            goodBoys.push(address(user1));
            goodBoys.push(address(rich_user));
            goodBoys.push(address(amm));
            oracleApproved.addToApprovedList(goodBoys);
        }

        
        ///perform buy that checks rule
        testCaseToken.approve(address(amm), 50);
        applicationCoin2.approve(address(amm), 50);
        vm.startPrank(rich_user, rich_user);
        testCaseToken.transfer(address(amm), 900);
        applicationCoin2.transfer(address(amm), 900);
        applicationCoin2.transfer(user1, 900);
        applicationCoin2.transfer(address(69), 900);
        return amm;
    }

    function _maxValueOutByAccessLevelSetup(ActionTypes action) private endWithStopPrank returns (DummyAMM) {
        switchToAppAdministrator();
        testCaseToken.transfer(rich_user, 10000 * ATTO);
        /// load non admin user with application coin
        testCaseToken.transfer(user1, 1000 * ATTO);
        assertEq(testCaseToken.balanceOf(user1), 1000 * ATTO);
        vm.startPrank(user1, user1);
        /// check transfer without access level with the rule turned off
        testCaseToken.transfer(user3, 50 * ATTO);
        assertEq(testCaseToken.balanceOf(user3), 50 * ATTO);

        switchToAppAdministrator();
        applicationCoin2.mint(appAdministrator, 10000000000000000000000 * ATTO);
        applicationCoin2.mint(user1, 10000);
        applicationCoin2.mint(user2, 10000);
        applicationCoin2.mint(rich_user, 10000);
        switchToAppAdministrator();
        DummyAMM amm = new DummyAMM();

        UtilApplicationERC20(address(testCaseToken)).mint(user1, 10000);
        ///perform buy that checks rule
        testCaseToken.approve(address(amm), 50);
        applicationCoin2.approve(address(amm), 50);
        vm.startPrank(rich_user, rich_user);
        testCaseToken.transfer(address(amm), 10000 * ATTO);
        applicationCoin2.transfer(address(amm), 900);

        /// price the tokens
        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(testCaseToken), 1 * ATTO); //setting at $1
        assertEq(erc20Pricer.getTokenPrice(address(testCaseToken)), 1 * ATTO);
        /// create and activate rule
        switchToRuleAdmin();
        uint32[] memory ruleIds = new uint32[](1);
        ruleIds[0] = createAccountMaxValueOutByAccessLevelRule(10, 100, 1000, 10000, 100000);
        setAccountMaxValueOutByAccessLevelRuleFull(createActionTypeArray(action), ruleIds);
        /// test transfers pass under rule value
        //User 1 currently has 950 tokens valued at $950
        //User3 currently has 50 tokens valued at $50
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(user1, 1);
        applicationAppManager.addAccessLevel(user3, 0);
        applicationAppManager.addAccessLevel(user4, 0);

        return amm;
    }

    function _pauseRuleSetup() private endWithStopPrank {
        switchToAppAdministrator();
        ///Test transfers without pause rule
        /// set up a non admin user with tokens
        testCaseToken.transfer(user1, 100000);
        assertEq(testCaseToken.balanceOf(user1), 100000);
        testCaseToken.transfer(treasuryAccount, 100000);
        assertEq(testCaseToken.balanceOf(treasuryAccount), 100000);
        vm.startPrank(user1, user1);
        testCaseToken.transfer(user2, 1000);

        ///set pause rule and check check that the transaction reverts
        switchToRuleAdmin();
        applicationAppManager.addPauseRule(Blocktime + 1000, Blocktime + 1500);
        vm.warp(Blocktime + 1001);
    }

    function _accountMaxTransactionValueByRiskScoreSetup(ActionTypes action) private endWithStopPrank returns (DummyAMM) {
        switchToAppAdministrator();
        uint8[] memory riskScores = createUint8Array(10, 40, 80, 99);
        /// set up a non admin user with tokens
        testCaseToken.transfer(user1, 10000000 * (10 ** 18));
        assertEq(testCaseToken.balanceOf(user1), 10000000 * (10 ** 18));
        testCaseToken.transfer(user2, 10000 * (10 ** 18));
        assertEq(testCaseToken.balanceOf(user2), 10000 * (10 ** 18));
        testCaseToken.transfer(user3, 1500 * (10 ** 18));
        assertEq(testCaseToken.balanceOf(user3), 1500 * (10 ** 18));
        testCaseToken.transfer(user4, 1000000 * (10 ** 18));
        assertEq(testCaseToken.balanceOf(user4), 1000000 * (10 ** 18));
        testCaseToken.transfer(user5, 10000 * (10 ** 18));
        assertEq(testCaseToken.balanceOf(user5), 10000 * (10 ** 18));

        ///Assign Risk scores to user1 and user 2
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, riskScores[0]);
        applicationAppManager.addRiskScore(user2, riskScores[1]);
        applicationAppManager.addRiskScore(user5, riskScores[3]);

        switchToAppAdministrator();
        applicationCoin2.mint(appAdministrator, 10000000000000000000000 * ATTO);
        applicationCoin2.mint(user1, 10000);
        applicationCoin2.mint(user2, 10000);

        switchToAppAdministrator();
        DummyAMM amm = new DummyAMM();

        UtilApplicationERC20(address(testCaseToken)).mint(user1, 10000);
        ///perform buy that checks rule
        testCaseToken.approve(address(amm), 50);
        applicationCoin2.approve(address(amm), 50);
        vm.startPrank(user1, user1);
        testCaseToken.transfer(address(amm), 10000 * ATTO);
        applicationCoin2.transfer(address(amm), 900);

        ///Switch to app admin and set up ERC20Pricer and activate AccountMaxTxValueByRiskScore Rule
        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(testCaseToken), 1 * (10 ** 18)); //setting at $1
        assertEq(erc20Pricer.getTokenPrice(address(testCaseToken)), 1 * (10 ** 18));

        uint32[] memory ruleIds = new uint32[](1);
        ruleIds[0] = createAccountMaxTxValueByRiskRule(riskScores, createUint48Array(1000000, 100000, 10000, 1000));
        setAccountMaxTxValueByRiskRuleFull(createActionTypeArray(action), ruleIds);

        return amm;
    }

    function _passesAccountDenyForNoAccessLevelRuleCoinSetup(ActionTypes action) public endWithStopPrank returns (DummyAMM) {
        switchToAppAdministrator();
        /// load non admin user with application coin
        testCaseToken.transfer(rich_user, 1000000 * ATTO);
        assertEq(testCaseToken.balanceOf(rich_user), 1000000 * ATTO);
        vm.startPrank(rich_user, rich_user);
        /// check transfer without access level but with the rule turned off
        testCaseToken.transfer(user3, 5 * ATTO);
        assertEq(testCaseToken.balanceOf(user3), 5 * ATTO);

        switchToAppAdministrator();
        applicationCoin2.mint(appAdministrator, 10000000000000000000000 * ATTO);
        applicationCoin2.mint(user1, 10000);
        applicationCoin2.mint(rich_user, 10000);
        applicationCoin2.mint(user3, 10000);
        DummyAMM amm = new DummyAMM();

        UtilApplicationERC20(address(testCaseToken)).mint(user1, 10000);
        ///perform buy that checks rule
        testCaseToken.approve(address(amm), 50);
        applicationCoin2.approve(address(amm), 50);
        vm.startPrank(rich_user, rich_user);
        testCaseToken.transfer(address(amm), 10000 * ATTO);
        applicationCoin2.transfer(address(amm), 900);
        

        /// now turn the rule on
        createAccountDenyForNoAccessLevelRuleFull(createActionTypeArray(action));

        return amm;
    }

    function _accountMaxTransactionValueByRiskScoreWithPeriodSetup() private endWithStopPrank {
        switchToAppAdministrator();
        uint8[] memory riskScores = createUint8Array(10, 40, 80, 99);
        /// set up a non admin user with tokens
        testCaseToken.transfer(user1, 10000000 * ATTO);
        assertEq(testCaseToken.balanceOf(user1), 10000000 * ATTO);
        testCaseToken.transfer(user2, 10000 * ATTO);
        assertEq(testCaseToken.balanceOf(user2), 10000 * ATTO);
        testCaseToken.transfer(user3, 1500 * ATTO);
        assertEq(testCaseToken.balanceOf(user3), 1500 * ATTO);
        testCaseToken.transfer(user4, 1000000 * ATTO);
        assertEq(testCaseToken.balanceOf(user4), 1000000 * ATTO);
        testCaseToken.transfer(user5, 10000 * ATTO);
        assertEq(testCaseToken.balanceOf(user5), 10000 * ATTO);

        ///Assign Risk scores to user1 and user 2
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, riskScores[0]);
        applicationAppManager.addRiskScore(user2, riskScores[1]);
        applicationAppManager.addRiskScore(user5, riskScores[3]);

        ///Switch to app admin and set up ERC20Pricer and activate AccountMaxTxValueByRiskScore Rule
        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(testCaseToken), 1 * ATTO); //setting at $1
        assertEq(erc20Pricer.getTokenPrice(address(testCaseToken)), 1 * ATTO);
        uint8 period = 24;
        uint32 ruleId = createAccountMaxTxValueByRiskRule(riskScores, createUint48Array(1000000, 100000, 10000, 1000), period);
        setAccountMaxTxValueByRiskRule(ruleId);
    }

    function _tokenMaxTradingVolumeWithSupplySetSetup(ActionTypes action) private endWithStopPrank returns (DummyAMM) {
        /// set the rule for 40% in 2 hours, starting at midnight
        switchToAppAdministrator();
        /// load non admin users with game coin
        testCaseToken.transfer(rich_user, 100_000 * ATTO);
        assertEq(testCaseToken.balanceOf(rich_user), 100_000 * ATTO);

        applicationCoin2.mint(appAdministrator, 10000000000000000000000 * ATTO);
        applicationCoin2.mint(user1, 10000);
        applicationCoin2.mint(rich_user, 10000);
        applicationCoin2.mint(user3, 10000);
        DummyAMM amm = new DummyAMM();

        ///perform buy that checks rule
        testCaseToken.approve(address(amm), 50);
        applicationCoin2.approve(address(amm), 50);
        vm.startPrank(rich_user, rich_user);
        testCaseToken.transfer(address(amm), 40000 * ATTO);
        applicationCoin2.transfer(address(amm), 900);

        /// apply the rule
        uint32 ruleId = createTokenMaxTradingVolumeRule(4000, 2, Blocktime, 100_000 * ATTO);
        setTokenMaxTradingVolumeRuleSingleAction(action, address(applicationCoinHandler), ruleId);

        return amm;
    }

    function _tradeRuleSetup() private returns (DummyAMM) {
        /// initialize AMM and give two users more app tokens and "chain native" tokens
        DummyAMM amm = initializeAMMAndUsers();
        applicationCoin2.transfer(user1, 50_000_000 * ATTO);
        applicationCoin2.transfer(user2, 30_000_000 * ATTO);
        testCaseToken.transfer(user1, 50_000_000 * ATTO);
        testCaseToken.transfer(user2, 30_000_000 * ATTO);
        assertEq(applicationCoin2.balanceOf(user1), 50_001_000 * ATTO);
        return amm;
    }

    function _setupAccountMaxTradeSizeSell() private endWithStopPrank {
        ///Add tag to user
        switchToAppAdministrator();
        applicationAppManager.addTag(user1, "AccountMaxSellSize");
        applicationAppManager.addTag(user2, "AccountMaxSellSize");
        /// add the rule.
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.SELL);
        uint32 ruleId = createAccountMaxTradeSizeRule("AccountMaxSellSize", 600, 36);
        setAccountMaxTradeSizeRule(address(applicationCoinHandler), actionTypes, ruleId);
    }

    function _setupAccountMaxTradeSizeSellBlankTag() private {
        /// add the rule.
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.SELL);
        uint32 ruleId = createAccountMaxTradeSizeRule("", 600, 36);
        setAccountMaxTradeSizeRule(address(applicationCoinHandler), actionTypes, ruleId);
    }

    function _setupAccountMaxTradeSizeBuyRule() private endWithStopPrank {
        switchToAppAdministrator();
        /// Add tag to users
        applicationAppManager.addTag(user1, "MaxBuySize");
        applicationAppManager.addTag(user2, "MaxBuySize");
        /// add the rule.
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.BUY);
        uint32 ruleId = createAccountMaxTradeSizeRule("MaxBuySize", 600, 36);
        setAccountMaxTradeSizeRule(address(applicationCoinHandler), actionTypes, ruleId);
    }

    function _setupAccountMaxTradeSizeBuyRuleBlankTag() private {
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.BUY);
        uint32 ruleId = createAccountMaxTradeSizeRule("", 600, 36);
        setAccountMaxTradeSizeRule(address(applicationCoinHandler), actionTypes, ruleId);
    }

    function _setupTokenMaxBuySellVolumeRuleBuyAction() internal endWithStopPrank {
        uint32 ruleId = createTokenMaxBuySellVolumeRule(5000, 24, 100_000_000, Blocktime);
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.BUY);
        setTokenMaxBuySellVolumeRule(address(applicationCoinHandler), actionTypes, ruleId);
    }

    function _setupTokenMaxBuySellVolumeRuleBuyActionB() internal endWithStopPrank {
        uint32 ruleId = createTokenMaxBuySellVolumeRule(1, 24, 100_000, Blocktime);
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.BUY);
        setTokenMaxBuySellVolumeRule(address(applicationCoinHandler), actionTypes, ruleId);
    }

    function _setupTokenMaxBuySellVolumeRuleSellAction() internal endWithStopPrank {
        uint32 ruleId = createTokenMaxBuySellVolumeRule(5000, 24, 100_000_000, Blocktime);
        ActionTypes[] memory actionTypes = createActionTypeArray(ActionTypes.SELL);
        setTokenMaxBuySellVolumeRule(address(applicationCoinHandler), actionTypes, ruleId);
    }

    function initializeAMMAndUsers() public returns (DummyAMM amm) {
        amm = new DummyAMM();
        applicationCoin2.mint(appAdministrator, 1_000_000_000_000 * ATTO);
        /// Approve the transfer of tokens into AMM
        testCaseToken.approve(address(amm), 1_000_000 * ATTO);
        applicationCoin2.approve(address(amm), 1_000_000 * ATTO);
        /// Transfer the tokens into the AMM
        testCaseToken.transfer(address(amm), 1_000_000 * ATTO);
        applicationCoin2.transfer(address(amm), 1_000_000 * ATTO);
        /// Make sure the tokens made it
        assertEq(testCaseToken.balanceOf(address(amm)), 1_000_000 * ATTO);
        assertEq(applicationCoin2.balanceOf(address(amm)), 1_000_000 * ATTO);
        testCaseToken.transfer(user1, 1000 * ATTO);
        testCaseToken.transfer(user2, 1000 * ATTO);
        testCaseToken.transfer(user3, 1000 * ATTO);
        testCaseToken.transfer(rich_user, 1000 * ATTO);
        applicationCoin2.transfer(user1, 1000 * ATTO);
        applicationCoin2.transfer(user2, 1000 * ATTO);
        testCaseToken.transfer(address(69), 1000 * ATTO);
        applicationCoin2.transfer(address(69), 1000 * ATTO);
    }

    function testERC20_ERC20CommonTests_FacetOwnershipModifiers_ERC20NonTaggedRules_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        /// create facet and test that onlyOwner modifer prevents calls from non owners 
        ERC20NonTaggedRuleFacet erc20NonTaggedTestFacet = new ERC20NonTaggedRuleFacet(); 
        switchToUser();
        vm.expectRevert("UNAUTHORIZED");
        erc20NonTaggedTestFacet.checkNonTaggedRules(user1, user, user, 10, ActionTypes.P2P_TRANSFER);
        /// test that users cannot call the facets directly through the proxy address 
        vm.expectRevert("UNAUTHORIZED");
        ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).checkNonTaggedRules(user1, user, user, 10, ActionTypes.P2P_TRANSFER);
    }

    function testERC20_ERC20CommonTests_FacetOwnershipModifiers_ERC20TaggedRulesFacet_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        /// create facet and test that onlyOwner modifer prevents calls from non owners 
        ERC20TaggedRuleFacet erc20TaggedTestFacet = new ERC20TaggedRuleFacet(); 
        switchToUser();
        vm.expectRevert("UNAUTHORIZED");
        erc20TaggedTestFacet.checkTaggedAndTradingRules(10, 10, user1, user, user, 10, ActionTypes.P2P_TRANSFER);
        /// test that users cannot call the facets directly through the proxy address 
        vm.expectRevert("UNAUTHORIZED");
        ERC20NonTaggedRuleFacet(address(applicationCoinHandler)).checkNonTaggedRules(user1, user, user, 10, ActionTypes.P2P_TRANSFER);
    }

    function testERC20_ERC20CommonTests_FacetOwnershipModifiers_TradingRules_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        /// create facet and test that onlyOwner modifer prevents calls from non owners 
        TradingRuleFacet tradeRuleTestFacet = new TradingRuleFacet();
        switchToUser();
        vm.expectRevert("UNAUTHORIZED");
        tradeRuleTestFacet.checkTradingRules(user1, user, user, createBytes32Array("Oscar"), createBytes32Array("Shane"), 10, ActionTypes.P2P_TRANSFER);
        /// test that users cannot call the facets directly through the proxy address 
        vm.expectRevert("UNAUTHORIZED");
        TradingRuleFacet(address(applicationCoinHandler)).checkTradingRules(user1, user, user, createBytes32Array("Tayler"), createBytes32Array("Michael"), 10, ActionTypes.P2P_TRANSFER);
    }
    
}
