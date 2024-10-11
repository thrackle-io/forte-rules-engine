// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/client/token/ERC20/util/ERC20Util.sol";

contract ApplicationERC20FuzzTest is ERC20Util {
    // event Log(string eventString, uint256 number);
    UtilApplicationERC20 draculaCoin;

    function setUp() public {
        vm.warp(Blocktime);
        setUpProcotolAndCreateERC20AndDiamondHandler();
        switchToAppAdministrator();
        draculaCoin = new UtilApplicationERC20("application2", "DRAC", address(applicationAppManager));
        applicationCoinHandler2 = _createERC20HandlerDiamond();
        ERC20HandlerMainFacet(address(applicationCoinHandler2)).initialize(address(ruleProcessor), address(applicationAppManager), address(draculaCoin));
        draculaCoin.connectHandlerToToken(address(applicationCoinHandler2));
        /// register the token
        applicationAppManager.registerToken("DRAC", address(draculaCoin));
        vm.stopPrank();
    }

    // Test balance
    function testERC20_ApplicationERC20Fuzz_BalanceERC20_Positive(uint256 _supply) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, _supply);
        assertEq(applicationCoin.balanceOf(appAdministrator), _supply);
    }

    function testERC20_ApplicationERC20Fuzz_BalanceERC20_MaxSupply_Positive(uint256 _supply, uint256 _mintAmount) public endWithStopPrank {
        _mintAmount = bound(_mintAmount, 1, type(uint256).max);
        switchToAppAdministrator();
        applicationCoin.setMaxSupply(_supply);
        if (_supply >= applicationCoin.getMaxSupply() || _supply == 0) {
            applicationCoin.mint(appAdministrator, _mintAmount);
            assertEq(applicationCoin.balanceOf(appAdministrator), _mintAmount);
        } else {
            assertEq(applicationCoin.balanceOf(appAdministrator), 0);
        }
    }

    function testERC20_ApplicationERC20Fuzz_BalanceERC20_MaxSupply_Negative(uint256 _supply, uint256 _mintAmount) public endWithStopPrank {
        _mintAmount = bound(_mintAmount, 1, type(uint256).max);
        switchToAppAdministrator();
        applicationCoin.setMaxSupply(_supply);
        if (_supply < applicationCoin.getMaxSupply() && _supply != 0) {
            vm.expectRevert(abi.encodeWithSignature("ExceedingMaxSupply()"));
            applicationCoin.mint(appAdministrator, _mintAmount);
            assertEq(applicationCoin.balanceOf(appAdministrator), 0);
        }
    }

    function testERC20_ApplicationERC20Fuzz_setMaxSupply_Positive(uint256 _supply) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.setMaxSupply(_supply);
        assertEq(applicationCoin.getMaxSupply(), _supply);
    }

    function testERC20_ApplicationERC20Fuzz_setMaxSupply_NotAppAdmin(uint256 _supply) public endWithStopPrank {
        vm.expectRevert(abi.encodeWithSignature("NotAppAdministrator()"));
        applicationCoin.setMaxSupply(_supply);
        assertEq(applicationCoin.getMaxSupply(), 0);
    }

    function testERC20_ApplicationERC20Fuzz_Transfer_Positive(uint8 _addressIndex, uint256 _amount) public endWithStopPrank {
        switchToAppAdministrator();
        address _user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 1)[0];
        applicationCoin.mint(appAdministrator, _amount);
        applicationCoin.transfer(_user1, _amount);
        assertEq(applicationCoin.balanceOf(_user1), _amount);
        assertEq(applicationCoin.balanceOf(appAdministrator), 0);
    }

    function testERC20_ApplicationERC20Fuzz_Transfer_ToAddressZeroAddress(uint256 _amount) public endWithStopPrank {
        switchToAppAdministrator();
        address _user1 = address(0);
        applicationCoin.mint(appAdministrator, _amount);
        vm.expectRevert("ERC20: transfer to the zero address");
        applicationCoin.transfer(_user1, _amount);
        assertEq(applicationCoin.balanceOf(appAdministrator), _amount);
    }

    function testERC20_ApplicationERC20Fuzz_Transfer_NotOwned(uint8 _addressIndex, uint256 _amount) public endWithStopPrank {
        _amount = bound(_amount, 1, type(uint256).max);
        switchToAppAdministrator();
        address _user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 1)[0];
        applicationCoin.mint(appAdministrator, _amount);
        switchToUser();
        vm.expectRevert("ERC20: transfer amount exceeds balance");
        applicationCoin.transfer(_user1, _amount);
        assertEq(applicationCoin.balanceOf(_user1), 0);
    }

    /* TOKEN MINIMUM TRANSACTION SIZE RULE */
    function testERC20_ApplicationERC20Fuzz_TokenMinTransactionSize_All_Positive(uint8 _addressIndex, uint128 _transferAmount) public endWithStopPrank {
        _transferAmount = uint128(bound(uint256(_transferAmount), 1, type(uint128).max - 1));
        applicationCoin.mint(appAdministrator, type(uint256).max);
        address _user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 1)[0];
        switchToRuleAdmin();
        uint32 ruleId = createTokenMinimumTransactionRule(_transferAmount);
        setTokenMinimumTransactionRule(address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        applicationCoin.transfer(_user1, _transferAmount + 1);
        assertEq(applicationCoin.balanceOf(_user1), _transferAmount + 1);
    }

    function testERC20_ApplicationERC20Fuzz_TokenMinTransactionSize_All_Negative(uint8 _addressIndex, uint128 _transferAmount) public endWithStopPrank {
        // if the transferAmount is the max, adjust so the internal arithmetic works
        _transferAmount = uint128(bound(uint256(_transferAmount), 1, type(uint128).max - 1));
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user2) = _get2RandomAddresses(_addressIndex);
        // Then we add the rule.
        uint32 ruleId;
        switchToRuleAdmin();
        ruleId = createTokenMinimumTransactionRule(_transferAmount);
        setTokenMinimumTransactionRule(address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        // now we check for proper failure
        vm.expectRevert(0x7a78c901);
        applicationCoin.transfer(_user2, _transferAmount - 1);
    }

    /* Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_TokenMinTransactionSize_Transfer_Positive(uint8 _addressIndex, uint128 _transferAmount) public endWithStopPrank {
        _transferAmount = uint128(bound(uint256(_transferAmount), 1, type(uint128).max - 1));
        applicationCoin.mint(appAdministrator, type(uint256).max);
        address _user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 1)[0];
        switchToRuleAdmin();
        uint32 ruleId = createTokenMinimumTransactionRule(_transferAmount);
        setTokenMinimumTransactionRuleSingleAction(ActionTypes.P2P_TRANSFER, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        applicationCoin.transfer(_user1, _transferAmount + 1);
        assertEq(applicationCoin.balanceOf(_user1), _transferAmount + 1);
    }

    function testERC20_ApplicationERC20Fuzz_TokenMinTransactionSize_Transfer_Negative(uint8 _addressIndex, uint128 _transferAmount) public endWithStopPrank {
        // if the transferAmount is the max, adjust so the internal arithmetic works
        _transferAmount = uint128(bound(uint256(_transferAmount), 1, type(uint128).max - 1));
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user2) = _get2RandomAddresses(_addressIndex);
        // Then we add the rule.
        uint32 ruleId;
        switchToRuleAdmin();
        ruleId = createTokenMinimumTransactionRule(_transferAmount);
        setTokenMinimumTransactionRuleSingleAction(ActionTypes.P2P_TRANSFER, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        // now we check for proper failure
        vm.expectRevert(0x7a78c901);
        applicationCoin.transfer(_user2, _transferAmount - 1);
    }

    /* Test MINT only */
    function testERC20_ApplicationERC20Fuzz_TokenMinTransactionSize_Mint_Positive(uint8 _addressIndex, uint128 _transferAmount) public endWithStopPrank {
        _transferAmount = uint128(bound(uint256(_transferAmount), 1, type(uint128).max - 1));
        address _user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 1)[0];
        switchToRuleAdmin();
        uint32 ruleId = createTokenMinimumTransactionRule(_transferAmount);
        setTokenMinimumTransactionRuleSingleAction(ActionTypes.MINT, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        applicationCoin.mint(_user1, _transferAmount + 1);
        assertEq(applicationCoin.balanceOf(_user1), _transferAmount + 1);
    }

    function testERC20_ApplicationERC20Fuzz_TokenMinTransactionSize_Mint_Negative(uint8 _addressIndex, uint128 _transferAmount) public endWithStopPrank {
        // if the transferAmount is the max, adjust so the internal arithmetic works
        _transferAmount = uint128(bound(uint256(_transferAmount), 1, type(uint128).max - 1));
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user2) = _get2RandomAddresses(_addressIndex);
        // Then we add the rule.
        uint32 ruleId;
        switchToRuleAdmin();
        ruleId = createTokenMinimumTransactionRule(_transferAmount);
        setTokenMinimumTransactionRuleSingleAction(ActionTypes.MINT, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        // now we check for proper failure
        vm.expectRevert(0x7a78c901);
        applicationCoin.mint(_user2, _transferAmount - 1);
    }

    /* Test BURN only */
    function testERC20_ApplicationERC20Fuzz_TokenMinTransactionSize_Burn_Positive(uint8 _addressIndex, uint128 _transferAmount) public endWithStopPrank {
        _transferAmount = uint128(bound(uint256(_transferAmount), 1, type(uint128).max - 1));
        applicationCoin.mint(appAdministrator, type(uint256).max);
        address _user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 1)[0];
        switchToRuleAdmin();
        uint32 ruleId = createTokenMinimumTransactionRule(_transferAmount);
        setTokenMinimumTransactionRuleSingleAction(ActionTypes.BURN, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        applicationCoin.transfer(_user1, _transferAmount + 1);
        vm.startPrank(_user1, _user1);
        applicationCoin.burn(_transferAmount + 1);
        assertEq(applicationCoin.balanceOf(_user1), 0);
    }

    function testERC20_ApplicationERC20Fuzz_TokenMinTransactionSize_Burn_Negative(uint8 _addressIndex, uint128 _transferAmount) public endWithStopPrank {
        _transferAmount = uint128(bound(uint256(_transferAmount), 1, type(uint128).max - 1));
        applicationCoin.mint(appAdministrator, type(uint256).max);
        address _user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 1)[0];
        switchToRuleAdmin();
        uint32 ruleId = createTokenMinimumTransactionRule(_transferAmount);
        setTokenMinimumTransactionRuleSingleAction(ActionTypes.BURN, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        applicationCoin.transfer(_user1, _transferAmount - 1);
        vm.startPrank(_user1, _user1);
        // now we check for proper failure
        vm.expectRevert(0x7a78c901);
        applicationCoin.burn(_transferAmount - 1);
        assertEq(applicationCoin.balanceOf(_user1), _transferAmount - 1);
    }

    /* Test BUY only */
    function testERC20_ApplicationERC20Fuzz_TokenMinTransactionSize_Buy_Positive(uint8 _addressIndex, uint256 _transferAmount) public endWithStopPrank {
        _transferAmount = bound(uint256(_transferAmount), 1, type(uint128).max);
        address _user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 1)[0];
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, _transferAmount, false);
        switchToRuleAdmin();
        uint32 ruleId = createTokenMinimumTransactionRule(_transferAmount);
        setTokenMinimumTransactionRuleSingleAction(ActionTypes.BUY, address(applicationCoinHandler), ruleId);
        vm.startPrank(_user1, _user1);
        /// Approve transfer
        applicationCoin2.approve(address(amm), _transferAmount);
        /// Buy some applicationCoin
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), _transferAmount, _transferAmount, false);
        assertEq(applicationCoin.balanceOf(_user1), _transferAmount);
    }

    function testERC20_ApplicationERC20Fuzz_TokenMinTransactionSize_Buy_Negative(uint8 _addressIndex, uint256 _transferAmount) public endWithStopPrank {
        _transferAmount = bound(uint256(_transferAmount), 1, type(uint128).max);
        address _user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 1)[0];
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, _transferAmount, false);
        switchToRuleAdmin();
        // Set the minimum as one more than the transfer amount
        uint32 ruleId = createTokenMinimumTransactionRule(_transferAmount + 1);
        setTokenMinimumTransactionRuleSingleAction(ActionTypes.BUY, address(applicationCoinHandler), ruleId);
        vm.startPrank(_user1, _user1);
        /// Approve transfer
        applicationCoin2.approve(address(amm), _transferAmount);
        // now we check for proper failure
        vm.expectRevert(0x7a78c901);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), _transferAmount, _transferAmount, false);
    }

    /* Test SELL only */
    function testERC20_ApplicationERC20Fuzz_TokenMinTransactionSize_Sell_Positive(uint8 _addressIndex, uint256 _transferAmount) public endWithStopPrank {
        _transferAmount = bound(uint256(_transferAmount), 1, type(uint128).max);
        address _user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 1)[0];
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, _transferAmount, true);
        switchToRuleAdmin();
        uint32 ruleId = createTokenMinimumTransactionRule(_transferAmount);
        setTokenMinimumTransactionRuleSingleAction(ActionTypes.SELL, address(applicationCoinHandler), ruleId);
        vm.startPrank(_user1, _user1);
        /// Approve transfer
        applicationCoin.approve(address(amm), _transferAmount);
        /// Sell some applicationCoin
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), _transferAmount, _transferAmount, true);
        assertEq(applicationCoin2.balanceOf(_user1), _transferAmount);
    }

    function testERC20_ApplicationERC20Fuzz_TokenMinTransactionSize_Sell_Negative(uint8 _addressIndex, uint256 _transferAmount) public endWithStopPrank {
        _transferAmount = bound(uint256(_transferAmount), 1, type(uint128).max);
        address _user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 1)[0];
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, _transferAmount, true);
        switchToRuleAdmin();
        // Set the minimum as one more than the transfer amount
        uint32 ruleId = createTokenMinimumTransactionRule(_transferAmount + 1);
        setTokenMinimumTransactionRuleSingleAction(ActionTypes.SELL, address(applicationCoinHandler), ruleId);
        vm.startPrank(_user1, _user1);
        /// Approve transfer
        applicationCoin.approve(address(amm), _transferAmount);
        // now we check for proper failure
        vm.expectRevert(0x7a78c901);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), _transferAmount, _transferAmount, true);
    }

    /* TOKEN MIN MAX TOKEN BALANCE RULE */
    function testERC20_ApplicationERC20Fuzz_AccountMinMaxTokenBalance_All_Positive(bytes32 _tag, uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        _amountSeed = uint24(bound(uint256(_amountSeed), 1, 167770));
        switchToAppAdministrator();
        if (_tag == "") _tag = bytes32("TEST");
        (address _richUser, address _user1, address _user2, address _user3) = _get4RandomAddresses(_addressIndex);
        // set up amounts
        uint256 maxAmount = _amountSeed * 100;
        uint256 minAmount = _amountSeed;
        applicationCoin.mint(appAdministrator, type(uint256).max);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_richUser, maxAmount);
        applicationCoin.transfer(_user1, maxAmount);
        uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array(_tag), createUint256Array(minAmount), createUint256Array(maxAmount));
        setAccountMinMaxTokenBalanceRule(address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        ///Add Tag to account
        address[3] memory tempAddresses = [_user1, _user2, _user3];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addTag(tempAddresses[i], _tag); ///add tag
        for (uint i; i < tempAddresses.length; i++) assertTrue(applicationAppManager.hasTag(tempAddresses[i], _tag));
        ///perform transfer that checks rule
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        applicationCoin.transfer(_user2, minAmount);
        assertEq(applicationCoin.balanceOf(_user2), minAmount);
        assertEq(applicationCoin.balanceOf(_user1), maxAmount - minAmount);
    }

    /* Test MINT only */
    function testERC20_ApplicationERC20Fuzz_AccountMinMaxTokenBalance_Mint_Positive(bytes32 _tag, uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        _amountSeed = uint24(bound(uint256(_amountSeed), 1, 167770));
        switchToAppAdministrator();
        if (_tag == "") _tag = bytes32("TEST");
        (address _user1, address _user2, address _user3) = _get3RandomAddresses(_addressIndex);
        // set up amounts
        uint256 maxAmount = _amountSeed * 100;
        uint256 minAmount = _amountSeed;
        uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array(_tag), createUint256Array(minAmount), createUint256Array(maxAmount));
        setAccountMinMaxTokenBalanceRuleSingleAction(ActionTypes.MINT, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        ///Add Tag to account
        address[3] memory tempAddresses = [_user1, _user2, _user3];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addTag(tempAddresses[i], _tag); ///add tag
        for (uint i; i < tempAddresses.length; i++) assertTrue(applicationAppManager.hasTag(tempAddresses[i], _tag));
        ///perform transfer that checks rule
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        applicationCoin.mint(_user1, minAmount);
        assertEq(applicationCoin.balanceOf(_user1), minAmount);
    }

    /* Test BURN only */
    function testERC20_ApplicationERC20Fuzz_AccountMinMaxTokenBalance_Burn_Positive(bytes32 _tag, uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        _amountSeed = uint24(bound(uint256(_amountSeed), 1, 167770));
        switchToAppAdministrator();
        if (_tag == "") _tag = bytes32("TEST");
        (address _user1, address _user2, address _user3) = _get3RandomAddresses(_addressIndex);
        // set up amounts
        uint256 maxAmount = _amountSeed * 100;
        uint256 minAmount = _amountSeed;
        applicationCoin.mint(appAdministrator, type(uint256).max);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, maxAmount);
        uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array(_tag), createUint256Array(minAmount), createUint256Array(maxAmount));
        setAccountMinMaxTokenBalanceRuleSingleAction(ActionTypes.BURN, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        ///Add Tag to account
        address[3] memory tempAddresses = [_user1, _user2, _user3];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addTag(tempAddresses[i], _tag); ///add tag
        for (uint i; i < tempAddresses.length; i++) assertTrue(applicationAppManager.hasTag(tempAddresses[i], _tag));
        ///perform transfer that checks rule
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        applicationCoin.burn(maxAmount - minAmount);
        assertEq(applicationCoin.balanceOf(_user1), maxAmount - (maxAmount - minAmount));
    }

    /* Test BUY only */
    function testERC20_ApplicationERC20Fuzz_AccountMinMaxTokenBalance_Buy_Positive(bytes32 _tag, uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        _amountSeed = uint24(bound(uint256(_amountSeed), 1, 167770));
        switchToAppAdministrator();
        if (_tag == "") _tag = bytes32("TEST");
        (address _user1, address _user2, address _user3) = _get3RandomAddresses(_addressIndex);
        // set up amounts
        uint256 maxAmount = _amountSeed * 100;
        uint256 minAmount = _amountSeed;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, maxAmount, false);
        uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array(_tag), createUint256Array(minAmount), createUint256Array(maxAmount));
        setAccountMinMaxTokenBalanceRuleSingleAction(ActionTypes.BUY, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        ///Add Tag to account
        address[3] memory tempAddresses = [_user1, _user2, _user3];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addTag(tempAddresses[i], _tag); ///add tag
        for (uint i; i < tempAddresses.length; i++) assertTrue(applicationAppManager.hasTag(tempAddresses[i], _tag));
        ///perform transfer that checks rule
        vm.startPrank(_user1, _user1);
        /// Approve transfer
        applicationCoin2.approve(address(amm), minAmount);
        /// Buy some applicationCoin
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), minAmount, minAmount, false);
        assertEq(applicationCoin.balanceOf(_user1), minAmount);
    }

    /* Test SELL only */
    function testERC20_ApplicationERC20Fuzz_AccountMinMaxTokenBalance_Sell_Positive(bytes32 _tag, uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        _amountSeed = uint24(bound(uint256(_amountSeed), 1, 167770));
        switchToAppAdministrator();
        if (_tag == "") _tag = bytes32("TEST");
        (address _user1, address _user2, address _user3) = _get3RandomAddresses(_addressIndex);
        // set up amounts
        uint256 maxAmount = _amountSeed * 100;
        uint256 minAmount = _amountSeed;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, maxAmount, true);
        uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array(_tag), createUint256Array(minAmount), createUint256Array(maxAmount));
        setAccountMinMaxTokenBalanceRuleSingleAction(ActionTypes.SELL, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        ///Add Tag to account
        address[3] memory tempAddresses = [_user1, _user2, _user3];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addTag(tempAddresses[i], _tag); ///add tag
        for (uint i; i < tempAddresses.length; i++) assertTrue(applicationAppManager.hasTag(tempAddresses[i], _tag));
        ///perform transfer that checks rule
        vm.startPrank(_user1, _user1);
        /// Approve transfer
        applicationCoin.approve(address(amm), minAmount);
        /// Buy some applicationCoin
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), minAmount, minAmount, true);
        assertEq(applicationCoin2.balanceOf(_user1), minAmount);
    }
    /* Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_AccountMinMaxTokenBalance_Transfer_Positive(bytes32 _tag, uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        _amountSeed = uint24(bound(uint256(_amountSeed), 1, 167770));
        switchToAppAdministrator();
        if (_tag == "") _tag = bytes32("TEST");
        (address _richUser, address _user1, address _user2, address _user3) = _get4RandomAddresses(_addressIndex);
        // set up amounts
        uint256 maxAmount = _amountSeed * 100;
        uint256 minAmount = _amountSeed;
        applicationCoin.mint(appAdministrator, type(uint256).max);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_richUser, maxAmount);
        applicationCoin.transfer(_user1, maxAmount);
        uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array(_tag), createUint256Array(minAmount), createUint256Array(maxAmount));
        setAccountMinMaxTokenBalanceRuleSingleAction(ActionTypes.P2P_TRANSFER, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        ///Add Tag to account
        address[3] memory tempAddresses = [_user1, _user2, _user3];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addTag(tempAddresses[i], _tag); ///add tag
        for (uint i; i < tempAddresses.length; i++) assertTrue(applicationAppManager.hasTag(tempAddresses[i], _tag));
        ///perform transfer that checks rule
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        applicationCoin.transfer(_user2, minAmount);
        assertEq(applicationCoin.balanceOf(_user2), minAmount);
        assertEq(applicationCoin.balanceOf(_user1), maxAmount - minAmount);
    }

    /* Test All actions */
    function testERC20_ApplicationERC20Fuzz_AccountMinMaxTokenBalance_All_UnderMinBalance(bytes32 _tag, uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        _amountSeed = uint24(bound(uint256(_amountSeed), 2, 167770));
        switchToAppAdministrator();
        if (_tag != "") {
            (address _user1, address _user2) = _get2RandomAddresses(_addressIndex);
            // set up amounts
            uint256 maxAmount = _amountSeed * 100;
            uint256 minAmount = _amountSeed;
            applicationCoin.mint(appAdministrator, type(uint256).max);
            /// set up a non admin user with tokens
            applicationCoin.transfer(_user1, maxAmount);
            uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array(_tag), createUint256Array(minAmount), createUint256Array(maxAmount));
            setAccountMinMaxTokenBalanceRule(address(applicationCoinHandler), ruleId);
            switchToAppAdministrator();
            ///Add Tag to account
            applicationAppManager.addTag(_user1, _tag); ///add tag
            applicationAppManager.addTag(_user2, _tag); ///add tag
            ///perform transfer that checks rule
            vm.startPrank(_user1, _user1);
            // make sure the minimum rules fail results in revert
            vm.expectRevert(abi.encodeWithSignature("UnderMinBalance()"));
            applicationCoin.transfer(_user2, maxAmount);
        }
    }
    /* Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_AccountMinMaxTokenBalance_Transfer_UnderMinBalance(bytes32 _tag, uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        _amountSeed = uint24(bound(uint256(_amountSeed), 2, 167770));
        switchToAppAdministrator();
        if (_tag != "") {
            (address _user1, address _user2) = _get2RandomAddresses(_addressIndex);
            // set up amounts
            uint256 maxAmount = _amountSeed * 100;
            uint256 minAmount = _amountSeed;
            applicationCoin.mint(appAdministrator, type(uint256).max);
            /// set up a non admin user with tokens
            applicationCoin.transfer(_user1, maxAmount);
            uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array(_tag), createUint256Array(minAmount), createUint256Array(maxAmount));
            setAccountMinMaxTokenBalanceRuleSingleAction(ActionTypes.P2P_TRANSFER, address(applicationCoinHandler), ruleId);
            switchToAppAdministrator();
            ///Add Tag to account
            applicationAppManager.addTag(_user1, _tag); ///add tag
            applicationAppManager.addTag(_user2, _tag); ///add tag
            ///perform transfer that checks rule
            vm.startPrank(_user1, _user1);
            // make sure the minimum rules fail results in revert
            vm.expectRevert(abi.encodeWithSignature("UnderMinBalance()"));
            applicationCoin.transfer(_user2, maxAmount);
        }
    }

    /* NOTE: MINT and BUY will never trigger this rule for under min as it only checks the amount transferred out does not bring the from address balance below the minimum */

    /* Test BURN only */
    function testERC20_ApplicationERC20Fuzz_AccountMinMaxTokenBalance_Burn_UnderMinBalance(bytes32 _tag, uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        _amountSeed = uint24(bound(uint256(_amountSeed), 1, 167770));
        switchToAppAdministrator();
        if (_tag == "") _tag = bytes32("TEST");
        (address _user1, address _user2, address _user3) = _get3RandomAddresses(_addressIndex);
        // set up amounts
        uint256 maxAmount = _amountSeed * 100;
        uint256 minAmount = _amountSeed;
        applicationCoin.mint(appAdministrator, type(uint256).max);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, minAmount);
        uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array(_tag), createUint256Array(minAmount), createUint256Array(maxAmount));
        setAccountMinMaxTokenBalanceRuleSingleAction(ActionTypes.BURN, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        ///Add Tag to account
        address[3] memory tempAddresses = [_user1, _user2, _user3];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addTag(tempAddresses[i], _tag); ///add tag
        for (uint i; i < tempAddresses.length; i++) assertTrue(applicationAppManager.hasTag(tempAddresses[i], _tag));
        ///perform transfer that checks rule
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        // make sure the minimum rules fail results in revert
        vm.expectRevert(abi.encodeWithSignature("UnderMinBalance()"));
        applicationCoin.burn(1);
    }


    /* Test SELL only */
    function testERC20_ApplicationERC20Fuzz_AccountMinMaxTokenBalance_Sell_UnderMinBalance(bytes32 _tag, uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        _amountSeed = uint24(bound(uint256(_amountSeed), 1, 167770));
        switchToAppAdministrator();
        if (_tag == "") _tag = bytes32("TEST");
        (address _user1, address _user2, address _user3) = _get3RandomAddresses(_addressIndex);
        // set up amounts
        uint256 maxAmount = _amountSeed * 100;
        uint256 minAmount = _amountSeed;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, minAmount, true);
        uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array(_tag), createUint256Array(minAmount), createUint256Array(maxAmount));
        setAccountMinMaxTokenBalanceRuleSingleAction(ActionTypes.SELL, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        ///Add Tag to account
        address[3] memory tempAddresses = [_user1, _user2, _user3];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addTag(tempAddresses[i], _tag); ///add tag
        for (uint i; i < tempAddresses.length; i++) assertTrue(applicationAppManager.hasTag(tempAddresses[i], _tag));
        ///perform transfer that checks rule
        vm.startPrank(_user1, _user1);
        // get the user's current balance
        uint256 balance = applicationCoin.balanceOf(_user1);
        console.log(balance);
        /// Approve transfer        
        applicationCoin.approve(address(amm), balance);
        // make sure the minimum rules fail results in revert
        vm.expectRevert(abi.encodeWithSignature("UnderMinBalance()"));
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), balance, balance, true);
    }
    /* Test All Actions set */
    function testERC20_ApplicationERC20Fuzz_AccountMinMaxTokenBalance_All_OverMaxBalance(bytes32 _tag, uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        if (_tag != "") {
            (address _richUser, address _user1, address _user2, address _user3) = _get4RandomAddresses(_addressIndex);
            // set up amounts
            uint256 maxAmount;
            uint256 minAmount;
            applicationCoin.mint(appAdministrator, type(uint256).max);
            // set up amounts(accounting for too big and too small numbers)
            if (_amountSeed == 0) {
                _amountSeed = 1;
            }
            if (_amountSeed > 167770) {
                _amountSeed = 167770;
            }
            maxAmount = _amountSeed * 100;
            minAmount = maxAmount / 100;
            /// set up a non admin user with tokens
            applicationCoin.transfer(_richUser, maxAmount);
            assertEq(applicationCoin.balanceOf(_richUser), maxAmount);
            applicationCoin.transfer(_user1, maxAmount);
            assertEq(applicationCoin.balanceOf(_user1), maxAmount);
            uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array(_tag), createUint256Array(minAmount), createUint256Array(maxAmount));
            setAccountMinMaxTokenBalanceRule(address(applicationCoinHandler), ruleId);
            switchToAppAdministrator();
            ///Add Tag to account
            address[3] memory tempAddresses = [_user1, _user2, _user3];
            for (uint i; i < tempAddresses.length; i++) applicationAppManager.addTag(tempAddresses[i], _tag); ///add tag
            /// make sure the maximum rule fail results in revert
            vm.startPrank(_richUser);
            vm.expectRevert(abi.encodeWithSignature("OverMaxBalance()"));
            applicationCoin.transfer(_user2, maxAmount + 1);
        }
    }

    /* Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_AccountMinMaxTokenBalance_Transfer_OverMaxBalance(bytes32 _tag, uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        if (_tag != "") {
            (address _richUser, address _user1, address _user2, address _user3) = _get4RandomAddresses(_addressIndex);
            // set up amounts
            uint256 maxAmount;
            uint256 minAmount;
            applicationCoin.mint(appAdministrator, type(uint256).max);
            // set up amounts(accounting for too big and too small numbers)
            if (_amountSeed == 0) {
                _amountSeed = 1;
            }
            if (_amountSeed > 167770) {
                _amountSeed = 167770;
            }
            maxAmount = _amountSeed * 100;
            minAmount = maxAmount / 100;
            /// set up a non admin user with tokens
            applicationCoin.transfer(_richUser, maxAmount);
            assertEq(applicationCoin.balanceOf(_richUser), maxAmount);
            applicationCoin.transfer(_user1, maxAmount);
            assertEq(applicationCoin.balanceOf(_user1), maxAmount);
            uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array(_tag), createUint256Array(minAmount), createUint256Array(maxAmount));
            setAccountMinMaxTokenBalanceRuleSingleAction(ActionTypes.P2P_TRANSFER, address(applicationCoinHandler), ruleId);
            switchToAppAdministrator();
            ///Add Tag to account
            address[3] memory tempAddresses = [_user1, _user2, _user3];
            for (uint i; i < tempAddresses.length; i++) applicationAppManager.addTag(tempAddresses[i], _tag); ///add tag
            /// make sure the maximum rule fail results in revert
            vm.startPrank(_richUser);
            vm.expectRevert(abi.encodeWithSignature("OverMaxBalance()"));
            applicationCoin.transfer(_user2, maxAmount + 1);
        }
    }

    /* Test MINT only */
    function testERC20_ApplicationERC20Fuzz_AccountMinMaxTokenBalance_Mint_OverMaxBalance(bytes32 _tag, uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
         _amountSeed = uint24(bound(uint256(_amountSeed), 1, 167770));
        switchToAppAdministrator();
        if (_tag == "") _tag = bytes32("TEST");
        (address _user1, address _user2, address _user3) = _get3RandomAddresses(_addressIndex);
        // set up amounts
        uint256 maxAmount = _amountSeed * 100;
        uint256 minAmount = _amountSeed;
        uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array(_tag), createUint256Array(minAmount), createUint256Array(maxAmount));
        setAccountMinMaxTokenBalanceRuleSingleAction(ActionTypes.MINT, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        ///Add Tag to account
        address[3] memory tempAddresses = [_user1, _user2, _user3];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addTag(tempAddresses[i], _tag); ///add tag
        for (uint i; i < tempAddresses.length; i++) assertTrue(applicationAppManager.hasTag(tempAddresses[i], _tag));
        ///perform transfer that checks rule
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        vm.expectRevert(abi.encodeWithSignature("OverMaxBalance()"));
        applicationCoin.mint(_user1, maxAmount+1);
    }

    /* Test BURN/SELL NOTE: There is no need to test burn/sell for over min balance since it only checks the transfer to account(which would be zero address) */
    
    /* Test BUY only */
    function testERC20_ApplicationERC20Fuzz_AccountMinMaxTokenBalance_Buy_OverMaxBalance(bytes32 _tag, uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        _amountSeed = uint24(bound(uint256(_amountSeed), 1, 167770));
        switchToAppAdministrator();
        if (_tag == "") _tag = bytes32("TEST");
        (address _user1, address _user2, address _user3) = _get3RandomAddresses(_addressIndex);
        // set up amounts
        uint256 maxAmount = _amountSeed * 100;
        uint256 minAmount = _amountSeed;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, maxAmount, false);
        uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array(_tag), createUint256Array(minAmount), createUint256Array(maxAmount));
        setAccountMinMaxTokenBalanceRuleSingleAction(ActionTypes.BUY, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        ///Add Tag to account
        address[3] memory tempAddresses = [_user1, _user2, _user3];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addTag(tempAddresses[i], _tag); ///add tag
        for (uint i; i < tempAddresses.length; i++) assertTrue(applicationAppManager.hasTag(tempAddresses[i], _tag));
        ///perform transfer that checks rule
        vm.startPrank(_user1, _user1);
        /// Approve transfer
        applicationCoin2.approve(address(amm), maxAmount);
        /// Buy some applicationCoin
        vm.expectRevert(abi.encodeWithSignature("OverMaxBalance()"));
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), maxAmount, maxAmount+1, false);
    }

    /** Test all actions */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracle_All_Positive(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user2, address _user3) = _get3RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, 100000);
        assertEq(applicationCoin.balanceOf(_user1), 100000);

        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        setAccountApproveDenyOracleRule(address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user3);
        oracleDenied.addToDeniedList(badBoys);
        // test that the oracle works
        // This one should pass
        ///perform transfer that checks rule
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        applicationCoin.transfer(_user2, 10);
        assertEq(applicationCoin.balanceOf(_user2), 10);
    }

    /** Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracle_Transfer_Positive(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user2, address _user3) = _get3RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, 100000);
        assertEq(applicationCoin.balanceOf(_user1), 100000);

        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        setAccountApproveDenyOracleRuleSingleAction(ActionTypes.P2P_TRANSFER, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user3);
        oracleDenied.addToDeniedList(badBoys);
        // test that the oracle works
        // This one should pass
        ///perform transfer that checks rule
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        applicationCoin.transfer(_user2, 10);
        assertEq(applicationCoin.balanceOf(_user2), 10);
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracle_Mint_Positive(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        (address _user1, address _user2) = _get2RandomAddresses(_addressIndex);
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        setAccountApproveDenyOracleRuleSingleAction(ActionTypes.MINT, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user2);
        oracleDenied.addToDeniedList(badBoys);
        // test that the oracle works
        ///perform transfer that checks rule
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        applicationCoin.mint(_user1, 10);
        assertEq(applicationCoin.balanceOf(_user1), 10);
    }

    /** Test BURN only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracle_Burn_Positive(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint64).max);
        (address _user1, address _user2) = _get2RandomAddresses(_addressIndex);
        // transfer tokens to standard user
        applicationCoin.transfer(_user1, 100);
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        setAccountApproveDenyOracleRuleSingleAction(ActionTypes.BURN, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user2);
        oracleDenied.addToDeniedList(badBoys);
        // test that the oracle works
        ///perform transfer that checks rule
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        applicationCoin.burn(10);
        assertEq(applicationCoin.balanceOf(_user1), 90);
    }

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracle_Buy_Positive(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        uint256 transferAmount = 10;
        (address _user1, address _user2) = _get2RandomAddresses(_addressIndex);
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, transferAmount, false);
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        setAccountApproveDenyOracleRuleSingleAction(ActionTypes.BUY, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user2);
        oracleDenied.addToDeniedList(badBoys);
        vm.startPrank(_user1, _user1);
        /// Approve transfer
        applicationCoin2.approve(address(amm), transferAmount);
        /// Buy some applicationCoin
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), transferAmount, transferAmount, false);
        assertEq(applicationCoin.balanceOf(_user1), transferAmount);
    }

    /** Test SELL only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracle_Sell_Positive(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        uint256 transferAmount = 10;
        (address _user1, address _user2) = _get2RandomAddresses(_addressIndex);
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, transferAmount, true);
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        setAccountApproveDenyOracleRuleSingleAction(ActionTypes.SELL, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user2);
        oracleDenied.addToDeniedList(badBoys);
        vm.startPrank(_user1, _user1);
        /// Approve transfer
        applicationCoin.approve(address(amm), transferAmount);
        /// Buy some applicationCoin
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), transferAmount, transferAmount, true);
        assertEq(applicationCoin2.balanceOf(_user1), transferAmount);
    }

    /** All Actions */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracle_All_Denied(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user3) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, 100000);
        assertEq(applicationCoin.balanceOf(_user1), 100000);

        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        setAccountApproveDenyOracleRule(address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user3);
        oracleDenied.addToDeniedList(badBoys);
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        applicationCoin.transfer(_user3, 10);
        assertEq(applicationCoin.balanceOf(_user3), 0);
    }

     /** Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracle_Transfer_Denied(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user3) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, 100000);
        assertEq(applicationCoin.balanceOf(_user1), 100000);

        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        setAccountApproveDenyOracleRuleSingleAction(ActionTypes.P2P_TRANSFER, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user3);
        oracleDenied.addToDeniedList(badBoys);
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        applicationCoin.transfer(_user3, 10);
        assertEq(applicationCoin.balanceOf(_user3), 0);
    }

    /** Test BURN only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracle_Burn_Denied(uint8 _addressIndex) public endWithStopPrank {
        (address _user1) = _get1RandomAddress(_addressIndex);
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint64).max);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, 100000);
        assertEq(applicationCoin.balanceOf(_user1), 100000);
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        setAccountApproveDenyOracleRuleSingleAction(ActionTypes.BURN, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user1);
        oracleDenied.addToDeniedList(badBoys);
        ///perform transfer that checks rule
        vm.startPrank(_user1, _user1);
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        applicationCoin.burn(10);
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracle_Mint_Denied(uint8 _addressIndex) public endWithStopPrank {
        (address _user1) = _get1RandomAddress(_addressIndex);

        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        setAccountApproveDenyOracleRuleSingleAction(ActionTypes.MINT, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user1);
        oracleDenied.addToDeniedList(badBoys);
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        applicationCoin.mint(_user1,10);
    }

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracle_Buy_Denied(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        uint256 transferAmount = 10;
        (address _user1) = _get1RandomAddress(_addressIndex);
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, transferAmount, false);
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        setAccountApproveDenyOracleRuleSingleAction(ActionTypes.BUY, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user1);
        oracleDenied.addToDeniedList(badBoys);
        vm.startPrank(_user1, _user1);
        ///perform transfer that checks rule
        /// Approve transfer
        applicationCoin2.approve(address(amm), transferAmount);
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        /// Buy some applicationCoin
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), transferAmount, transferAmount, false);
    }

    /** Test SELL only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracle_Sell_Denied(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        uint256 transferAmount = 10;
        (address _user1) = _get1RandomAddress(_addressIndex);
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, transferAmount, true);
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        setAccountApproveDenyOracleRuleSingleAction(ActionTypes.SELL, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user1);
        oracleDenied.addToDeniedList(badBoys);
        vm.startPrank(_user1, _user1);
        ///perform transfer that checks rule
        /// Approve transfer
        applicationCoin.approve(address(amm), transferAmount);
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        /// Buy some applicationCoin
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), transferAmount, transferAmount, true);
    }

    /** Test All Actions */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracle_All_NotApproved(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user3) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, 100000);
        assertEq(applicationCoin.balanceOf(_user1), 100000);

        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(1);
        setAccountApproveDenyOracleRule(address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        applicationCoin.transfer(_user3, 10);
        assertEq(applicationCoin.balanceOf(_user3), 0);
    }

    /** Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracle_Transfer_NotApproved(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user3) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, 100000);
        assertEq(applicationCoin.balanceOf(_user1), 100000);

        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(1);
        setAccountApproveDenyOracleRuleSingleAction(ActionTypes.P2P_TRANSFER, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        applicationCoin.transfer(_user3, 10);
        assertEq(applicationCoin.balanceOf(_user3), 0);
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracle_Mint_NotApproved(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user3) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, 100000);
        assertEq(applicationCoin.balanceOf(_user1), 100000);

        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(1);
        setAccountApproveDenyOracleRuleSingleAction(ActionTypes.MINT, address(applicationCoinHandler), ruleId);
        vm.startPrank(_user3, _user3);
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        applicationCoin.mint(_user3, 10);
    }

    /** Test BURN only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracle_Burn_NotApproved(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user3) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, 100000);
        assertEq(applicationCoin.balanceOf(_user1), 100000);

        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(1);
        setAccountApproveDenyOracleRuleSingleAction(ActionTypes.BURN, address(applicationCoinHandler), ruleId);
        vm.startPrank(_user3, _user3);
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        applicationCoin.burn( 10);
    }

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracle_Buy_NotApproved(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        uint256 transferAmount = 10;
        (address _user1) = _get1RandomAddress(_addressIndex);
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, transferAmount, false);
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(1);
        setAccountApproveDenyOracleRuleSingleAction(ActionTypes.BUY, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user1);
        oracleDenied.addToDeniedList(badBoys);
        vm.startPrank(_user1, _user1);
        ///perform transfer that checks rule
        /// Approve transfer
        applicationCoin2.approve(address(amm), transferAmount);
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        /// Buy some applicationCoin
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), transferAmount, transferAmount, false);
    }

    /** Test SELL only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracle_Sell_NotApproved(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        uint256 transferAmount = 10;
        (address _user1) = _get1RandomAddress(_addressIndex);
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, transferAmount, true);
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(1);
        setAccountApproveDenyOracleRuleSingleAction(ActionTypes.SELL, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user1);
        oracleDenied.addToDeniedList(badBoys);
        vm.startPrank(_user1, _user1);
        ///perform transfer that checks rule
        /// Approve transfer
        applicationCoin.approve(address(amm), transferAmount);
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        /// Buy some applicationCoin
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), transferAmount, transferAmount, true);
    }

    /** Test all actions */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracleFlexible_All_Positive(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user2, address _user3) = _get3RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, 100000);
        assertEq(applicationCoin.balanceOf(_user1), 100000);

        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(0, 3);
        setAccountApproveDenyOracleFlexibleRule(address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user3);
        oracleDenied.addToDeniedList(badBoys);
        // test that the oracle works
        // This one should pass
        ///perform transfer that checks rule
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        applicationCoin.transfer(_user2, 10);
        assertEq(applicationCoin.balanceOf(_user2), 10);
    }

    /** Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracleFlexible_Transfer_Positive(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user2, address _user3) = _get3RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, 100000);
        assertEq(applicationCoin.balanceOf(_user1), 100000);

        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(0, 3);
        setAccountApproveDenyOracleFlexibleRuleSingleAction(ActionTypes.P2P_TRANSFER, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user3);
        oracleDenied.addToDeniedList(badBoys);
        // test that the oracle works
        // This one should pass
        ///perform transfer that checks rule
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        applicationCoin.transfer(_user2, 10);
        assertEq(applicationCoin.balanceOf(_user2), 10);
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracleFlexible_Mint_Positive(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        (address _user1, address _user2) = _get2RandomAddresses(_addressIndex);
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(0, 3);
        setAccountApproveDenyOracleFlexibleRuleSingleAction(ActionTypes.MINT, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user2);
        oracleDenied.addToDeniedList(badBoys);
        // test that the oracle works
        ///perform transfer that checks rule
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        applicationCoin.mint(_user1, 10);
        assertEq(applicationCoin.balanceOf(_user1), 10);
    }

    /** Test BURN only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracleFlexible_Burn_Positive(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint64).max);
        (address _user1, address _user2) = _get2RandomAddresses(_addressIndex);
        // transfer tokens to standard user
        applicationCoin.transfer(_user1, 100);
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(0, 3);
        setAccountApproveDenyOracleFlexibleRuleSingleAction(ActionTypes.BURN, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user2);
        oracleDenied.addToDeniedList(badBoys);
        // test that the oracle works
        ///perform transfer that checks rule
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        applicationCoin.burn(10);
        assertEq(applicationCoin.balanceOf(_user1), 90);
    }

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracleFlexible_Buy_Positive(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        uint256 transferAmount = 10;
        (address _user1, address _user2) = _get2RandomAddresses(_addressIndex);
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, transferAmount, false);
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(0, 3);
        setAccountApproveDenyOracleFlexibleRuleSingleAction(ActionTypes.BUY, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user2);
        oracleDenied.addToDeniedList(badBoys);
        vm.startPrank(_user1, _user1);
        /// Approve transfer
        applicationCoin2.approve(address(amm), transferAmount);
        /// Buy some applicationCoin
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), transferAmount, transferAmount, false);
        assertEq(applicationCoin.balanceOf(_user1), transferAmount);
    }

    /** Test SELL only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracleFlexible_Sell_Positive(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        uint256 transferAmount = 10;
        (address _user1, address _user2) = _get2RandomAddresses(_addressIndex);
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, transferAmount, true);
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(0, 3);
        setAccountApproveDenyOracleFlexibleRuleSingleAction(ActionTypes.SELL, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user2);
        oracleDenied.addToDeniedList(badBoys);
        vm.startPrank(_user1, _user1);
        /// Approve transfer
        applicationCoin.approve(address(amm), transferAmount);
        /// Buy some applicationCoin
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), transferAmount, transferAmount, true);
        assertEq(applicationCoin2.balanceOf(_user1), transferAmount);
    }

    /** All Actions */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracleFlexible_All_Denied(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user3) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, 100000);
        assertEq(applicationCoin.balanceOf(_user1), 100000);

        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(0, 3);
        setAccountApproveDenyOracleFlexibleRule(address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user3);
        oracleDenied.addToDeniedList(badBoys);
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        applicationCoin.transfer(_user3, 10);
        assertEq(applicationCoin.balanceOf(_user3), 0);
    }

     /** Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracleFlexible_Transfer_Denied(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user3) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, 100000);
        assertEq(applicationCoin.balanceOf(_user1), 100000);

        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(0, 3);
        setAccountApproveDenyOracleFlexibleRuleSingleAction(ActionTypes.P2P_TRANSFER, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user3);
        oracleDenied.addToDeniedList(badBoys);
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        applicationCoin.transfer(_user3, 10);
        assertEq(applicationCoin.balanceOf(_user3), 0);
    }

    /** Test BURN only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracleFlexible_Burn_Denied(uint8 _addressIndex) public endWithStopPrank {
        (address _user1) = _get1RandomAddress(_addressIndex);
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint64).max);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, 100000);
        assertEq(applicationCoin.balanceOf(_user1), 100000);
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(0, 3);
        setAccountApproveDenyOracleFlexibleRuleSingleAction(ActionTypes.BURN, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user1);
        oracleDenied.addToDeniedList(badBoys);
        ///perform transfer that checks rule
        vm.startPrank(_user1, _user1);
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        applicationCoin.burn(10);
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracleFlexible_Mint_Denied(uint8 _addressIndex) public endWithStopPrank {
        (address _user1) = _get1RandomAddress(_addressIndex);

        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(0, 3);
        setAccountApproveDenyOracleFlexibleRuleSingleAction(ActionTypes.MINT, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user1);
        oracleDenied.addToDeniedList(badBoys);
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        applicationCoin.mint(_user1,10);
    }

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracleFlexible_Buy_Denied(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        uint256 transferAmount = 10;
        (address _user1) = _get1RandomAddress(_addressIndex);
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, transferAmount, false);
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(0, 3);
        setAccountApproveDenyOracleFlexibleRuleSingleAction(ActionTypes.BUY, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user1);
        oracleDenied.addToDeniedList(badBoys);
        vm.startPrank(_user1, _user1);
        ///perform transfer that checks rule
        /// Approve transfer
        applicationCoin2.approve(address(amm), transferAmount);
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        /// Buy some applicationCoin
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), transferAmount, transferAmount, false);
    }

    /** Test SELL only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracleFlexible_Sell_Denied(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        uint256 transferAmount = 10;
        (address _user1) = _get1RandomAddress(_addressIndex);
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, transferAmount, true);
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(0, 3);
        setAccountApproveDenyOracleFlexibleRuleSingleAction(ActionTypes.SELL, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user1);
        oracleDenied.addToDeniedList(badBoys);
        vm.startPrank(_user1, _user1);
        ///perform transfer that checks rule
        /// Approve transfer
        applicationCoin.approve(address(amm), transferAmount);
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        /// Buy some applicationCoin
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), transferAmount, transferAmount, true);
    }

    /** Test All Actions */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracleFlexible_All_NotApproved(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user3) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, 100000);
        assertEq(applicationCoin.balanceOf(_user1), 100000);

        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(1, 0);
        setAccountApproveDenyOracleFlexibleRule(address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        applicationCoin.transfer(_user3, 10);
        assertEq(applicationCoin.balanceOf(_user3), 0);
    }

    /** Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracleFlexible_Transfer_NotApproved(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user3) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, 100000);
        assertEq(applicationCoin.balanceOf(_user1), 100000);

        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(1, 0);
        setAccountApproveDenyOracleFlexibleRuleSingleAction(ActionTypes.P2P_TRANSFER, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        applicationCoin.transfer(_user3, 10);
        assertEq(applicationCoin.balanceOf(_user3), 0);
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracleFlexible_Mint_NotApproved(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user3) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, 100000);
        assertEq(applicationCoin.balanceOf(_user1), 100000);

        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(1, 0);
        setAccountApproveDenyOracleFlexibleRuleSingleAction(ActionTypes.MINT, address(applicationCoinHandler), ruleId);
        vm.startPrank(_user3, _user3);
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        applicationCoin.mint(_user3, 10);
    }

    /** Test BURN only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracleFlexible_Burn_NotApproved(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user3) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, 100000);
        assertEq(applicationCoin.balanceOf(_user1), 100000);

        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(1, 0);
        setAccountApproveDenyOracleFlexibleRuleSingleAction(ActionTypes.BURN, address(applicationCoinHandler), ruleId);
        vm.startPrank(_user3, _user3);
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        applicationCoin.burn( 10);
    }

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracleFlexible_Buy_NotApproved(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        uint256 transferAmount = 10;
        (address _user1) = _get1RandomAddress(_addressIndex);
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, transferAmount, false);
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(1, 0);
        setAccountApproveDenyOracleFlexibleRuleSingleAction(ActionTypes.BUY, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user1);
        oracleDenied.addToDeniedList(badBoys);
        vm.startPrank(_user1, _user1);
        ///perform transfer that checks rule
        /// Approve transfer
        applicationCoin2.approve(address(amm), transferAmount);
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        /// Buy some applicationCoin
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), transferAmount, transferAmount, false);
    }

    /** Test SELL only */
    function testERC20_ApplicationERC20Fuzz_AccountApproveDenyOracleFlexible_Sell_NotApproved(uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        uint256 transferAmount = 10;
        (address _user1) = _get1RandomAddress(_addressIndex);
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, transferAmount, true);
        // add the rule.
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleFlexibleRule(1, 0);
        setAccountApproveDenyOracleFlexibleRuleSingleAction(ActionTypes.SELL, address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        // add a blocked address
        badBoys.push(_user1);
        oracleDenied.addToDeniedList(badBoys);
        vm.startPrank(_user1, _user1);
        ///perform transfer that checks rule
        /// Approve transfer
        applicationCoin.approve(address(amm), transferAmount);
        // This one should fail
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        /// Buy some applicationCoin
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), transferAmount, transferAmount, true);
    }

    function _parameterizeRiskAndPeriod(uint8 _risk, uint8 _period) internal pure returns (uint8 period, uint8 risk) {
        period = _period > 6 ? _period / 6 + 1 : 1;
        risk = _parameterizeRisk(_risk);
    }
    /** Test All Actions */
    function testERC20_ApplicationERC20Fuzz_MaxTxSizePerPeriodByRiskRuleERC20_NextPeriod_All_Negative(uint8 _risk, uint8 _period) public endWithStopPrank {
        vm.warp(Blocktime);
        /// we create the rule
        uint8[] memory _riskScore = createUint8Array(25, 50, 75);
        (uint8 period, uint8 risk) = _parameterizeRiskAndPeriod(_risk, _period);
        /// we give some trillions to user1 to spend
        applicationCoin.mint(user1, 10_000_000_000_000 * (10 ** 18));

        /// we register the rule in the protocol
        uint32 ruleId = createAccountMaxTxValueByRiskRule(_riskScore, createUint48Array(100_000_000, 10_000, 1), period);
        setAccountMaxTxValueByRiskRule(ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);
        /// we jump to the next period and make sure it still works.
        vm.warp(block.timestamp + (uint256(period) * 1 hours) / 2);
        vm.stopPrank();
        vm.startPrank(user1, user1);
        applicationCoin.transfer(user2, 1 * (10 ** 18));

        /// let's go to the future in the middle of the period
        vm.warp(block.timestamp + (9 * (uint256(period) * 1 hours)) / 2);

        /// TEST RULE ON SENDER
        /// first we send only 1 token which shouldn't trigger any risk check
        applicationCoin.transfer(user2, 1);
        console.log(risk);
        /// let's go to the future in the middle of the period
        vm.warp(block.timestamp + (uint256(period) * 1 hours) / 2);
        /// now, if the user's risk profile is in the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        }
        applicationCoin.transfer(user2, 1 * (10 ** 18));
        /// 2
        /// if the user's risk profile is in the second to the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        }
        applicationCoin.transfer(user2, 10_000 * (10 ** 18) - 1);
        /// 10_001
        /// if the user's risk profile is in the second to the lowest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        applicationCoin.transfer(user2, 100_000_000 * (10 ** 18) - 10_000 * (10 ** 18));
        /// 100_000_000 - 10_000 + 10_001 = 100_000_000 + 1 = 100_000_001
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        applicationCoin.transfer(user2, 1_000_000_000_000 * (10 ** 18) - 100_000_000 * (10 ** 18));
    }

    /** Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_MaxTxSizePerPeriodByRiskRuleERC20_NextPeriod_Transfer_Negative(uint8 _risk, uint8 _period) public endWithStopPrank {
        vm.warp(Blocktime);
        /// we create the rule
        uint8[] memory _riskScore = createUint8Array(25, 50, 75);
        (uint8 period, uint8 risk) = _parameterizeRiskAndPeriod(_risk, _period);
        /// we give some trillions to user1 to spend
        applicationCoin.mint(user1, 10_000_000_000_000 * (10 ** 18));

        /// we register the rule in the protocol
        uint32 ruleId = createAccountMaxTxValueByRiskRule(_riskScore, createUint48Array(100_000_000, 10_000, 1), period);
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.P2P_TRANSFER, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);
        /// we jump to the next period and make sure it still works.
        vm.warp(block.timestamp + (uint256(period) * 1 hours) / 2);
        vm.stopPrank();
        vm.startPrank(user1, user1);
        applicationCoin.transfer(user2, 1 * (10 ** 18));

        /// let's go to the future in the middle of the period
        vm.warp(block.timestamp + (9 * (uint256(period) * 1 hours)) / 2);

        /// TEST RULE ON SENDER
        /// first we send only 1 token which shouldn't trigger any risk check
        applicationCoin.transfer(user2, 1);
        console.log(risk);
        /// let's go to the future in the middle of the period
        vm.warp(block.timestamp + (uint256(period) * 1 hours) / 2);
        /// now, if the user's risk profile is in the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        }
        applicationCoin.transfer(user2, 1 * (10 ** 18));
        /// 2
        /// if the user's risk profile is in the second to the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        }
        applicationCoin.transfer(user2, 10_000 * (10 ** 18) - 1);
        /// 10_001
        /// if the user's risk profile is in the second to the lowest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        applicationCoin.transfer(user2, 100_000_000 * (10 ** 18) - 10_000 * (10 ** 18));
        /// 100_000_000 - 10_000 + 10_001 = 100_000_000 + 1 = 100_000_001
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        applicationCoin.transfer(user2, 1_000_000_000_000 * (10 ** 18) - 100_000_000 * (10 ** 18));
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_MaxTxSizePerPeriodByRiskRuleERC20_NextPeriod_Mint_Negative(uint8 _risk, uint8 _period) public endWithStopPrank {
        vm.warp(Blocktime);
        /// we create the rule
        uint8[] memory _riskScore = createUint8Array(25, 50, 75);
        (uint8 period, uint8 risk) = _parameterizeRiskAndPeriod(_risk, _period);

        /// we register the rule in the protocol
        uint32 ruleId = createAccountMaxTxValueByRiskRule(_riskScore, createUint48Array(100_000_000, 10_000, 1), period);
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.MINT, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);
        /// we jump to the next period and make sure it still works.
        vm.warp(block.timestamp + (uint256(period) * 1 hours) / 2);
        vm.stopPrank();
        vm.startPrank(user1, user1);
        applicationCoin.mint(user1, 1 * (10 ** 18));

        /// let's go to the future in the middle of the period
        vm.warp(block.timestamp + (9 * (uint256(period) * 1 hours)) / 2);

        /// TEST RULE ON SENDER
        /// first we send only 1 token which shouldn't trigger any risk check
        applicationCoin.mint(user1, 1);
        console.log(risk);
        /// let's go to the future in the middle of the period
        vm.warp(block.timestamp + (uint256(period) * 1 hours) / 2);
        /// now, if the user's risk profile is in the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        }
        applicationCoin.mint(user1, 1 * (10 ** 18));
        /// 2
        /// if the user's risk profile is in the second to the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        }
        applicationCoin.mint(user1, 10_000 * (10 ** 18) - 1);
        /// 10_001
        /// if the user's risk profile is in the second to the lowest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        applicationCoin.mint(user1, 100_000_000 * (10 ** 18) - 10_000 * (10 ** 18));
        /// 100_000_000 - 10_000 + 10_001 = 100_000_000 + 1 = 100_000_001
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        applicationCoin.mint(user1, 1_000_000_000_000 * (10 ** 18) - 100_000_000 * (10 ** 18));
    }

    /** Test BURN only */
    function testERC20_ApplicationERC20Fuzz_MaxTxSizePerPeriodByRiskRuleERC20_NextPeriod_Burn_Negative(uint8 _risk, uint8 _period) public endWithStopPrank {
        vm.warp(Blocktime);
        /// we create the rule
        uint8[] memory _riskScore = createUint8Array(25, 50, 75);
        (uint8 period, uint8 risk) = _parameterizeRiskAndPeriod(_risk, _period);
        /// we give some trillions to user1 to spend
        applicationCoin.mint(user1, 10_000_000_000_000 * (10 ** 18));

        /// we register the rule in the protocol
        uint32 ruleId = createAccountMaxTxValueByRiskRule(_riskScore, createUint48Array(100_000_000, 10_000, 1), period);
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.BURN, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);
        /// we jump to the next period and make sure it still works.
        vm.warp(block.timestamp + (uint256(period) * 1 hours) / 2);
        vm.stopPrank();
        vm.startPrank(user1, user1);
        applicationCoin.burn(1 * (10 ** 18));

        /// let's go to the future in the middle of the period
        vm.warp(block.timestamp + (9 * (uint256(period) * 1 hours)) / 2);

        /// TEST RULE ON SENDER
        /// first we send only 1 token which shouldn't trigger any risk check
        applicationCoin.burn(1);
        console.log(risk);
        /// let's go to the future in the middle of the period
        vm.warp(block.timestamp + (uint256(period) * 1 hours) / 2);
        /// now, if the user's risk profile is in the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        }
        applicationCoin.burn(1 * (10 ** 18));
        /// 2
        /// if the user's risk profile is in the second to the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        }
        applicationCoin.burn(10_000 * (10 ** 18) - 1);
        /// 10_001
        /// if the user's risk profile is in the second to the lowest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        applicationCoin.burn(100_000_000 * (10 ** 18) - 10_000 * (10 ** 18));
        /// 100_000_000 - 10_000 + 10_001 = 100_000_000 + 1 = 100_000_001
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        applicationCoin.burn(1_000_000_000_000 * (10 ** 18) - 100_000_000 * (10 ** 18));
    }

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_MaxTxSizePerPeriodByRiskRuleERC20_NextPeriod_Buy_Negative(uint8 _risk, uint8 _period) public endWithStopPrank {
        vm.warp(Blocktime);
        /// we create the rule
        uint8[] memory _riskScore = createUint8Array(25, 50, 75);
        (uint8 period, uint8 risk) = _parameterizeRiskAndPeriod(_risk, _period);
        uint256 supply = 10_000_000_000_000 * (10 ** 18);
        uint256 tradeAmount;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, user1, supply, false);

        /// we register the rule in the protocol
        uint32 ruleId = createAccountMaxTxValueByRiskRule(_riskScore, createUint48Array(100_000_000, 10_000, 1), period);
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.BUY, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);
        /// we jump to the next period and make sure it still works.
        vm.warp(block.timestamp + (uint256(period) * 1 hours) / 2);
        vm.stopPrank();
        vm.startPrank(user1, user1);
        /// Approve all the transfers
        applicationCoin2.approve(address(amm), supply);
        /// Buy some applicationCoin
        tradeAmount = 1 * (10 ** 18);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);

        /// let's go to the future in the middle of the period
        vm.warp(block.timestamp + (9 * (uint256(period) * 1 hours)) / 2);

        /// TEST RULE ON SENDER
        /// first we send only 1 token which shouldn't trigger any risk check
        tradeAmount = 1;
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
        console.log(risk);
        /// let's go to the future in the middle of the period
        vm.warp(block.timestamp + (uint256(period) * 1 hours) / 2);
        /// now, if the user's risk profile is in the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        }
        tradeAmount = 1 * (10 ** 18);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
        /// 2
        /// if the user's risk profile is in the second to the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        }
        tradeAmount = 10_000 * (10 ** 18) - 1;
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
        /// 10_001
        /// if the user's risk profile is in the second to the lowest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        tradeAmount = 100_000_000 * (10 ** 18) - 10_000 * (10 ** 18);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
        /// 100_000_000 - 10_000 + 10_001 = 100_000_000 + 1 = 100_000_001
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        tradeAmount = 1_000_000_000_000 * (10 ** 18) - 100_000_000 * (10 ** 18);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
    }
    /** Test All Actions */
    function testERC20_ApplicationERC20Fuzz_MaxTxSizePerPeriodByRiskRuleERC20_Simple_All_Positive(uint8 _risk, uint8 _period) public endWithStopPrank {
        vm.warp(Blocktime);
        /// we create the rule parameters
        uint8[] memory _riskScore = createUint8Array(25, 50, 75);
        (uint8 period, uint8 risk) = _parameterizeRiskAndPeriod(_risk, _period);
        /// we give some trillions to user1 to spend
        applicationCoin.mint(user1, 10_000_000_000_000 * (10 ** 18));

        /// we create and register the rule in the protocol
        uint32 ruleId = createAccountMaxTxValueByRiskRule(_riskScore, createUint48Array(100_000_000, 10_000, 1), period);
        setAccountMaxTxValueByRiskRule(ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        /// we start the prank exactly at the time when the rule starts taking effect + 1 full period + 1 minute
        uint256 startTestAt = (block.timestamp + (uint256(period) * (1 hours)) + 1 minutes);
        vm.warp(startTestAt);

        /// TEST RULE ON SENDER
        /// we start making transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);
        /// Transfer 1 token to ensure valid transaction passes
        applicationCoin.transfer(user2, 1);
    }

    /** Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_MaxTxSizePerPeriodByRiskRuleERC20_Simple_Transfer_Positive(uint8 _risk, uint8 _period) public endWithStopPrank {
        vm.warp(Blocktime);
        /// we create the rule parameters
        uint8[] memory _riskScore = createUint8Array(25, 50, 75);
        (uint8 period, uint8 risk) = _parameterizeRiskAndPeriod(_risk, _period);
        /// we give some trillions to user1 to spend
        applicationCoin.mint(user1, 10_000_000_000_000 * (10 ** 18));

        /// we create and register the rule in the protocol
        uint32 ruleId = createAccountMaxTxValueByRiskRule(_riskScore, createUint48Array(100_000_000, 10_000, 1), period);
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.P2P_TRANSFER, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        /// we start the prank exactly at the time when the rule starts taking effect + 1 full period + 1 minute
        uint256 startTestAt = (block.timestamp + (uint256(period) * (1 hours)) + 1 minutes);
        vm.warp(startTestAt);

        /// TEST RULE ON SENDER
        /// we start making transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);
        /// Transfer 1 token to ensure valid transaction passes
        applicationCoin.transfer(user2, 1);
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_MaxTxSizePerPeriodByRiskRuleERC20_Simple_Mint_Positive(uint8 _risk, uint8 _period) public endWithStopPrank {
        vm.warp(Blocktime);
        /// we create the rule parameters
        uint8[] memory _riskScore = createUint8Array(25, 50, 75);
        (uint8 period, uint8 risk) = _parameterizeRiskAndPeriod(_risk, _period);

        /// we create and register the rule in the protocol
        uint32 ruleId = createAccountMaxTxValueByRiskRule(_riskScore, createUint48Array(100_000_000, 10_000, 1), period);
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.MINT, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        /// we start the prank exactly at the time when the rule starts taking effect + 1 full period + 1 minute
        uint256 startTestAt = (block.timestamp + (uint256(period) * (1 hours)) + 1 minutes);
        vm.warp(startTestAt);

        /// TEST RULE ON SENDER
        /// we start making transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);
        /// Transfer 1 token to ensure valid transaction passes
        applicationCoin.mint(user1, 1);
    }

    /** Test BURN only */
    function testERC20_ApplicationERC20Fuzz_MaxTxSizePerPeriodByRiskRuleERC20_Simple_Burn_Positive(uint8 _risk, uint8 _period) public endWithStopPrank {
        vm.warp(Blocktime);
        /// we create the rule parameters
        uint8[] memory _riskScore = createUint8Array(25, 50, 75);
        (uint8 period, uint8 risk) = _parameterizeRiskAndPeriod(_risk, _period);
        /// we give some trillions to user1 to spend
        applicationCoin.mint(user1, 10_000_000_000_000 * (10 ** 18));

        /// we create and register the rule in the protocol
        uint32 ruleId = createAccountMaxTxValueByRiskRule(_riskScore, createUint48Array(100_000_000, 10_000, 1), period);
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.BURN, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        /// we start the prank exactly at the time when the rule starts taking effect + 1 full period + 1 minute
        uint256 startTestAt = (block.timestamp + (uint256(period) * (1 hours)) + 1 minutes);
        vm.warp(startTestAt);

        /// TEST RULE ON SENDER
        /// we start making transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);
        /// Transfer 1 token to ensure valid transaction passes
        applicationCoin.burn(1);
    }

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_MaxTxSizePerPeriodByRiskRuleERC20_Simple_Buy_Positive(uint8 _risk, uint8 _period) public endWithStopPrank {
        vm.warp(Blocktime);
        /// we create the rule parameters
        uint8[] memory _riskScore = createUint8Array(25, 50, 75);
        (uint8 period, uint8 risk) = _parameterizeRiskAndPeriod(_risk, _period);
        uint256 supply = 10_000_000_000_000 * (10 ** 18);
        uint256 tradeAmount;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, user1, supply, false);

        /// we create and register the rule in the protocol
        uint32 ruleId = createAccountMaxTxValueByRiskRule(_riskScore, createUint48Array(100_000_000, 10_000, 1), period);
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.BURN, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        /// we start the prank exactly at the time when the rule starts taking effect + 1 full period + 1 minute
        uint256 startTestAt = (block.timestamp + (uint256(period) * (1 hours)) + 1 minutes);
        vm.warp(startTestAt);

        /// TEST RULE ON SENDER
        /// we start making transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);
        /// Approve all the transfers
        applicationCoin2.approve(address(amm), supply);
        /// Transfer 1 token to ensure valid transaction passes
        tradeAmount = 1;
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
    }

    /** Test SELL only */
    function testERC20_ApplicationERC20Fuzz_MaxTxSizePerPeriodByRiskRuleERC20_Simple_Sell_Positive(uint8 _risk, uint8 _period) public endWithStopPrank {
        vm.warp(Blocktime);
        /// we create the rule parameters
        uint8[] memory _riskScore = createUint8Array(25, 50, 75);
        (uint8 period, uint8 risk) = _parameterizeRiskAndPeriod(_risk, _period);
        uint256 supply = 10_000_000_000_000 * (10 ** 18);
        uint256 tradeAmount;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, user1, supply, true);

        /// we create and register the rule in the protocol
        uint32 ruleId = createAccountMaxTxValueByRiskRule(_riskScore, createUint48Array(100_000_000, 10_000, 1), period);
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.SELL, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        /// we start the prank exactly at the time when the rule starts taking effect + 1 full period + 1 minute
        uint256 startTestAt = (block.timestamp + (uint256(period) * (1 hours)) + 1 minutes);
        vm.warp(startTestAt);

        /// TEST RULE ON SENDER
        /// we start making transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);
        /// Approve all the transfers
        applicationCoin.approve(address(amm), supply);
        /// Transfer 1 token to ensure valid transaction passes
        tradeAmount = 1;
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, true);
    }

    /** Test All Actions */
    function testERC20_ApplicationERC20Fuzz_MaxTxSizePerPeriodByRiskRuleERC20_Simple_All_Negative(uint8 _risk, uint8 _period) public endWithStopPrank {
        vm.warp(Blocktime);
        /// we create the rule
        uint8[] memory _riskScore = createUint8Array(25, 50, 75);
        (uint8 period, uint8 risk) = _parameterizeRiskAndPeriod(_risk, _period);
        /// we give some trillions to user1 to spend
        applicationCoin.mint(user1, 10_000_000_000_000 * (10 ** 18));

        /// we register the rule in the protocol
        uint32 ruleId = createAccountMaxTxValueByRiskRule(_riskScore, createUint48Array(100_000_000, 10_000, 1), period);
        setAccountMaxTxValueByRiskRule(ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        /// we start the prank exactly at the time when the rule starts taking effect + 1 full period + 1 minute
        uint256 startTestAt = (block.timestamp + (uint256(period) * (1 hours)) + 1 minutes);
        vm.warp(startTestAt);

        /// TEST RULE ON SENDER
        /// we start making transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);
        /// first we send only 1 token which shouldn't trigger any risk check
        applicationCoin.transfer(user2, 1);

        /// let's go to the future in the middle of the period
        vm.warp(block.timestamp + (uint256(period) * 1 hours) / 2);
        /// now, if the user's risk profile is in the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        }
        console.log(risk);
        applicationCoin.transfer(user2, 1 * (10 ** 18));
        /// 2
        /// if the user's risk profile is in the second to the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        }
        console.log(risk);
        applicationCoin.transfer(user2, 10_000 * (10 ** 18) - 1);
        /// 10_001
        /// if the user's risk profile is in the lowest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        console.log(risk);
        applicationCoin.transfer(user2, 100_000_000 * (10 ** 18) - 10_000 * (10 ** 18));
        /// 100_000_000 - 10_000 + 10_001 = 100_000_000 + 1 = 100_000_001
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        console.log(risk);
        applicationCoin.transfer(user2, 1_000_000_000_000 * (10 ** 18) - 100_000_000 * (10 ** 18));
        /// if passed: 1_000_000_000_000 - 100_000_000 + 100_000_001 = 1_000_000_000_000 + 1 = 1_000_000_000_001
    }

    /** Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_MaxTxSizePerPeriodByRiskRuleERC20_Simple_Transfer_Negative(uint8 _risk, uint8 _period) public endWithStopPrank {
        vm.warp(Blocktime);
        /// we create the rule
        uint8[] memory _riskScore = createUint8Array(25, 50, 75);
        (uint8 period, uint8 risk) = _parameterizeRiskAndPeriod(_risk, _period);
        /// we give some trillions to user1 to spend
        applicationCoin.mint(user1, 10_000_000_000_000 * (10 ** 18));

        /// we register the rule in the protocol
        uint32 ruleId = createAccountMaxTxValueByRiskRule(_riskScore, createUint48Array(100_000_000, 10_000, 1), period);
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.P2P_TRANSFER, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        /// we start the prank exactly at the time when the rule starts taking effect + 1 full period + 1 minute
        uint256 startTestAt = (block.timestamp + (uint256(period) * (1 hours)) + 1 minutes);
        vm.warp(startTestAt);

        /// TEST RULE ON SENDER
        /// we start making transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);
        /// first we send only 1 token which shouldn't trigger any risk check
        applicationCoin.transfer(user2, 1);

        /// let's go to the future in the middle of the period
        vm.warp(block.timestamp + (uint256(period) * 1 hours) / 2);
        /// now, if the user's risk profile is in the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        }
        console.log(risk);
        applicationCoin.transfer(user2, 1 * (10 ** 18));
        /// 2
        /// if the user's risk profile is in the second to the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        }
        console.log(risk);
        applicationCoin.transfer(user2, 10_000 * (10 ** 18) - 1);
        /// 10_001
        /// if the user's risk profile is in the lowest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        console.log(risk);
        applicationCoin.transfer(user2, 100_000_000 * (10 ** 18) - 10_000 * (10 ** 18));
        /// 100_000_000 - 10_000 + 10_001 = 100_000_000 + 1 = 100_000_001
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        console.log(risk);
        applicationCoin.transfer(user2, 1_000_000_000_000 * (10 ** 18) - 100_000_000 * (10 ** 18));
        /// if passed: 1_000_000_000_000 - 100_000_000 + 100_000_001 = 1_000_000_000_000 + 1 = 1_000_000_000_001
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_MaxTxSizePerPeriodByRiskRuleERC20_Simple_Mint_Negative(uint8 _risk, uint8 _period) public endWithStopPrank {
        vm.warp(Blocktime);
        /// we create the rule
        uint8[] memory _riskScore = createUint8Array(25, 50, 75);
        (uint8 period, uint8 risk) = _parameterizeRiskAndPeriod(_risk, _period);

        /// we register the rule in the protocol
        uint32 ruleId = createAccountMaxTxValueByRiskRule(_riskScore, createUint48Array(100_000_000, 10_000, 1), period);
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.MINT, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        /// we start the prank exactly at the time when the rule starts taking effect + 1 full period + 1 minute
        uint256 startTestAt = (block.timestamp + (uint256(period) * (1 hours)) + 1 minutes);
        vm.warp(startTestAt);

        /// TEST RULE ON SENDER
        /// we start making transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);
        /// first we send only 1 token which shouldn't trigger any risk check
        applicationCoin.mint(user1, 1);

        /// let's go to the future in the middle of the period
        vm.warp(block.timestamp + (uint256(period) * 1 hours) / 2);
        /// now, if the user's risk profile is in the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        }
        console.log(risk);
        applicationCoin.mint(user1, 1 * (10 ** 18));
        /// 2
        /// if the user's risk profile is in the second to the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        }
        console.log(risk);
        applicationCoin.mint(user1, 10_000 * (10 ** 18) - 1);
        /// 10_001
        /// if the user's risk profile is in the lowest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        console.log(risk);
        applicationCoin.mint(user1, 100_000_000 * (10 ** 18) - 10_000 * (10 ** 18));
        /// 100_000_000 - 10_000 + 10_001 = 100_000_000 + 1 = 100_000_001
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        console.log(risk);
        applicationCoin.mint(user1, 1_000_000_000_000 * (10 ** 18) - 100_000_000 * (10 ** 18));
        /// if passed: 1_000_000_000_000 - 100_000_000 + 100_000_001 = 1_000_000_000_000 + 1 = 1_000_000_000_001
    }

    /** Test BURN only */
    function testERC20_ApplicationERC20Fuzz_MaxTxSizePerPeriodByRiskRuleERC20_Simple_Burn_Negative(uint8 _risk, uint8 _period) public endWithStopPrank {
        vm.warp(Blocktime);
        /// we create the rule
        uint8[] memory _riskScore = createUint8Array(25, 50, 75);
        (uint8 period, uint8 risk) = _parameterizeRiskAndPeriod(_risk, _period);
        /// we give some trillions to user1 to spend
        applicationCoin.mint(user1, 10_000_000_000_000 * (10 ** 18));

        /// we register the rule in the protocol
        uint32 ruleId = createAccountMaxTxValueByRiskRule(_riskScore, createUint48Array(100_000_000, 10_000, 1), period);
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.BURN, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        /// we start the prank exactly at the time when the rule starts taking effect + 1 full period + 1 minute
        uint256 startTestAt = (block.timestamp + (uint256(period) * (1 hours)) + 1 minutes);
        vm.warp(startTestAt);

        /// TEST RULE ON SENDER
        /// we start making transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);
        /// first we send only 1 token which shouldn't trigger any risk check
        applicationCoin.burn(1);

        /// let's go to the future in the middle of the period
        vm.warp(block.timestamp + (uint256(period) * 1 hours) / 2);
        /// now, if the user's risk profile is in the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        }
        console.log(risk);
        applicationCoin.burn(1 * (10 ** 18));
        /// 2
        /// if the user's risk profile is in the second to the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        }
        console.log(risk);
        applicationCoin.burn(10_000 * (10 ** 18) - 1);
        /// 10_001
        /// if the user's risk profile is in the lowest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        console.log(risk);
        applicationCoin.burn(100_000_000 * (10 ** 18) - 10_000 * (10 ** 18));
        /// 100_000_000 - 10_000 + 10_001 = 100_000_000 + 1 = 100_000_001
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        console.log(risk);
        applicationCoin.burn(1_000_000_000_000 * (10 ** 18) - 100_000_000 * (10 ** 18));
        /// if passed: 1_000_000_000_000 - 100_000_000 + 100_000_001 = 1_000_000_000_000 + 1 = 1_000_000_000_001
    }

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_MaxTxSizePerPeriodByRiskRuleERC20_Simple_Buy_Negative(uint8 _risk, uint8 _period) public endWithStopPrank {
        vm.warp(Blocktime);
        /// we create the rule
        uint8[] memory _riskScore = createUint8Array(25, 50, 75);
        (uint8 period, uint8 risk) = _parameterizeRiskAndPeriod(_risk, _period);
        uint256 supply = 10_000_000_000_000 * (10 ** 18);
        uint256 tradeAmount;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, user1, supply, false);

        /// we register the rule in the protocol
        uint32 ruleId = createAccountMaxTxValueByRiskRule(_riskScore, createUint48Array(100_000_000, 10_000, 1), period);
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.BUY, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        /// we start the prank exactly at the time when the rule starts taking effect + 1 full period + 1 minute
        uint256 startTestAt = (block.timestamp + (uint256(period) * (1 hours)) + 1 minutes);
        vm.warp(startTestAt);

        /// TEST RULE ON SENDER
        /// we start making transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);
        /// Approve all the transfers
        applicationCoin2.approve(address(amm), supply);
        /// first we send only 1 token which shouldn't trigger any risk check
        tradeAmount = 1;
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
        /// let's go to the future in the middle of the period
        vm.warp(block.timestamp + (uint256(period) * 1 hours) / 2);
        /// now, if the user's risk profile is in the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        }
        console.log(risk);
        tradeAmount = 1 * (10 ** 18);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
        /// 2
        /// if the user's risk profile is in the second to the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        }
        console.log(risk);
        tradeAmount = 10_000 * (10 ** 18) - 1;
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
        /// 10_001
        /// if the user's risk profile is in the lowest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        console.log(risk);
        tradeAmount = 100_000_000 * (10 ** 18) - 10_000 * (10 ** 18);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
        /// 100_000_000 - 10_000 + 10_001 = 100_000_000 + 1 = 100_000_001
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        console.log(risk);
        tradeAmount = 1_000_000_000_000 * (10 ** 18) - 100_000_000 * (10 ** 18);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
        /// if passed: 1_000_000_000_000 - 100_000_000 + 100_000_001 = 1_000_000_000_000 + 1 = 1_000_000_000_001
    }

    /** Test SELL only */
    function testERC20_ApplicationERC20Fuzz_MaxTxSizePerPeriodByRiskRuleERC20_Simple_Sell_Negative(uint8 _risk, uint8 _period) public endWithStopPrank {
        vm.warp(Blocktime);
        /// we create the rule
        uint8[] memory _riskScore = createUint8Array(25, 50, 75);
        (uint8 period, uint8 risk) = _parameterizeRiskAndPeriod(_risk, _period);
        uint256 supply = 10_000_000_000_000 * (10 ** 18);
        uint256 tradeAmount;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, user1, supply, true);

        /// we register the rule in the protocol
        uint32 ruleId = createAccountMaxTxValueByRiskRule(_riskScore, createUint48Array(100_000_000, 10_000, 1), period);
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.SELL, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        /// we start the prank exactly at the time when the rule starts taking effect + 1 full period + 1 minute
        uint256 startTestAt = (block.timestamp + (uint256(period) * (1 hours)) + 1 minutes);
        vm.warp(startTestAt);

        /// TEST RULE ON SENDER
        /// we start making transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);
        /// Approve all the transfers
        applicationCoin.approve(address(amm), supply);
        /// first we send only 1 token which shouldn't trigger any risk check
        tradeAmount = 1;
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, true);
        /// let's go to the future in the middle of the period
        vm.warp(block.timestamp + (uint256(period) * 1 hours) / 2);
        /// now, if the user's risk profile is in the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        }
        console.log(risk);
        tradeAmount = 1 * (10 ** 18);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, true);
        /// 2
        /// if the user's risk profile is in the second to the highest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        }
        console.log(risk);
        tradeAmount = 10_000 * (10 ** 18) - 1;
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, true);
        /// 10_001
        /// if the user's risk profile is in the lowest range, this transfer should revert
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        console.log(risk);
        tradeAmount = 100_000_000 * (10 ** 18) - 10_000 * (10 ** 18);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, true);
        /// 100_000_000 - 10_000 + 10_001 = 100_000_000 + 1 = 100_000_001
        if (risk >= _riskScore[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= _riskScore[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        } else if (risk >= _riskScore[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 100000000000000000000000000));
        }
        console.log(risk);
        tradeAmount = 1_000_000_000_000 * (10 ** 18) - 100_000_000 * (10 ** 18);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, true);
        /// if passed: 1_000_000_000_000 - 100_000_000 + 100_000_001 = 1_000_000_000_000 + 1 = 1_000_000_000_001
    }

    /** Test All actions */
    function testERC20_ApplicationERC20Fuzz_TransactionLimitByRiskScore_All_Positive(uint8 _risk) public endWithStopPrank {
        uint8 risk = _parameterizeRisk(_risk);
        uint8[] memory riskScores = createUint8Array(25, 50, 75);
        // make sure it at least always falls into the range
        risk = uint8(bound(uint256(risk), 0, 75));
        ///Give tokens to user1
        applicationCoin.mint(user1, 100000000 * (10 ** 18));

        ///Activate rule
        uint32 ruleId = createAccountMaxTxValueByRiskRule(riskScores, createUint48Array(100_000_000, 10_000, 1));
        setAccountMaxTxValueByRiskRule(ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);

        applicationCoin.transfer(user2, 1);
    }

    /** Test Transfer only */
    function testERC20_ApplicationERC20Fuzz_TransactionLimitByRiskScore_Transfer_Positive(uint8 _risk) public endWithStopPrank {
        uint8 risk = _parameterizeRisk(_risk);
        uint8[] memory riskScores = createUint8Array(25, 50, 75);
        // make sure it at least always falls into the range
        risk = uint8(bound(uint256(risk), 0, 75));
        ///Give tokens to user1
        applicationCoin.mint(user1, 100000000 * (10 ** 18));

        ///Activate rule
        uint32 ruleId = createAccountMaxTxValueByRiskRule(riskScores, createUint48Array(100_000_000, 10_000, 1));
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.P2P_TRANSFER, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);

        applicationCoin.transfer(user2, 1);
    }

    /** Test Mint only */
    function testERC20_ApplicationERC20Fuzz_TransactionLimitByRiskScore_Mint_Positive(uint8 _risk) public endWithStopPrank {
        uint8 risk = _parameterizeRisk(_risk);
        uint8[] memory riskScores = createUint8Array(25, 50, 75);
        // make sure it at least always falls into the range
        risk = uint8(bound(uint256(risk), 0, 75));

        ///Activate rule
        uint32 ruleId = createAccountMaxTxValueByRiskRule(riskScores, createUint48Array(100_000_000, 10_000, 1));
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.MINT, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);

        applicationCoin.mint(user1, 1);
    }

    /** Test BURN only */
    function testERC20_ApplicationERC20Fuzz_TransactionLimitByRiskScore_Burn_Positive(uint8 _risk) public endWithStopPrank {
        uint8 risk = _parameterizeRisk(_risk);
        uint8[] memory riskScores = createUint8Array(25, 50, 75);
        // make sure it at least always falls into the range
        risk = uint8(bound(uint256(risk), 0, 75));
        ///Give tokens to user1
        applicationCoin.mint(user1, 100000000 * (10 ** 18));

        ///Activate rule
        uint32 ruleId = createAccountMaxTxValueByRiskRule(riskScores, createUint48Array(100_000_000, 10_000, 1));
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.BURN, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);

        applicationCoin.burn(1);
    }

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_TransactionLimitByRiskScore_Buy_Positive(uint8 _risk) public endWithStopPrank {
        uint8 risk = _parameterizeRisk(_risk);
        uint8[] memory riskScores = createUint8Array(25, 50, 75);
        // make sure it at least always falls into the range
        risk = uint8(bound(uint256(risk), 0, 75));
        ///Give tokens to user1
        uint256 supply = 100000000 * (10 ** 18);
        uint256 tradeAmount;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, user1, supply, false);

        ///Activate rule
        uint32 ruleId = createAccountMaxTxValueByRiskRule(riskScores, createUint48Array(100_000_000, 10_000, 1));
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.BUY, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);
        /// Approve all the transfers
        applicationCoin2.approve(address(amm), supply);

        tradeAmount = 1;
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
    }

    /** Test SELL only */
    function testERC20_ApplicationERC20Fuzz_TransactionLimitByRiskScore_Sell_Positive(uint8 _risk) public endWithStopPrank {
        uint8 risk = _parameterizeRisk(_risk);
        uint8[] memory riskScores = createUint8Array(25, 50, 75);
        // make sure it at least always falls into the range
        risk = uint8(bound(uint256(risk), 0, 75));
        ///Give tokens to user1
        uint256 supply = 100000000 * (10 ** 18);
        uint256 tradeAmount;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, user1, supply, true);

        ///Activate rule
        uint32 ruleId = createAccountMaxTxValueByRiskRule(riskScores, createUint48Array(100_000_000, 10_000, 1));
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.SELL, ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);
        /// Approve all the transfers
        applicationCoin.approve(address(amm), supply);

        tradeAmount = 1;
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, true);
    }

    /** Test All actions */
    function testERC20_ApplicationERC20Fuzz_TransactionLimitByRiskScore_All_Negative(uint8 _risk) public endWithStopPrank {
        uint8 risk = _parameterizeRisk(_risk);
        uint8[] memory riskScores = createUint8Array(25, 50, 75);
        // make sure it at least always falls into the range
        risk = uint8(bound(uint256(risk), 0, 75));
        ///Give tokens to user1 and user2
        applicationCoin.mint(user1, 100000000 * (10 ** 18));

        ///Activate rule
        uint32 ruleId = createAccountMaxTxValueByRiskRule(riskScores, createUint48Array(100_000_000, 10_000, 1));
        setAccountMaxTxValueByRiskRule(ruleId);
        /// we set a risk score for user1 and user 2
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);

        if (risk >= riskScores[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        }
        applicationCoin.transfer(user2, 11 * (10 ** 18));

        if (risk >= riskScores[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= riskScores[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        }
        applicationCoin.transfer(user2, 10001 * (10 ** 18));
    }

    /** Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_TransactionLimitByRiskScore_Transfer_Negative(uint8 _risk) public endWithStopPrank {
        uint8 risk = _parameterizeRisk(_risk);
        uint8[] memory riskScores = createUint8Array(25, 50, 75);
        // make sure it at least always falls into the range
        risk = uint8(bound(uint256(risk), 0, 75));
        ///Give tokens to user1 and user2
        applicationCoin.mint(user1, 100000000 * (10 ** 18));

        ///Activate rule
        uint32 ruleId = createAccountMaxTxValueByRiskRule(riskScores, createUint48Array(100_000_000, 10_000, 1));
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.P2P_TRANSFER, ruleId);
        /// we set a risk score for user1 and user 2
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);

        if (risk >= riskScores[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        }
        applicationCoin.transfer(user2, 11 * (10 ** 18));

        if (risk >= riskScores[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= riskScores[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        }
        applicationCoin.transfer(user2, 10001 * (10 ** 18));
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_TransactionLimitByRiskScore_Mint_Negative(uint8 _risk) public endWithStopPrank {
        uint8 risk = _parameterizeRisk(_risk);
        uint8[] memory riskScores = createUint8Array(25, 50, 75);
        // make sure it at least always falls into the range
        risk = uint8(bound(uint256(risk), 0, 75));

        ///Activate rule
        uint32 ruleId = createAccountMaxTxValueByRiskRule(riskScores, createUint48Array(100_000_000, 10_000, 1));
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.MINT, ruleId);
        /// we set a risk score for user1 and user 2
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);

        if (risk >= riskScores[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        }
        applicationCoin.mint(user1, 11 * (10 ** 18));

        if (risk >= riskScores[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= riskScores[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        }
        applicationCoin.mint(user1, 10001 * (10 ** 18));
    }

    /** Test BURN only */
    function testERC20_ApplicationERC20Fuzz_TransactionLimitByRiskScore_Burn_Negative(uint8 _risk) public endWithStopPrank {
        uint8 risk = _parameterizeRisk(_risk);
        uint8[] memory riskScores = createUint8Array(25, 50, 75);
        // make sure it at least always falls into the range
        risk = uint8(bound(uint256(risk), 0, 75));
        ///Give tokens to user1 and user2
        applicationCoin.mint(user1, 100000000 * (10 ** 18));

        ///Activate rule
        uint32 ruleId = createAccountMaxTxValueByRiskRule(riskScores, createUint48Array(100_000_000, 10_000, 1));
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.BURN, ruleId);
        /// we set a risk score for user1 and user 2
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);

        if (risk >= riskScores[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        }
        applicationCoin.burn(11 * (10 ** 18));

        if (risk >= riskScores[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= riskScores[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        }
        applicationCoin.burn(10001 * (10 ** 18));
    }

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_TransactionLimitByRiskScore_Buy_Negative(uint8 _risk) public endWithStopPrank {
        uint8 risk = _parameterizeRisk(_risk);
        uint8[] memory riskScores = createUint8Array(25, 50, 75);
        // make sure it at least always falls into the range
        risk = uint8(bound(uint256(risk), 0, 75));
        ///Give tokens to user1 and user2
        uint256 supply = 100000000 * (10 ** 18);
        uint256 tradeAmount;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, user1, supply, false);
        ///Activate rule
        uint32 ruleId = createAccountMaxTxValueByRiskRule(riskScores, createUint48Array(100_000_000, 10_000, 1));
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.BUY, ruleId);
        /// we set a risk score for user1 and user 2
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);
        /// Approve all the transfers
        applicationCoin2.approve(address(amm), supply);
        if (risk >= riskScores[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        }
        tradeAmount = 11 * (10 ** 18);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);

        if (risk >= riskScores[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= riskScores[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        }
        tradeAmount = 10001 * (10 ** 18);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
    }

    /** Test SELL only */
    function testERC20_ApplicationERC20Fuzz_TransactionLimitByRiskScore_Sell_Negative(uint8 _risk) public endWithStopPrank {
        uint8 risk = _parameterizeRisk(_risk);
        uint8[] memory riskScores = createUint8Array(25, 50, 75);
        // make sure it at least always falls into the range
        risk = uint8(bound(uint256(risk), 0, 75));
        ///Give tokens to user1 and user2
        uint256 supply = 100000000 * (10 ** 18);
        uint256 tradeAmount;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, user1, supply, true);
        ///Activate rule
        uint32 ruleId = createAccountMaxTxValueByRiskRule(riskScores, createUint48Array(100_000_000, 10_000, 1));
        setAccountMaxTxValueByRiskRuleSingleAction(ActionTypes.SELL, ruleId);
        /// we set a risk score for user1 and user 2
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(user1, risk);

        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(user1, user1);
        /// Approve all the transfers
        applicationCoin.approve(address(amm), supply);
        if (risk >= riskScores[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        }
        tradeAmount = 11 * (10 ** 18);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, true);

        if (risk >= riskScores[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 1000000000000000000));
        } else if (risk >= riskScores[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, risk, 10000000000000000000000));
        }
        tradeAmount = 10001 * (10 ** 18);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, true);
    }

    /** Test All actions */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByRiskScore_All_Positive(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user2, address _user3, address _user4) = _get4RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, type(uint256).max);
        assertEq(applicationCoin.balanceOf(_user1), type(uint256).max);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        uint48 riskBalance1 = _amountSeed + 1000;
        uint48 riskBalance2 = _amountSeed + 500;
        uint48 riskBalance3 = _amountSeed + 100;
        // add the rule.
        uint8[] memory _riskScore = createUint8Array(25, 50, 75, 90);
        uint32 ruleId = createAccountMaxValueByRiskRule(_riskScore, createUint48Array(riskBalance1, riskBalance2, riskBalance3, 1));
        setAccountMaxValueByRiskRule(ruleId);
        /// we set a risk score for user2, user3 and user4
        switchToRiskAdmin();
        address[3] memory tempAddresses = [_user4, _user3, _user2];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addRiskScore(tempAddresses[i], _riskScore[i + 1]);

        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        ///Max riskScore allows for single token balance
        applicationCoin.transfer(_user2, 1 * (10 ** 18));
    }

    /** Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByRiskScore_Transfer_Positive(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user2, address _user3, address _user4) = _get4RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, type(uint256).max);
        assertEq(applicationCoin.balanceOf(_user1), type(uint256).max);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        uint48 riskBalance1 = _amountSeed + 1000;
        uint48 riskBalance2 = _amountSeed + 500;
        uint48 riskBalance3 = _amountSeed + 100;
        // add the rule.
        uint8[] memory _riskScore = createUint8Array(25, 50, 75, 90);
        uint32 ruleId = createAccountMaxValueByRiskRule(_riskScore, createUint48Array(riskBalance1, riskBalance2, riskBalance3, 1));
        setAccountMaxValueByRiskRuleSingleAction(ActionTypes.P2P_TRANSFER, ruleId);
        /// we set a risk score for user2, user3 and user4
        switchToRiskAdmin();
        address[3] memory tempAddresses = [_user4, _user3, _user2];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addRiskScore(tempAddresses[i], _riskScore[i + 1]);

        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        ///Max riskScore allows for single token balance
        applicationCoin.transfer(_user2, 1 * (10 ** 18));
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByRiskScore_Mint_Positive(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        (address _user1, address _user2, address _user3, address _user4) = _get4RandomAddresses(_addressIndex);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        uint48 riskBalance1 = _amountSeed + 1000;
        uint48 riskBalance2 = _amountSeed + 500;
        uint48 riskBalance3 = _amountSeed + 100;
        // add the rule.
        uint8[] memory _riskScore = createUint8Array(25, 50, 75, 90);
        uint32 ruleId = createAccountMaxValueByRiskRule(_riskScore, createUint48Array(riskBalance1, riskBalance2, riskBalance3, 1));
        setAccountMaxValueByRiskRuleSingleAction(ActionTypes.MINT, ruleId);
        /// we set a risk score for user2, user3 and user4
        switchToRiskAdmin();
        address[3] memory tempAddresses = [_user4, _user3, _user2];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addRiskScore(tempAddresses[i], _riskScore[i + 1]);

        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        ///Max riskScore allows for single token balance
        applicationCoin.mint(_user1, 1 * (10 ** 18));
    }

    /** BURN/SELL is not allowed for AccountMaxValueByRiskScore */

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByRiskScore_Buy_Positive(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        (address _user1, address _user2, address _user3, address _user4) = _get4RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        uint256 supply = 100000000 * (10 ** 18);
        uint256 tradeAmount;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, supply, false);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        uint48 riskBalance1 = _amountSeed + 1000;
        uint48 riskBalance2 = _amountSeed + 500;
        uint48 riskBalance3 = _amountSeed + 100;
        // add the rule.
        uint8[] memory _riskScore = createUint8Array(25, 50, 75, 90);
        uint32 ruleId = createAccountMaxValueByRiskRule(_riskScore, createUint48Array(riskBalance1, riskBalance2, riskBalance3, 1));
        setAccountMaxValueByRiskRuleSingleAction(ActionTypes.BUY, ruleId);
        /// we set a risk score for user2, user3 and user4
        switchToRiskAdmin();
        address[3] memory tempAddresses = [_user4, _user3, _user2];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addRiskScore(tempAddresses[i], _riskScore[i + 1]);

        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        /// Approve all the transfers
        applicationCoin2.approve(address(amm), supply);
        ///Max riskScore allows for single token balance
        tradeAmount = 1 * (10 ** 18);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
    }

    /** Test All Actions */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByRiskScore_All_Negative(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user2, address _user3, address _user4) = _get4RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, type(uint256).max);
        assertEq(applicationCoin.balanceOf(_user1), type(uint256).max);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        // Values greater than 5 will cause an overflow
        if (_amountSeed > 5) {
            _amountSeed = 5;
        }
        uint48 riskBalance1 = _amountSeed + 10;
        uint48 riskBalance2 = _amountSeed + 5;
        uint48 riskBalance3 = _amountSeed + 1;
        uint48 riskBalance4 = _amountSeed;
        // add the rule.
        uint8[] memory _riskScore = createUint8Array(25, 50, 75, 90);
        uint32 ruleId = createAccountMaxValueByRiskRule(_riskScore, createUint48Array(riskBalance1, riskBalance2, riskBalance3, 1));
        setAccountMaxValueByRiskRule(ruleId);
        /// we set a risk score for user2, user3 and user4
        switchToRiskAdmin();
        address[3] memory tempAddresses = [_user4, _user3, _user2];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addRiskScore(tempAddresses[i], _riskScore[i + 1]);
        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        ///Transfer more than Risk Score allows
        vm.expectRevert(abi.encodeWithSignature("OverMaxAccValueByRiskScore()"));
        applicationCoin.transfer(_user2, riskBalance4 * (10 ** 18) + 1);
        vm.expectRevert(abi.encodeWithSignature("OverMaxAccValueByRiskScore()"));
        applicationCoin.transfer(_user3, riskBalance3 * (10 ** 18) + 1);
        vm.expectRevert(abi.encodeWithSignature("OverMaxAccValueByRiskScore()"));
        applicationCoin.transfer(_user4, riskBalance1 * (10 ** 18) + 1);
    }

    /** Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByRiskScore_Transfer_Negative(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user2, address _user3, address _user4) = _get4RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, type(uint256).max);
        assertEq(applicationCoin.balanceOf(_user1), type(uint256).max);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        // Values greater than 5 will cause an overflow
        if (_amountSeed > 5) {
            _amountSeed = 5;
        }
        uint48 riskBalance1 = _amountSeed + 10;
        uint48 riskBalance2 = _amountSeed + 5;
        uint48 riskBalance3 = _amountSeed + 1;
        uint48 riskBalance4 = _amountSeed;
        // add the rule.
        uint8[] memory _riskScore = createUint8Array(25, 50, 75, 90);
        uint32 ruleId = createAccountMaxValueByRiskRule(_riskScore, createUint48Array(riskBalance1, riskBalance2, riskBalance3, 1));
        setAccountMaxValueByRiskRuleSingleAction(ActionTypes.P2P_TRANSFER, ruleId);
        /// we set a risk score for user2, user3 and user4
        switchToRiskAdmin();
        address[3] memory tempAddresses = [_user4, _user3, _user2];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addRiskScore(tempAddresses[i], _riskScore[i + 1]);
        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        ///Transfer more than Risk Score allows
        vm.expectRevert(abi.encodeWithSignature("OverMaxAccValueByRiskScore()"));
        applicationCoin.transfer(_user2, riskBalance4 * (10 ** 18) + 1);
        vm.expectRevert(abi.encodeWithSignature("OverMaxAccValueByRiskScore()"));
        applicationCoin.transfer(_user3, riskBalance3 * (10 ** 18) + 1);
        vm.expectRevert(abi.encodeWithSignature("OverMaxAccValueByRiskScore()"));
        applicationCoin.transfer(_user4, riskBalance1 * (10 ** 18) + 1);
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByRiskScore_Mint_Negative(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user2, address _user3, address _user4) = _get4RandomAddresses(_addressIndex);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        // Values greater than 5 will cause an overflow
        if (_amountSeed > 5) {
            _amountSeed = 5;
        }
        uint48 riskBalance1 = _amountSeed + 10;
        uint48 riskBalance2 = _amountSeed + 5;
        uint48 riskBalance3 = _amountSeed + 1;
        uint48 riskBalance4 = _amountSeed;
        // add the rule.
        uint8[] memory _riskScore = createUint8Array(25, 50, 75, 90);
        uint32 ruleId = createAccountMaxValueByRiskRule(_riskScore, createUint48Array(riskBalance1, riskBalance2, riskBalance3, 1));
        setAccountMaxValueByRiskRuleSingleAction(ActionTypes.MINT, ruleId);
        /// we set a risk score for user2, user3 and user4
        switchToRiskAdmin();
        address[3] memory tempAddresses = [_user4, _user3, _user2];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addRiskScore(tempAddresses[i], _riskScore[i + 1]);
        ///Execute transfers
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        ///Transfer more than Risk Score allows
        vm.expectRevert(abi.encodeWithSignature("OverMaxAccValueByRiskScore()"));
        applicationCoin.mint(_user2, riskBalance4 * (10 ** 18) + 1);
        vm.expectRevert(abi.encodeWithSignature("OverMaxAccValueByRiskScore()"));
        applicationCoin.mint(_user3, riskBalance3 * (10 ** 18) + 1);
        vm.expectRevert(abi.encodeWithSignature("OverMaxAccValueByRiskScore()"));
        applicationCoin.mint(_user4, riskBalance1 * (10 ** 18) + 1);
    }

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByRiskScore_Buy_Negative(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        uint256 tradeAmount;
        (address _user1, address _user2, address _user3, address _user4) = _get4RandomAddresses(_addressIndex);
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, type(uint128).max, false);
        {
            // set up amounts(accounting for too big and too small numbers)
            if (_amountSeed == 0) {
                _amountSeed = 1;
            }
            // Values greater than 5 will cause an overflow
            if (_amountSeed > 5) {
                _amountSeed = 5;
            }
        }
        uint48 riskBalance1 = _amountSeed + 10;
        uint48 riskBalance2 = _amountSeed + 5;
        uint48 riskBalance3 = _amountSeed + 1;
        uint48 riskBalance4 = _amountSeed;
        // add the rule.
        uint32 ruleId = createAccountMaxValueByRiskRule(createUint8Array(25, 50, 75, 90), createUint48Array(riskBalance1, riskBalance2, riskBalance3, 1));
        {
            setAccountMaxValueByRiskRuleSingleAction(ActionTypes.BUY, ruleId);
            /// we set a risk score for user2, user3 and user4
            switchToRiskAdmin();
            address[3] memory tempAddresses = [_user4, _user3, _user2];
            for (uint i; i < tempAddresses.length; i++) applicationAppManager.addRiskScore(tempAddresses[i], createUint8Array(25, 50, 75, 90)[i + 1]);
        }
        ///Execute transfers
        {
            vm.stopPrank();
            vm.startPrank(_user2, _user2);
            /// Approve all the transfers
            applicationCoin2.mint(_user2,riskBalance4 * (10 ** 18) + 1);
            applicationCoin2.approve(address(amm), riskBalance4 * (10 ** 18) + 1);
            ///Transfer more than Risk Score allows
            tradeAmount = riskBalance4 * (10 ** 18) + 1;
            vm.expectRevert(abi.encodeWithSignature("OverMaxAccValueByRiskScore()"));
            amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
        }
        {
            vm.stopPrank();
            vm.startPrank(_user3, _user3);
            /// Approve all the transfers
            applicationCoin2.mint(_user3,riskBalance3 * (10 ** 18) + 1);
            applicationCoin2.approve(address(amm), riskBalance3 * (10 ** 18) + 1);
            tradeAmount = riskBalance3 * (10 ** 18) + 1;
            vm.expectRevert(abi.encodeWithSignature("OverMaxAccValueByRiskScore()"));
            amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
        }
        {
            vm.stopPrank();
            vm.startPrank(_user4, _user4);
            /// Approve all the transfers
            applicationCoin2.mint(_user4,riskBalance1 * (10 ** 18) + 1);
            applicationCoin2.approve(address(amm), riskBalance1 * (10 ** 18) + 1);
            tradeAmount = riskBalance1 * (10 ** 18) + 1;
            vm.expectRevert(abi.encodeWithSignature("OverMaxAccValueByRiskScore()"));
            amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
        }
    }

    /** Test All actions */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByAccessLevel_All_Positive(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user3) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, type(uint256).max);
        assertEq(applicationCoin.balanceOf(_user1), type(uint256).max);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _createAccessBalances(_amountSeed);
        // add the rule.
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, accessBalance1, accessBalance2, accessBalance3, accessBalance4);
        setAccountMaxValueByAccessLevelRule(ruleId);

        /// Add access level to _user3
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(_user3, 4);

        /// perform transfer that checks user with AccessLevel and no balances
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        /// this one is within the limit and should pass
        applicationCoin.transfer(_user3, uint256(accessBalance4) * (10 ** 18));
        assertEq(applicationCoin.balanceOf(_user3), uint256(accessBalance4) * (10 ** 18));
    }

    /** Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByAccessLevel_Transfer_Positive(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user3) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, type(uint256).max);
        assertEq(applicationCoin.balanceOf(_user1), type(uint256).max);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _createAccessBalances(_amountSeed);
        // add the rule.
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, accessBalance1, accessBalance2, accessBalance3, accessBalance4);
        setAccountMaxValueByAccessLevelRuleSingleAction(ActionTypes.P2P_TRANSFER, ruleId);

        /// Add access level to _user3
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(_user3, 4);

        /// perform transfer that checks user with AccessLevel and no balances
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        /// this one is within the limit and should pass
        applicationCoin.transfer(_user3, uint256(accessBalance4) * (10 ** 18));
        assertEq(applicationCoin.balanceOf(_user3), uint256(accessBalance4) * (10 ** 18));
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByAccessLevel_Mint_Positive(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        (address _user1, address _user3) = _get2RandomAddresses(_addressIndex);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _createAccessBalances(_amountSeed);
        // add the rule.
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, accessBalance1, accessBalance2, accessBalance3, accessBalance4);
        setAccountMaxValueByAccessLevelRuleSingleAction(ActionTypes.MINT, ruleId);

        /// Add access level to _user3
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(_user3, 4);

        /// perform transfer that checks user with AccessLevel and no balances
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        /// this one is within the limit and should pass
        applicationCoin.mint(_user3, uint256(accessBalance4) * (10 ** 18));
        assertEq(applicationCoin.balanceOf(_user3), uint256(accessBalance4) * (10 ** 18));
    }

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByAccessLevel_Buy_Positive(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        (address _user3) = _get1RandomAddress(_addressIndex);
        uint256 supply = type(uint128).max;
        uint256 tradeAmount;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user3, supply, false);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _createAccessBalances(_amountSeed);
        // add the rule.
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, accessBalance1, accessBalance2, accessBalance3, accessBalance4);
        setAccountMaxValueByAccessLevelRuleSingleAction(ActionTypes.BUY, ruleId);

        /// Add access level to _user3
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(_user3, 4);

        /// perform transfer that checks user with AccessLevel and no balances
        vm.stopPrank();
        vm.startPrank(_user3, _user3);
        /// Approve all the transfers
        applicationCoin2.approve(address(amm), supply);
        /// this one is within the limit and should pass
        tradeAmount = uint256(accessBalance4) * (10 ** 18);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
        assertEq(applicationCoin.balanceOf(_user3), uint256(accessBalance4) * (10 ** 18));
    }

    /** Test All actions */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByAccessLevel_All_NoAccessLevel(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user2) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, type(uint256).max);
        assertEq(applicationCoin.balanceOf(_user1), type(uint256).max);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _createAccessBalances(_amountSeed);
        // add the rule.
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, accessBalance1, accessBalance2, accessBalance3, accessBalance4);
        setAccountMaxValueByAccessLevelRule(ruleId);
        assertTrue(applicationHandler.isAccountMaxValueByAccessLevelActive(ActionTypes.P2P_TRANSFER));
        ///perform transfer that checks rule when account does not have AccessLevel(should fail)
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        vm.expectRevert(0xaee8b993);
        applicationCoin.transfer(_user2, 1);
        assertEq(applicationCoin.balanceOf(_user2), 0);
    }

    /** Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByAccessLevel_Transfer_NoAccessLevel(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user2) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, type(uint256).max);
        assertEq(applicationCoin.balanceOf(_user1), type(uint256).max);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _createAccessBalances(_amountSeed);
        // add the rule.
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, accessBalance1, accessBalance2, accessBalance3, accessBalance4);
        setAccountMaxValueByAccessLevelRuleSingleAction(ActionTypes.P2P_TRANSFER, ruleId);
        assertTrue(applicationHandler.isAccountMaxValueByAccessLevelActive(ActionTypes.P2P_TRANSFER));
        ///perform transfer that checks rule when account does not have AccessLevel(should fail)
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        vm.expectRevert(0xaee8b993);
        applicationCoin.transfer(_user2, 1);
        assertEq(applicationCoin.balanceOf(_user2), 0);
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByAccessLevel_Mint_NoAccessLevel(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        address _user1 = _get1RandomAddress(_addressIndex);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _createAccessBalances(_amountSeed);
        // add the rule.
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, accessBalance1, accessBalance2, accessBalance3, accessBalance4);
        setAccountMaxValueByAccessLevelRuleSingleAction(ActionTypes.MINT, ruleId);
        assertTrue(applicationHandler.isAccountMaxValueByAccessLevelActive(ActionTypes.MINT));
        ///perform transfer that checks rule when account does not have AccessLevel(should fail)
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        vm.expectRevert(0xaee8b993);
        applicationCoin.mint(_user1, 1);
        assertEq(applicationCoin.balanceOf(_user1), 0);
    }

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByAccessLevel_Buy_NoAccessLevel(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        address _user1 = _get1RandomAddress(_addressIndex);
        uint256 supply = type(uint128).max;
        uint256 tradeAmount;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, supply, false);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _createAccessBalances(_amountSeed);
        // add the rule.
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, accessBalance1, accessBalance2, accessBalance3, accessBalance4);
        setAccountMaxValueByAccessLevelRuleSingleAction(ActionTypes.BUY, ruleId);
        ///perform transfer that checks rule when account does not have AccessLevel(should fail)
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        /// Approve all the transfers
        applicationCoin2.approve(address(amm), supply);
        tradeAmount = 1;
        vm.expectRevert(0xaee8b993);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
        assertEq(applicationCoin.balanceOf(_user1), 0);
    }

    /** Test All actions */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByAccessLevel_All_NoBalancesNegative(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user3) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, type(uint256).max);
        assertEq(applicationCoin.balanceOf(_user1), type(uint256).max);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _createAccessBalances(_amountSeed);
        // add the rule.
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, accessBalance1, accessBalance2, accessBalance3, accessBalance4);
        setAccountMaxValueByAccessLevelRule(ruleId);

        // Add access level to _user3
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(_user3, 4);

        /// perform transfer that checks user with AccessLevel and no balances
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        /// this one is over the limit and should fail
        vm.expectRevert(0xaee8b993);
        applicationCoin.transfer(_user3, uint256(accessBalance4) * (10 ** 18) + 1);
    }

    /** Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByAccessLevel_Transfer_NoBalancesNegative(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user3) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, type(uint256).max);
        assertEq(applicationCoin.balanceOf(_user1), type(uint256).max);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _createAccessBalances(_amountSeed);
        // add the rule.
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, accessBalance1, accessBalance2, accessBalance3, accessBalance4);
        setAccountMaxValueByAccessLevelRuleSingleAction(ActionTypes.P2P_TRANSFER, ruleId);

        // Add access level to _user3
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(_user3, 4);

        /// perform transfer that checks user with AccessLevel and no balances
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        /// this one is over the limit and should fail
        vm.expectRevert(0xaee8b993);
        applicationCoin.transfer(_user3, uint256(accessBalance4) * (10 ** 18) + 1);
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByAccessLevel_Mint_NoBalancesNegative(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        address _user3 = _get1RandomAddress(_addressIndex);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _createAccessBalances(_amountSeed);
        // add the rule.
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, accessBalance1, accessBalance2, accessBalance3, accessBalance4);
        setAccountMaxValueByAccessLevelRuleSingleAction(ActionTypes.MINT, ruleId);

        // Add access level to _user3
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(_user3, 4);

        /// perform transfer that checks user with AccessLevel and no balances
        vm.stopPrank();
        vm.startPrank(_user3, _user3);
        /// this one is over the limit and should fail
        vm.expectRevert(0xaee8b993);
        applicationCoin.mint(_user3, uint256(accessBalance4) * (10 ** 18) + 1);
    }

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByAccessLevel_Buy_NoBalancesNegative(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        address _user3 = _get1RandomAddress(_addressIndex);
        uint256 supply = type(uint128).max;
        uint256 tradeAmount;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user3, supply, false);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _createAccessBalances(_amountSeed);
        // add the rule.
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, accessBalance1, accessBalance2, accessBalance3, accessBalance4);
        setAccountMaxValueByAccessLevelRuleSingleAction(ActionTypes.BUY, ruleId);

        // Add access level to _user3
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(_user3, 4);

        /// perform transfer that checks user with AccessLevel and no balances
        vm.stopPrank();
        vm.startPrank(_user3, _user3);
        /// Approve all the transfers
        applicationCoin2.approve(address(amm), supply);
        /// this one is over the limit and should fail
        tradeAmount = uint256(accessBalance4) * (10 ** 18) + 1;
        vm.expectRevert(0xaee8b993);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
        assertEq(applicationCoin.balanceOf(_user3), 0);
    }
    /** Test All actions */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByAccessLevel_All_BalancesNegative(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user4) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, type(uint256).max);
        assertEq(applicationCoin.balanceOf(_user1), type(uint256).max);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _createAccessBalances(_amountSeed);
        // add the rule.
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, accessBalance1, accessBalance2, accessBalance3, accessBalance4);
        setAccountMaxValueByAccessLevelRule(ruleId);

        switchToTreasuryAccount();
        draculaCoin.mint(treasuryAccount, type(uint256).max);

        draculaCoin.transfer(_user1, type(uint256).max);
        assertEq(draculaCoin.balanceOf(_user1), type(uint256).max);
        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(draculaCoin), 1 * (10 ** 18)); //setting at $1
        assertEq(erc20Pricer.getTokenPrice(address(draculaCoin)), 1 * (10 ** 18));
        // set the access level for the user4
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(_user4, 3);

        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        draculaCoin.transfer(_user4, uint256(accessBalance3) * (10 ** 18) - 1 * (10 ** 18));
        uint256 beginningBalance = applicationCoin.balanceOf(_user1);
        /// perform transfer that checks user with AccessLevel and existing balances(should fail because of other balance)
        vm.expectRevert(0xaee8b993);
        applicationCoin.transfer(_user4, 2 * (10 ** 18));
        //Make sure balance didn't change.
        assertEq(applicationCoin.balanceOf(_user1), beginningBalance);
    }

    /** Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByAccessLevel_Transfer_BalancesNegative(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (address _user1, address _user4) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationCoin.transfer(_user1, type(uint256).max);
        assertEq(applicationCoin.balanceOf(_user1), type(uint256).max);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _createAccessBalances(_amountSeed);
        // add the rule.
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, accessBalance1, accessBalance2, accessBalance3, accessBalance4);
        setAccountMaxValueByAccessLevelRuleSingleAction(ActionTypes.P2P_TRANSFER, ruleId);

        switchToTreasuryAccount();
        draculaCoin.mint(treasuryAccount, type(uint256).max);

        draculaCoin.transfer(_user1, type(uint256).max);
        assertEq(draculaCoin.balanceOf(_user1), type(uint256).max);
        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(draculaCoin), 1 * (10 ** 18)); //setting at $1
        assertEq(erc20Pricer.getTokenPrice(address(draculaCoin)), 1 * (10 ** 18));
        // set the access level for the user4
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(_user4, 3);

        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        draculaCoin.transfer(_user4, uint256(accessBalance3) * (10 ** 18) - 1 * (10 ** 18));
        uint256 beginningBalance = applicationCoin.balanceOf(_user1);
        /// perform transfer that checks user with AccessLevel and existing balances(should fail because of other balance)
        vm.expectRevert(0xaee8b993);
        applicationCoin.transfer(_user4, 2 * (10 ** 18));
        //Make sure balance didn't change.
        assertEq(applicationCoin.balanceOf(_user1), beginningBalance);
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByAccessLevel_Mint_BalancesNegative(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        address _user4 = _get1RandomAddress(_addressIndex);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _createAccessBalances(_amountSeed);
        // add the rule.
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, accessBalance1, accessBalance2, accessBalance3, accessBalance4);
        setAccountMaxValueByAccessLevelRuleSingleAction(ActionTypes.MINT, ruleId);

        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(draculaCoin), 1 * (10 ** 18)); //setting at $1
        assertEq(erc20Pricer.getTokenPrice(address(draculaCoin)), 1 * (10 ** 18));
        // set the access level for the user4
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(_user4, 3);

        vm.stopPrank();
        vm.startPrank(_user4, _user4);
        draculaCoin.mint(_user4, uint256(accessBalance3) * (10 ** 18) - 1 * (10 ** 18));
        /// perform transfer that checks user with AccessLevel and existing balances(should fail because of other balance)
        vm.expectRevert(0xaee8b993);
        applicationCoin.mint(_user4, 2 * (10 ** 18));
    }

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_AccountMaxValueByAccessLevel_Buy_BalancesNegative(uint8 _addressIndex, uint24 _amountSeed) public endWithStopPrank {
        switchToAppAdministrator();
        address _user4 = _get1RandomAddress(_addressIndex);
        uint256 supply = type(uint128).max;
        uint256 tradeAmount;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user4, supply, false);
        // set up amounts(accounting for too big and too small numbers)
        if (_amountSeed == 0) {
            _amountSeed = 1;
        }
        if (_amountSeed > 167770) {
            _amountSeed = 167770;
        }
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _createAccessBalances(_amountSeed);
        // add the rule.
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, accessBalance1, accessBalance2, accessBalance3, accessBalance4);
        setAccountMaxValueByAccessLevelRuleSingleAction(ActionTypes.BUY, ruleId);

        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(draculaCoin), 1 * (10 ** 18)); //setting at $1
        assertEq(erc20Pricer.getTokenPrice(address(draculaCoin)), 1 * (10 ** 18));
        // set the access level for the user4
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(_user4, 3);

        vm.stopPrank();
        vm.startPrank(_user4, _user4);
        /// Approve all the transfers
        applicationCoin2.approve(address(amm), supply);
        tradeAmount = uint256(accessBalance3) * (10 ** 18) - 1 * (10 ** 18);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
        /// perform transfer that checks user with AccessLevel and existing balances(should fail because of other balance)
        tradeAmount = 2 * (10 ** 18);
        vm.expectRevert(0xaee8b993);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
    }

    function testERC20_ApplicationERC20Fuzz_AccountMinMaxTokenBalance_Positive2(uint8 _addressIndex, uint256 _amountSeed, bytes32 tag1, bytes32 tag2, bytes32 tag3) public endWithStopPrank {
        switchToAppAdministrator();
        _amountSeed = bound(_amountSeed, 1, 1000);
        if (tag1 == "") tag1 = "TAG1";
        if (tag2 == "") tag2 = "TAG2";
        if (tag3 == "") tag3 = "TAG3";
        if (tag1 == tag2 || tag1 == tag3) {
            tag1 = "TAG1";
            tag2 = "TAG2";
            tag3 = "TAG3";
        }
        applicationCoin.mint(appAdministrator, type(uint256).max);
        (rich_user, user1) = _get2RandomAddresses(_addressIndex);
        // Set up the rule conditions
        vm.warp(Blocktime);
        bytes32[] memory accs = createBytes32Array(tag1, tag2, tag3);
        uint256[] memory minAmounts = createUint256Array((_amountSeed * (10 ** 18)), (_amountSeed + 1000) * (10 ** 18), (_amountSeed + 2000) * (10 ** 18));
        uint256[] memory maxAmounts = createUint256Array(999999 * BIGNUMBER, 99999 * BIGNUMBER, 99999 * BIGNUMBER);
        /// 720 = 1 month, 4380 = 6 months, 17520 = 2 years
        uint16[] memory periods = createUint16Array(720, 4380, 17520);

        switchToAppAdministrator();
        /// load non admin users with application coin
        applicationCoin.transfer(rich_user, (_amountSeed * 10) * (10 ** 18));

        uint32 ruleId = createAccountMinMaxTokenBalanceRule(accs, minAmounts, maxAmounts, periods);
        setAccountMinMaxTokenBalanceRule(address(applicationCoinHandler), ruleId);
        switchToAppAdministrator();
        /// tag the user
        applicationAppManager.addTag(rich_user, tag1); ///add tag
        applicationAppManager.addTag(user1, tag1); ///add tag
        /// switch to the user
        vm.stopPrank();
        vm.startPrank(rich_user, rich_user);
        /// make sure a transfer that is acceptable will still pass within the freeze window.
        uint256 transferAmount = (applicationCoin.balanceOf(rich_user) - (minAmounts[0] - 1)) - 1;
        applicationCoin.transfer(user1, transferAmount);
        assertEq(transferAmount, applicationCoin.balanceOf(user1));
    }

    function testERC20_ApplicationERC20Fuzz_TransactionFeeTable_StandardFee_Positive(uint8 _addressIndex, uint24 _amountSeed, int24 _feeSeed) public endWithStopPrank {
        _amountSeed = uint24(bound(_amountSeed, 1, type(uint24).max / 10000));
        if (_feeSeed > 10000) _feeSeed = 10000;
        if (_feeSeed <= 0) _feeSeed = 1;
        (address fromUser, address treasury, address toUser) = _get3RandomAddresses(_addressIndex);
        uint256 fromUserBalance = type(uint256).max - 1;
        applicationCoin.mint(fromUser, fromUserBalance);
        uint256 maxBalance = type(uint256).max;
        address targetAccount = treasury;
        // create a fee
        switchToRuleAdmin();
        FeesFacet(address(applicationCoinHandler)).addFee("fee", 0, maxBalance, _feeSeed, targetAccount);
        switchToAppAdministrator();
        Fee memory fee = FeesFacet(address(applicationCoinHandler)).getFee("fee");
        assertEq(fee.feePercentage, _feeSeed);
        assertEq(fee.minBalance, 0);
        assertEq(fee.maxBalance, maxBalance);
        assertEq(1, FeesFacet(address(applicationCoinHandler)).getFeeTotal());

        // now test the fee assessment
        applicationAppManager.addTag(fromUser, "fee"); ///add tag
        vm.stopPrank();
        vm.startPrank(fromUser);
        // make sure standard fee works
        console.logUint(_amountSeed);
        applicationCoin.transfer(toUser, _amountSeed);
        assertEq(applicationCoin.balanceOf(fromUser), fromUserBalance - _amountSeed);
    }

    function testERC20_ApplicationERC20Fuzz_TransactionFeeTable_Discount_Positive(uint8 _addressIndex, uint24 _amountSeed, int24 _feeSeed, int24 _discountSeed) public endWithStopPrank {
        _amountSeed = uint24(bound(_amountSeed, 1, type(uint24).max / 10000));
        if (_feeSeed > 10000) _feeSeed = 10000;
        if (_feeSeed <= 0) _feeSeed = 1;
        if (_discountSeed >= 0) _discountSeed = -1;
        if (_discountSeed < -10000) _discountSeed = -10000;

        (address fromUser, address treasury, address toUser) = _get3RandomAddresses(_addressIndex);
        uint256 fromUserBalance = type(uint256).max - 1;
        applicationCoin.mint(fromUser, fromUserBalance);
        uint256 maxBalance = type(uint256).max;
        address targetAccount = treasury;
        // create a fee
        switchToRuleAdmin();
        FeesFacet(address(applicationCoinHandler)).addFee("fee", 0, maxBalance, _feeSeed, targetAccount);
        switchToAppAdministrator();
        Fee memory fee = FeesFacet(address(applicationCoinHandler)).getFee("fee");

        // now test the fee assessment
        applicationAppManager.addTag(fromUser, "fee"); ///add tag
        applicationAppManager.addTag(fromUser, "discount"); ///add tag
        switchToRuleAdmin();
        FeesFacet(address(applicationCoinHandler)).addFee("discount", 0, maxBalance, _discountSeed, address(0));
        switchToAppAdministrator();
        fee = FeesFacet(address(applicationCoinHandler)).getFee("discount");
        vm.stopPrank();
        vm.startPrank(fromUser);
        // make sure standard fee works
        console.logUint(_amountSeed);
        applicationCoin.transfer(toUser, _amountSeed);
        assertEq(applicationCoin.balanceOf(fromUser), fromUserBalance - _amountSeed);
        uint feeCalculus;
        // discount is set, calculate for it
        // fees calculate to 0
        if (_feeSeed + _discountSeed < 0) {
            feeCalculus = 0;
        } else {
            feeCalculus = uint24(_feeSeed + _discountSeed); // note: discount is negative
        }
        assertEq(applicationCoin.balanceOf(toUser), _amountSeed - (_amountSeed * feeCalculus) / 10000);
        assertEq(applicationCoin.balanceOf(targetAccount), (_amountSeed * feeCalculus) / 10000);
    }

    function testERC20_ApplicationERC20Fuzz_TransactionFeeTable_StandardFee_TransferFrom_Positive(uint8 _addressIndex, uint24 _amountSeed, int24 _feeSeed) public endWithStopPrank {
        _amountSeed = uint24(bound(_amountSeed, 1, type(uint24).max / 10000));
        if (_feeSeed > 10000) _feeSeed = 10000;
        if (_feeSeed <= 0) _feeSeed = 1;
        (address fromUser, address treasury, address toUser) = _get3RandomAddresses(_addressIndex);
        uint256 fromUserBalance = type(uint256).max - 1;
        applicationCoin.mint(fromUser, fromUserBalance);
        uint256 maxBalance = type(uint256).max;
        address targetAccount = treasury;
        // create a fee
        switchToRuleAdmin();
        FeesFacet(address(applicationCoinHandler)).addFee("fee", 0, maxBalance, _feeSeed, targetAccount);
        switchToAppAdministrator();
        Fee memory fee = FeesFacet(address(applicationCoinHandler)).getFee("fee");
        assertEq(fee.feePercentage, _feeSeed);
        assertEq(fee.minBalance, 0);
        assertEq(fee.maxBalance, maxBalance);
        assertEq(1, FeesFacet(address(applicationCoinHandler)).getFeeTotal());

        // now test the fee assessment
        applicationAppManager.addTag(fromUser, "fee"); ///add tag
        vm.stopPrank();
        vm.startPrank(fromUser);
        applicationCoin.approve(fromUser, _amountSeed);
        // make sure standard fee works
        console.logUint(_amountSeed);
        applicationCoin.transferFrom(fromUser, toUser, _amountSeed);
        assertEq(applicationCoin.balanceOf(fromUser), fromUserBalance - _amountSeed);
    }

    function testERC20_ApplicationERC20Fuzz_TransactionFeeTable_Discount_TransferFrom_Positive(uint8 _addressIndex, uint24 _amountSeed, int24 _feeSeed, int24 _discountSeed) public endWithStopPrank {
        _amountSeed = uint24(bound(_amountSeed, 1, type(uint24).max / 10000));
        if (_feeSeed > 10000) _feeSeed = 10000;
        if (_feeSeed <= 0) _feeSeed = 1;
        if (_discountSeed >= 0) _discountSeed = -1;
        if (_discountSeed < -10000) _discountSeed = -10000;

        (address fromUser, address treasury, address toUser) = _get3RandomAddresses(_addressIndex);
        uint256 fromUserBalance = type(uint256).max - 1;
        applicationCoin.mint(fromUser, fromUserBalance);
        uint256 maxBalance = type(uint256).max;
        address targetAccount = treasury;
        // create a fee
        switchToRuleAdmin();
        FeesFacet(address(applicationCoinHandler)).addFee("fee", 0, maxBalance, _feeSeed, targetAccount);
        switchToAppAdministrator();
        Fee memory fee = FeesFacet(address(applicationCoinHandler)).getFee("fee");

        // now test the fee assessment
        applicationAppManager.addTag(fromUser, "fee"); ///add tag
        applicationAppManager.addTag(fromUser, "discount"); ///add tag
        switchToRuleAdmin();
        FeesFacet(address(applicationCoinHandler)).addFee("discount", 0, maxBalance, _discountSeed, address(0));
        switchToAppAdministrator();
        fee = FeesFacet(address(applicationCoinHandler)).getFee("discount");
        vm.stopPrank();
        vm.startPrank(fromUser);
        // make sure standard fee works
        console.logUint(_amountSeed);
        applicationCoin.approve(fromUser, _amountSeed);
        applicationCoin.transferFrom(fromUser, toUser, _amountSeed);
        assertEq(applicationCoin.balanceOf(fromUser), fromUserBalance - _amountSeed);
        uint feeCalculus;
        // discount is set, calculate for it
        // fees calculate to 0
        if (_feeSeed + _discountSeed < 0) {
            feeCalculus = 0;
        } else {
            feeCalculus = uint24(_feeSeed + _discountSeed); // note: discount is negative
        }
        assertEq(applicationCoin.balanceOf(toUser), _amountSeed - (_amountSeed * feeCalculus) / 10000);
        assertEq(applicationCoin.balanceOf(targetAccount), (_amountSeed * feeCalculus) / 10000);
    }

    /** Test All actions */
    function testERC20_ApplicationERC20Fuzz_TokenMaxTradingVolume_All_Positive(uint8 _addressIndex, uint8 _period, uint24 _maxPercent) public endWithStopPrank {
        _period = uint8(bound(_period, 1, type(uint8).max));
        _maxPercent = uint24(bound(_maxPercent, 1, 99999));
        rich_user = getUniqueAddresses(_addressIndex % ADDRESSES.length, 5)[0];

        switchToAppAdministrator();
        /// load non admin users with game coin
        applicationCoin.mint(rich_user, 1000000);
        /// apply the rule
        uint32 ruleId = createTokenMaxTradingVolumeRule(_maxPercent, _period, Blocktime, 100_000);
        setTokenMaxTradingVolumeRule(address(applicationCoinHandler), ruleId);
        vm.stopPrank();
        vm.startPrank(rich_user, rich_user);
        /// determine the maximum transfer amount
        uint256 maxSize = uint256(_maxPercent) * 10;
        /// make sure that transfer under the threshold works
        applicationCoin.transfer(user1, maxSize - 1);
        assertEq(applicationCoin.balanceOf(user1), maxSize - 1);
    }

    /** Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_TokenMaxTradingVolume_Transfer_Positive(uint8 _addressIndex, uint8 _period, uint24 _maxPercent) public endWithStopPrank {
        _period = uint8(bound(_period, 1, type(uint8).max));
        _maxPercent = uint24(bound(_maxPercent, 1, 99999));
        rich_user = getUniqueAddresses(_addressIndex % ADDRESSES.length, 5)[0];

        switchToAppAdministrator();
        /// load non admin users with game coin
        applicationCoin.mint(rich_user, 1000000);
        /// apply the rule
        uint32 ruleId = createTokenMaxTradingVolumeRule(_maxPercent, _period, Blocktime, 100_000);
        setTokenMaxTradingVolumeRuleSingleAction(ActionTypes.P2P_TRANSFER, address(applicationCoinHandler), ruleId);
        vm.stopPrank();
        vm.startPrank(rich_user, rich_user);
        /// determine the maximum transfer amount
        uint256 maxSize = uint256(_maxPercent) * 10;
        /// make sure that transfer under the threshold works
        applicationCoin.transfer(user1, maxSize - 1);
        assertEq(applicationCoin.balanceOf(user1), maxSize - 1);
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_TokenMaxTradingVolume_Mint_Positive(uint8 _addressIndex, uint8 _period, uint24 _maxPercent) public endWithStopPrank {
        _period = uint8(bound(_period, 1, type(uint8).max));
        _maxPercent = uint24(bound(_maxPercent, 1, 99999));
        rich_user = getUniqueAddresses(_addressIndex % ADDRESSES.length, 5)[0];

        switchToAppAdministrator();
        /// load non admin users with game coin
        applicationCoin.mint(rich_user, 1000000);
        /// apply the rule
        uint32 ruleId = createTokenMaxTradingVolumeRule(_maxPercent, _period, Blocktime, 100_000);
        setTokenMaxTradingVolumeRuleSingleAction(ActionTypes.MINT, address(applicationCoinHandler), ruleId);
        vm.stopPrank();
        vm.startPrank(rich_user, rich_user);
        /// determine the maximum transfer amount
        uint256 maxSize = uint256(_maxPercent) * 10;
        /// make sure that transfer under the threshold works
        applicationCoin.transfer(user1, maxSize - 1);
        assertEq(applicationCoin.balanceOf(user1), maxSize - 1);
    }

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_TokenMaxTradingVolume_Buy_Positive(uint8 _addressIndex, uint8 _period, uint24 _maxPercent) public endWithStopPrank {
        _period = uint8(bound(_period, 1, type(uint8).max));
        _maxPercent = uint24(bound(_maxPercent, 1, 99999));
        address _user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 5)[0];
        uint256 supply = type(uint128).max;
        uint256 tradeAmount;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, supply, false);
        switchToRuleAdmin();
        /// apply the rule
        uint32 ruleId = createTokenMaxTradingVolumeRule(_maxPercent, _period, Blocktime, 100_000);
        setTokenMaxTradingVolumeRuleSingleAction(ActionTypes.BUY, address(applicationCoinHandler), ruleId);
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        /// Approve all the transfers
        applicationCoin2.approve(address(amm), supply);
        /// determine the maximum transfer amount
        uint256 maxSize = uint256(_maxPercent) * 10;
        /// make sure that transfer under the threshold works
        tradeAmount = maxSize - 1;
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
        assertEq(applicationCoin.balanceOf(_user1), tradeAmount);
    }

    /** Test SELL only */
    function testERC20_ApplicationERC20Fuzz_TokenMaxTradingVolume_Sell_Positive(uint8 _addressIndex, uint8 _period, uint24 _maxPercent) public endWithStopPrank {
        _period = uint8(bound(_period, 1, type(uint8).max));
        _maxPercent = uint24(bound(_maxPercent, 1, 99999));
        address _user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 5)[0];
        uint256 supply = type(uint128).max;
        uint256 tradeAmount;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, _user1, supply, true);
        switchToRuleAdmin();
        /// apply the rule
        uint32 ruleId = createTokenMaxTradingVolumeRule(_maxPercent, _period, Blocktime, 100_000);
        setTokenMaxTradingVolumeRuleSingleAction(ActionTypes.SELL, address(applicationCoinHandler), ruleId);
        vm.stopPrank();
        vm.startPrank(_user1, _user1);
        /// Approve all the transfers
        applicationCoin.approve(address(amm), supply);
        /// determine the maximum transfer amount
        uint256 maxSize = uint256(_maxPercent) * 10;
        /// make sure that transfer under the threshold works
        tradeAmount = maxSize - 1;
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, true);
        assertEq(applicationCoin2.balanceOf(_user1), tradeAmount);
    }

    /** All Actions */
    function testERC20_ApplicationERC20Fuzz_TokenMaxTradingVolume_All_Negative(uint8 _addressIndex, uint8 _period, uint24 _maxPercent) public endWithStopPrank {
        _period = uint8(bound(_period, 1, type(uint8).max));
        _maxPercent = uint24(bound(_maxPercent, 1, 99999));
        rich_user = getUniqueAddresses(_addressIndex % ADDRESSES.length, 5)[0];

        switchToAppAdministrator();
        /// load non admin users with game coin
        applicationCoin.mint(rich_user, 1000000);
        /// apply the rule
        uint32 ruleId = createTokenMaxTradingVolumeRule(_maxPercent, _period, Blocktime, 100_000);
        setTokenMaxTradingVolumeRule(address(applicationCoinHandler), ruleId);
        vm.stopPrank();
        vm.startPrank(rich_user, rich_user);
        /// determine the maximum transfer amount
        uint256 maxSize = uint256(_maxPercent) * 10;
        /// now violate the rule and ensure revert
        vm.expectRevert(0x009da0ce);
        applicationCoin.transfer(user1, maxSize);
        assertEq(applicationCoin.balanceOf(user1), 0);
        /// now move 1 block into the future and make sure it works
        vm.warp(block.timestamp + (uint256(_period) * 1 hours) + 1 minutes);
        /// now violate the rule in this block and ensure revert
        vm.expectRevert(0x009da0ce);
        applicationCoin.transfer(user2, maxSize);
        assertEq(applicationCoin.balanceOf(user2), 0);
    }

    /** Test TRANSFER only */
    function testERC20_ApplicationERC20Fuzz_TokenMaxTradingVolume_Transfer_Negative(uint8 _addressIndex, uint8 _period, uint24 _maxPercent) public endWithStopPrank {
        _period = uint8(bound(_period, 1, type(uint8).max));
        _maxPercent = uint24(bound(_maxPercent, 1, 99999));
        rich_user = getUniqueAddresses(_addressIndex % ADDRESSES.length, 5)[0];

        switchToAppAdministrator();
        /// load non admin users with game coin
        applicationCoin.mint(rich_user, 1000000);
        /// apply the rule
        uint32 ruleId = createTokenMaxTradingVolumeRule(_maxPercent, _period, Blocktime, 100_000);
        setTokenMaxTradingVolumeRuleSingleAction(ActionTypes.P2P_TRANSFER, address(applicationCoinHandler), ruleId);
        vm.stopPrank();
        vm.startPrank(rich_user, rich_user);
        /// determine the maximum transfer amount
        uint256 maxSize = uint256(_maxPercent) * 10;
        /// now violate the rule and ensure revert
        vm.expectRevert(0x009da0ce);
        applicationCoin.transfer(user1, maxSize);
        assertEq(applicationCoin.balanceOf(user1), 0);
        /// now move 1 block into the future and make sure it works
        vm.warp(block.timestamp + (uint256(_period) * 1 hours) + 1 minutes);
        /// now violate the rule in this block and ensure revert
        vm.expectRevert(0x009da0ce);
        applicationCoin.transfer(user2, maxSize);
        assertEq(applicationCoin.balanceOf(user2), 0);
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_TokenMaxTradingVolume_Mint_Negative(uint8 _addressIndex, uint8 _period, uint24 _maxPercent) public endWithStopPrank {
        _period = uint8(bound(_period, 1, type(uint8).max));
        _maxPercent = uint24(bound(_maxPercent, 1, 99999));
        rich_user = getUniqueAddresses(_addressIndex % ADDRESSES.length, 5)[0];

        switchToAppAdministrator();
        /// apply the rule
        uint32 ruleId = createTokenMaxTradingVolumeRule(_maxPercent, _period, Blocktime, 100_000);
        setTokenMaxTradingVolumeRuleSingleAction(ActionTypes.MINT, address(applicationCoinHandler), ruleId);
        vm.stopPrank();
        vm.startPrank(rich_user, rich_user);
        /// determine the maximum transfer amount
        uint256 maxSize = uint256(_maxPercent) * 10;
        /// now violate the rule and ensure revert
        vm.expectRevert(0x009da0ce);
        applicationCoin.mint(user1, maxSize);
        assertEq(applicationCoin.balanceOf(user1), 0);
        /// now move 1 block into the future and make sure it works
        vm.warp(block.timestamp + (uint256(_period) * 1 hours) + 1 minutes);
        /// now violate the rule in this block and ensure revert
        vm.expectRevert(0x009da0ce);
        applicationCoin.mint(user2, maxSize);
        assertEq(applicationCoin.balanceOf(user2), 0);
    }

    /** Test BUY only */
    function testERC20_ApplicationERC20Fuzz_TokenMaxTradingVolume_Buy_Negative(uint8 _addressIndex, uint8 _period, uint24 _maxPercent) public endWithStopPrank {
        _period = uint8(bound(_period, 1, type(uint8).max));
        _maxPercent = uint24(bound(_maxPercent, 1, 99999));
        rich_user = getUniqueAddresses(_addressIndex % ADDRESSES.length, 5)[0];

        switchToAppAdministrator();
        uint256 supply = type(uint128).max;
        uint256 tradeAmount;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, rich_user, supply, false);
        /// apply the rule
        uint32 ruleId = createTokenMaxTradingVolumeRule(_maxPercent, _period, Blocktime, 100_000);
        setTokenMaxTradingVolumeRuleSingleAction(ActionTypes.BUY, address(applicationCoinHandler), ruleId);
        vm.stopPrank();
        vm.startPrank(rich_user, rich_user);
        /// Approve all the transfers
        applicationCoin2.approve(address(amm), supply);
        /// determine the maximum transfer amount
        uint256 maxSize = uint256(_maxPercent) * 10;
        /// now violate the rule and ensure revert
        tradeAmount = maxSize;
        vm.expectRevert(0x009da0ce);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, false);
        assertEq(applicationCoin.balanceOf(user1), 0);
    }

    /** Test SELL only */
    function testERC20_ApplicationERC20Fuzz_TokenMaxTradingVolume_Sell_Negative(uint8 _addressIndex, uint8 _period, uint24 _maxPercent) public endWithStopPrank {
        _period = uint8(bound(_period, 1, type(uint8).max));
        _maxPercent = uint24(bound(_maxPercent, 1, 99999));
        rich_user = getUniqueAddresses(_addressIndex % ADDRESSES.length, 5)[0];

        switchToAppAdministrator();
        uint256 supply = type(uint128).max;
        uint256 tradeAmount;
        // Create and configure AMM, load user1 with applicationCoin2 so she can buy applicationCoin
        DummyAMM amm = _createAndInitializeAMM(applicationCoin, applicationCoin2, rich_user, supply, true);
        /// apply the rule
        uint32 ruleId = createTokenMaxTradingVolumeRule(_maxPercent, _period, Blocktime, 100_000);
        setTokenMaxTradingVolumeRuleSingleAction(ActionTypes.SELL, address(applicationCoinHandler), ruleId);
        vm.stopPrank();
        vm.startPrank(rich_user, rich_user);
        /// Approve all the transfers
        applicationCoin.approve(address(amm), supply);
        /// determine the maximum transfer amount
        uint256 maxSize = uint256(_maxPercent) * 10;
        /// now violate the rule and ensure revert
        tradeAmount = maxSize;
        vm.expectRevert(0x009da0ce);
        amm.dummyTrade(address(applicationCoin), address(applicationCoin2), tradeAmount, tradeAmount, true);
        assertEq(applicationCoin.balanceOf(user1), 0);
    }

    /** Test All Actions */
    function testERC20_ApplicationERC20Fuzz_TokenMaxSupplyVolatility_All_Negative(uint8 _addressIndex, uint256 amount, uint16 volLimit) public endWithStopPrank {
        switchToAppAdministrator();
        vm.warp(Blocktime);
        /// test params
        volLimit = uint16(bound(volLimit, 100, 9999));
        uint256 initialSupply = 100_000 * (10 ** 18);
        uint256 volume = uint256(volLimit) * 10;
        amount = bound(amount, (initialSupply - volume), initialSupply);
        uint8 rulePeriod = 24; /// 24 hours
        uint64 _startTime = Blocktime; /// default timestamp
        uint256 tokenSupply = 0; /// calls totalSupply() for the token
        user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 1)[0];
        /// mint initial supply
        applicationCoin.mint(treasuryAccount, initialSupply);
        switchToTreasuryAccount();
        /// create and activate rule
        uint32 ruleId = createTokenMaxSupplyVolatilityRule(volLimit, rulePeriod, _startTime, tokenSupply);
        setTokenMaxSupplyVolatilityRule(address(applicationCoinHandler), ruleId);
        /// test mint
        vm.stopPrank();
        vm.startPrank(user1, user1);
        console.log(initialSupply);
        console.log(volume);
        console.log(amount);
        vm.expectRevert(abi.encodeWithSignature("OverMaxSupplyVolatility()"));
        applicationCoin.mint(user1, amount);
        assertEq(applicationCoin.balanceOf(user1), 0);
    }

    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_TokenMaxSupplyVolatility_Mint_Negative(uint8 _addressIndex, uint256 amount, uint16 volLimit) public endWithStopPrank {
        switchToAppAdministrator();
        vm.warp(Blocktime);
        /// test params
        volLimit = uint16(bound(volLimit, 100, 9999));
        uint256 initialSupply = 100_000 * (10 ** 18);
        uint256 volume = uint256(volLimit) * 10;
        amount = bound(amount, (initialSupply - volume), initialSupply);
        uint8 rulePeriod = 24; /// 24 hours
        uint64 _startTime = Blocktime; /// default timestamp
        uint256 tokenSupply = 0; /// calls totalSupply() for the token
        user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 1)[0];
        /// mint initial supply
        applicationCoin.mint(treasuryAccount, initialSupply);
        switchToTreasuryAccount();
        /// create and activate rule
        uint32 ruleId = createTokenMaxSupplyVolatilityRule(volLimit, rulePeriod, _startTime, tokenSupply);
        setTokenMaxSupplyVolatilityRuleSingleAction(ActionTypes.MINT, address(applicationCoinHandler), ruleId);
        /// test mint
        vm.stopPrank();
        vm.startPrank(user1, user1);
        console.log(initialSupply);
        console.log(volume);
        console.log(amount);
        vm.expectRevert(abi.encodeWithSignature("OverMaxSupplyVolatility()"));
        applicationCoin.mint(user1, amount);
        assertEq(applicationCoin.balanceOf(user1), 0);
    }
    /** Test All actions */
    function testERC20_ApplicationERC20Fuzz_TokenMaxSupplyVolatility_All_Positive(uint8 _addressIndex, uint256 amount, uint16 volLimit) public endWithStopPrank {
        switchToAppAdministrator();
        vm.warp(Blocktime);
        /// test params
        volLimit = uint16(bound(volLimit, 100, 9999));
        uint256 initialSupply = 100_000 * (10 ** 18);
        uint256 volume = uint256(volLimit) * 10;
        amount = bound(amount, 1, (initialSupply / volume));
        uint8 rulePeriod = 24; /// 24 hours
        uint64 _startTime = Blocktime; /// default timestamp
        uint256 tokenSupply = 0; /// calls totalSupply() for the token
        user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 1)[0];
        /// mint initial supply
        applicationCoin.mint(treasuryAccount, initialSupply);
        switchToTreasuryAccount();
        /// create and activate rule
        uint32 ruleId = createTokenMaxSupplyVolatilityRule(volLimit, rulePeriod, _startTime, tokenSupply);
        setTokenMaxSupplyVolatilityRule(address(applicationCoinHandler), ruleId);
        /// test mint
        vm.stopPrank();
        vm.startPrank(user1, user1);
        console.log(initialSupply);
        console.log(volume);
        console.log(amount);
        applicationCoin.mint(user1, amount);
    }
    /** Test MINT only */
    function testERC20_ApplicationERC20Fuzz_TokenMaxSupplyVolatility_Mint_Positive(uint8 _addressIndex, uint256 amount, uint16 volLimit) public endWithStopPrank {
        switchToAppAdministrator();
        vm.warp(Blocktime);
        /// test params
        volLimit = uint16(bound(volLimit, 100, 9999));
        uint256 initialSupply = 100_000 * (10 ** 18);
        uint256 volume = uint256(volLimit) * 10;
        amount = bound(amount, 1, (initialSupply / volume));
        uint8 rulePeriod = 24; /// 24 hours
        uint64 _startTime = Blocktime; /// default timestamp
        uint256 tokenSupply = 0; /// calls totalSupply() for the token
        user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 1)[0];
        /// mint initial supply
        applicationCoin.mint(treasuryAccount, initialSupply);
        switchToTreasuryAccount();
        /// create and activate rule
        uint32 ruleId = createTokenMaxSupplyVolatilityRule(volLimit, rulePeriod, _startTime, tokenSupply);
        setTokenMaxSupplyVolatilityRuleSingleAction(ActionTypes.MINT, address(applicationCoinHandler), ruleId);
        /// test mint
        vm.stopPrank();
        vm.startPrank(user1, user1);
        console.log(initialSupply);
        console.log(volume);
        console.log(amount);
        applicationCoin.mint(user1, amount);
    }
    /** Test BURN only */
    function testERC20_ApplicationERC20Fuzz_TokenMaxSupplyVolatility_Burn_Positive(uint8 _addressIndex, uint256 amount, uint16 volLimit) public endWithStopPrank {
        switchToAppAdministrator();
        vm.warp(Blocktime);
        /// test params
        volLimit = uint16(bound(volLimit, 100, 9999));
        uint256 initialSupply = 100_000 * (10 ** 18);
        uint256 volume = uint256(volLimit) * 10;
        amount = bound(amount, 1, (initialSupply / volume));
        uint8 rulePeriod = 24; /// 24 hours
        uint64 _startTime = Blocktime; /// default timestamp
        uint256 tokenSupply = 0; /// calls totalSupply() for the token
        user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 1)[0];
        /// mint initial supply
        applicationCoin.mint(treasuryAccount, initialSupply);
        switchToTreasuryAccount();
        /// create and activate rule
        uint32 ruleId = createTokenMaxSupplyVolatilityRule(volLimit, rulePeriod, _startTime, tokenSupply);
        setTokenMaxSupplyVolatilityRuleSingleAction(ActionTypes.BURN, address(applicationCoinHandler), ruleId);
        /// test mint
        vm.stopPrank();
        vm.startPrank(user1, user1);
        console.log(initialSupply);
        console.log(volume);
        console.log(amount);
        applicationCoin.mint(user1, amount);
    }
    /** Test BURN only */
    function testERC20_ApplicationERC20Fuzz_TokenMaxSupplyVolatility_Burn_Negative(uint8 _addressIndex, uint256 amount, uint16 volLimit) public endWithStopPrank {
        switchToAppAdministrator();
        vm.warp(Blocktime);
        /// test params
        volLimit = uint16(bound(volLimit, 100, 9999));
        uint256 initialSupply = 100_000 * (10 ** 18);
        uint256 volume = uint256(volLimit) * 10;
        amount = bound(amount, (initialSupply - volume), initialSupply);
        uint8 rulePeriod = 24; /// 24 hours
        uint64 _startTime = Blocktime; /// default timestamp
        uint256 tokenSupply = 0; /// calls totalSupply() for the token
        user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 1)[0];
        /// mint initial supply
        applicationCoin.mint(treasuryAccount, initialSupply);
        switchToTreasuryAccount();
        /// create and activate rule
        uint32 ruleId = createTokenMaxSupplyVolatilityRule(volLimit, rulePeriod, _startTime, tokenSupply);
        setTokenMaxSupplyVolatilityRuleSingleAction(ActionTypes.BURN, address(applicationCoinHandler), ruleId);
        /// test mint
        vm.stopPrank();
        vm.startPrank(user1, user1);
        console.log(initialSupply);
        console.log(volume);
        console.log(amount);
        vm.expectRevert(abi.encodeWithSignature("OverMaxSupplyVolatility()"));
        applicationCoin.burn(amount);
    }

    function _createAccessBalances(uint24 _amountSeed) internal pure returns (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) {
        accessBalance1 = _amountSeed;
        accessBalance2 = _amountSeed + 100;
        accessBalance3 = _amountSeed + 500;
        accessBalance4 = _amountSeed + 1000;
    }

    function _createAndInitializeAMM(UtilApplicationERC20 token1, UtilApplicationERC20 token2, address user, uint256 tokenAmount, bool isToken1In) public returns (DummyAMM amm) {
        switchToAppAdministrator();
        amm = new DummyAMM();
        tokenAmount = tokenAmount + 1_000;
        if (token1.balanceOf(appAdministrator) < tokenAmount) {
            token1.mint(appAdministrator, tokenAmount - token1.balanceOf(appAdministrator));
        }
        if (token2.balanceOf(appAdministrator) < tokenAmount) {
            token2.mint(appAdministrator, tokenAmount - token2.balanceOf(appAdministrator));
        }
        /// Approve the transfer of tokens into AMM
        token1.approve(address(amm), tokenAmount);
        token2.approve(address(amm), tokenAmount);
        /// Transfer the tokens into the AMM
        token1.transfer(address(amm), tokenAmount);
        token2.transfer(address(amm), tokenAmount);
        /// Make sure the tokens made it
        assertEq(token1.balanceOf(address(amm)), tokenAmount);
        assertEq(token2.balanceOf(address(amm)), tokenAmount);
        if (isToken1In) {
            token1.mint(user, tokenAmount);
            assertEq(token1.balanceOf(user), tokenAmount);
        } else {
            token2.mint(user, tokenAmount);
            assertEq(token2.balanceOf(user), tokenAmount);
        }
        return amm;
    }
}
