// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/util/TestCommonFoundry.sol";
import "test/client/token/ERC721/util/ERC721Util.sol";

contract ApplicationERC721FuzzTest is TestCommonFoundry, ERC721Util {
    event Log(string eventString, bytes32[] tag);

    uint8[] riskScoresRuleA = createUint8Array(20, 40, 60, 80, 99);
    uint48[] maxBalancesRiskRule = createUint48Array(70, 50, 40, 30, 20);
    uint8[] riskScoresRuleB = createUint8Array(25, 50, 75);
    uint48[] maxSizeRiskRule = createUint48Array(100_000_000, 10_000, 1);

    function setUp() public endWithStopPrank {
        vm.warp(Blocktime);
        setUpProcotolAndCreateERC20AndDiamondHandler();
        switchToAppAdministrator();
        applicationCoin.mint(appAdministrator, type(uint256).max);
    }

    function _buildMint(uint8 _addressIndex) internal returns (address randomUser) {
        randomUser = _get1RandomAddress(_addressIndex);
        switchToAppAdministrator();
    }

    function _mintAmount(address _address, uint256 _amount) internal endWithStopPrank {
        switchToAppAdministrator();
        for (uint i; i < _amount; i++) applicationNFT.safeMint(_address);
    }

    function testERC721_ApplicationERC721Fuzz_Mint_Positive(uint8 _addressIndex) public endWithStopPrank {
        address randomUser = _buildMint(_addressIndex);
        applicationNFT.safeMint(randomUser);
        assertEq(applicationNFT.balanceOf(randomUser), 1);
        applicationNFT.safeMint(randomUser);
        assertEq(applicationNFT.balanceOf(randomUser), 2);
    }

    function testERC721_ApplicationERC721Fuzz_Mint_NotAppAdministratorOrOwner(uint8 _addressIndex) public endWithStopPrank {
        address randomUser = _get1RandomAddress(_addressIndex);
        switchToAccessLevelAdmin();
        vm.expectRevert(abi.encodeWithSignature("NotAppAdministratorOrOwner()"));
        applicationNFT.safeMint(randomUser);
    }

    function _buildTransfer(uint8 _addressIndex) internal endWithStopPrank returns (address randomUser, address randomUser2) {
        (randomUser, randomUser2) = _get2RandomAddresses(_addressIndex);
        switchToAppAdministrator();
        applicationNFT.safeMint(randomUser);
    }

    function testERC721_ApplicationERC721Fuzz_Transfer_Positive(uint8 _addressIndex) public endWithStopPrank {
        (address randomUser, address randomUser2) = _buildTransfer(_addressIndex);
        vm.startPrank(randomUser);
        applicationNFT.transferFrom(randomUser, randomUser2, 0);
        assertEq(applicationNFT.ownerOf(0), randomUser2);
        assertEq(applicationNFT.balanceOf(randomUser), 0);
        assertEq(applicationNFT.balanceOf(randomUser2), 1);
    }

    function testERC721_ApplicationERC721Fuzz_Transfer_NotOwnerOrApproved(uint8 _addressIndex) public endWithStopPrank {
        (address randomUser, address randomUser2) = _buildTransfer(_addressIndex);
        vm.startPrank(randomUser2);
        vm.expectRevert("ERC721: caller is not token owner or approved");
        applicationNFT.transferFrom(randomUser2, randomUser, 0);
    }

    function _buildBurn(uint8 _addressIndex) internal endWithStopPrank returns (address randomUser, address randomUser2) {
        (randomUser, randomUser2) = _buildTransfer(_addressIndex);
        vm.startPrank(randomUser);
        applicationNFT.transferFrom(randomUser, randomUser2, 0);
        switchToAppAdministrator();
        applicationNFT.safeMint(randomUser);
        randomUser2;
    }

    function testERC721_ApplicationERC721Fuzz_Burn_Positive(uint8 _addressIndex) public endWithStopPrank {
        (address randomUser, address randomUser2) = _buildBurn(_addressIndex);
        vm.startPrank(randomUser);
        applicationNFT.burn(1);
        assertEq(applicationNFT.balanceOf(randomUser), 0);
        vm.startPrank(randomUser2);
        applicationNFT.burn(0);
        assertEq(applicationNFT.balanceOf(randomUser2), 0);
    }

    function testERC721_ApplicationERC721Fuzz_Burn_NotOwnerOrApproved(uint8 _addressIndex) public {
        (address randomUser, address randomUser2) = _buildBurn(_addressIndex);
        vm.startPrank(randomUser);
        vm.expectRevert("ERC721: caller is not token owner or approved");
        applicationNFT.burn(0);
        randomUser2;
    }

    function _buildMinMaxTokenBalance(uint8 _addressIndex) internal endWithStopPrank returns (address randomUser, address richGuy, address _user1, address _user2, address _user3) {
        (randomUser, richGuy, _user1, _user2, _user3) = _get5RandomAddresses(_addressIndex);
        switchToAppAdministrator();
        _mintAmount(randomUser, 11);
        vm.startPrank(randomUser);
        ///transfer tokenId 1 and 2 to richGuy
        applicationNFT.transferFrom(randomUser, richGuy, 0);
        applicationNFT.transferFrom(randomUser, richGuy, 1);
        assertEq(applicationNFT.balanceOf(richGuy), 2);
        ///transfer tokenId 3 and 4 to user1
        applicationNFT.transferFrom(randomUser, _user1, 3);
        applicationNFT.transferFrom(randomUser, _user1, 4);
        assertEq(applicationNFT.balanceOf(_user1), 2);
        ///Add Tag to account
        switchToAppAdministrator();
        address[3] memory tempAddresses = [_user1, _user2, richGuy];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addTag(tempAddresses[i], "Oscar"); ///add tag
        for (uint i; i < tempAddresses.length; i++) assertTrue(applicationAppManager.hasTag(tempAddresses[i], "Oscar"));
        switchToRuleAdmin();
        /// Apply Rule
        uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array("Oscar"), createUint256Array(1), createUint256Array(6));
        setAccountMinMaxTokenBalanceRule(address(applicationNFTHandler), ruleId);
        vm.startPrank(_user1);
        /// test we can go to the minimum without issues
        applicationNFT.transferFrom(_user1, _user2, 3);
        vm.startPrank(randomUser);
        /// test we can go to the maximum without issues
        for (uint i = 6; i < 10; i++) applicationNFT.transferFrom(randomUser, richGuy, i);
    }

    function testERC721_ApplicationERC721Fuzz_AccountMinMaxTokenBalanceRule_PositiveMin(uint8 _addressIndex) public endWithStopPrank {
        (address randomUser, address richGuy, address _user1, address _user2, address _user3) = _buildMinMaxTokenBalance(_addressIndex);
        assertEq(applicationNFT.balanceOf(_user1), 1);
        console.log(randomUser, richGuy, _user2, _user3);
    }

    function testERC721_ApplicationERC721Fuzz_AccountMinMaxTokenBalanceRule_PositiveMax(uint8 _addressIndex) public endWithStopPrank {
        (address randomUser, address richGuy, address _user1, address _user2, address _user3) = _buildMinMaxTokenBalance(_addressIndex);
        assertEq(applicationNFT.balanceOf(richGuy), 6);
        console.log(randomUser, _user1, _user2, _user3);
    }

    function testERC721_ApplicationERC721Fuzz_AccountMinMaxTokenBalanceRule_NegativeMinimum(uint8 _addressIndex) public endWithStopPrank {
        (address randomUser, address richGuy, address _user1, address _user2, address _user3) = _buildMinMaxTokenBalance(_addressIndex);
        vm.startPrank(_user1);
        vm.expectRevert(abi.encodeWithSignature("UnderMinBalance()"));
        applicationNFT.transferFrom(_user1, _user3, 4);
        console.log(randomUser, richGuy, _user2);
    }

    function testERC721_ApplicationERC721Fuzz_AccountMinMaxTokenBalanceRule_NegativeMaximum(uint8 _addressIndex) public endWithStopPrank {
        (address randomUser, address richGuy, address _user1, address _user2, address _user3) = _buildMinMaxTokenBalance(_addressIndex);
        vm.startPrank(randomUser);
        vm.expectRevert(abi.encodeWithSignature("OverMaxBalance()"));
        applicationNFT.transferFrom(randomUser, richGuy, 10);
        console.log(_user1, _user2, _user3);
    }

    function _buildAccountApproveDenyOracle(uint8 _addressIndex) internal endWithStopPrank returns (address randomUser, address richGuy, address _user1, address _user2, address _user3) {
        (randomUser, richGuy, _user1, _user2, _user3) = _get5RandomAddresses(_addressIndex);
        /// set up a non admin user an nft

        _mintAmount(_user1, 5);
        assertEq(applicationNFT.balanceOf(_user1), 5);
        // add a blacklist address
        badBoys.push(_user3);
        switchToAppAdministrator();
        oracleDenied.addToDeniedList(badBoys);
        // add an allowed address
        goodBoys.push(randomUser);
        oracleApproved.addToApprovedList(goodBoys);
    }

    function _buildAccountApproveDenyOracleDeny(uint8 _addressIndex) internal endWithStopPrank returns (address randomUser, address richGuy, address _user1, address _user2, address _user3) {
        (randomUser, richGuy, _user1, _user2, _user3) = _buildAccountApproveDenyOracle(_addressIndex);
        /// connect the rule to this handler
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        setAccountApproveDenyOracleRule(address(applicationNFTHandler), ruleId);
    }

    function _buildAccountApproveDenyOracleApprove(uint8 _addressIndex) internal endWithStopPrank returns (address randomUser, address richGuy, address _user1, address _user2, address _user3) {
        (randomUser, richGuy, _user1, _user2, _user3) = _buildAccountApproveDenyOracle(_addressIndex);
        /// connect the rule to this handler
        switchToRuleAdmin();
        uint32 ruleId = createAccountApproveDenyOracleRule(1);
        setAccountApproveDenyOracleRule(address(applicationNFTHandler), ruleId);
    }

    function testERC721_ApplicationERC721Fuzz_AccountApproveDenyOracle_PositiveDeny(uint8 _addressIndex) public endWithStopPrank {
        (address randomUser, address richGuy, address _user1, address _user2, address _user3) = _buildAccountApproveDenyOracleDeny(_addressIndex);
        vm.startPrank(_user1);
        applicationNFT.transferFrom(_user1, _user2, 0);
        assertEq(applicationNFT.balanceOf(_user2), 1);
        console.log(randomUser, richGuy, _user3);
    }

    function testERC721_ApplicationERC721Fuzz_AccountApproveDenyOracle_NegativeDeny(uint8 _addressIndex) public endWithStopPrank {
        (address randomUser, address richGuy, address _user1, address _user2, address _user3) = _buildAccountApproveDenyOracleDeny(_addressIndex);
        vm.startPrank(_user1);
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        applicationNFT.transferFrom(_user1, _user3, 1);
        assertEq(applicationNFT.balanceOf(_user3), 0);
        console.log(randomUser, richGuy, _user2);
    }

    function testERC721_ApplicationERC721Fuzz_AccountApproveDenyOracle_PositiveApprove(uint8 _addressIndex) public endWithStopPrank {
        (address randomUser, address richGuy, address _user1, address _user2, address _user3) = _buildAccountApproveDenyOracleApprove(_addressIndex);
        vm.startPrank(_user1);
        applicationNFT.transferFrom(_user1, randomUser, 2);
        console.log(richGuy, _user2, _user3);
    }

    function testERC721_ApplicationERC721Fuzz_AccountApproveDenyOracle_NegativeApprove(uint8 _addressIndex) public endWithStopPrank {
        (address randomUser, address richGuy, address _user1, address _user2, address _user3) = _buildAccountApproveDenyOracleApprove(_addressIndex);
        vm.startPrank(_user1);
        vm.expectRevert(abi.encodeWithSignature("AddressNotApproved()"));
        applicationNFT.transferFrom(_user1, richGuy, 3);
        console.log(randomUser, _user2, _user3);
    }

    function testERC721_ApplicationERC721Fuzz_AccountApproveDenyOracle_NegativeOracleType() public endWithStopPrank {
        switchToRuleAdmin();
        vm.expectRevert("Oracle Type Invalid");
        createAccountApproveDenyOracleRule(2);
    }

    function _buildTokenMaxDailyTradesSimple(uint8 _addressIndex) internal endWithStopPrank returns (address _user1, address _user2) {
        (_user1, _user2) = _get2RandomAddresses(_addressIndex);
        /// set up a non admin user an nft
        _mintAmount(_user1, 5);
        assertEq(applicationNFT.balanceOf(_user1), 5);

        // tag the NFT collection
        switchToAppAdministrator();
        applicationAppManager.addTag(address(applicationNFT), "DiscoPunk"); ///add tag
        // apply the rule to the ApplicationERC721Handler
        uint32 ruleId = createTokenMaxDailyTradesRule("BoredGrape", "DiscoPunk", 1, 5);
        setTokenMaxDailyTradesRule(address(applicationNFTHandler), ruleId);
    }

    /**
     * @dev Test the TokenMaxDailyTrades rule
     */
    function testERC721_ApplicationERC721Fuzz_TokenMaxDailyTrades_PositiveSimple(uint8 _addressIndex) public endWithStopPrank {
        (address _user1, address _user2) = _buildTokenMaxDailyTradesSimple(_addressIndex);
        vm.startPrank(_user1);
        applicationNFT.transferFrom(_user1, _user2, 0);
        assertEq(applicationNFT.balanceOf(_user2), 1);
        vm.startPrank(_user2);
        applicationNFT.transferFrom(_user2, _user1, 0);
        assertEq(applicationNFT.balanceOf(_user2), 0);
    }

    function _buildTokenMaxDailyTradesRrestrictiveTag(uint8 _addressIndex) internal endWithStopPrank returns (address _user1, address _user2) {
        (_user1, _user2) = _buildTokenMaxDailyTradesSimple(_addressIndex);
        switchToAppAdministrator();
        applicationAppManager.removeTag(address(applicationNFT), "DiscoPunk"); ///add tag
        applicationAppManager.addTag(address(applicationNFT), "BoredGrape"); ///add tag
        vm.startPrank(_user1);
        applicationNFT.transferFrom(_user1, _user2, 1);
    }

    function testERC721_ApplicationERC721Fuzz_TokenMaxDailyTrades_PositiveRestrictiveTag(uint8 _addressIndex) public endWithStopPrank {
        (address _user1, address _user2) = _buildTokenMaxDailyTradesRrestrictiveTag(_addressIndex);
        assertEq(applicationNFT.balanceOf(_user2), 1);
        _user1;
    }

    function testERC721_ApplicationERC721Fuzz_TokenMaxDailyTrades_NegativeRestrictiveTag(uint8 _addressIndex) public endWithStopPrank {
        (address _user1, address _user2) = _buildTokenMaxDailyTradesRrestrictiveTag(_addressIndex);
        vm.startPrank(_user2);
        // this one should fail because it is more than 1 in 24 hours
        vm.expectRevert(abi.encodeWithSignature("OverMaxDailyTrades()"));
        applicationNFT.transferFrom(_user2, _user1, 1);
        assertEq(applicationNFT.balanceOf(_user2), 1);
    }

    function _buildTokenMaxDailyTradesRrestrictiveTagNewPeriodA(uint8 _addressIndex) internal endWithStopPrank returns (address _user1, address _user2) {
        (_user1, _user2) = _buildTokenMaxDailyTradesRrestrictiveTag(_addressIndex);
        vm.warp(block.timestamp + 1 days);
        vm.startPrank(_user2);
        applicationNFT.transferFrom(_user2, _user1, 1);
    }

    function testERC721_ApplicationERC721Fuzz_TokenMaxDailyTrades_PositiveNewPeriodA(uint8 _addressIndex) public endWithStopPrank {
        (address _user1, address _user2) = _buildTokenMaxDailyTradesRrestrictiveTagNewPeriodA(_addressIndex);
        assertEq(applicationNFT.balanceOf(_user2), 0);
        _user1;
    }

    function _buildTokenMaxDailyTradesRrestrictiveTagNewPeriodB(uint8 _addressIndex) internal endWithStopPrank returns (address _user1, address _user2) {
        (_user1, _user2) = _buildTokenMaxDailyTradesRrestrictiveTagNewPeriodA(_addressIndex);
        switchToAppAdministrator();
        applicationAppManager.addTag(address(applicationNFT), "DiscoPunk"); ///add tag
        vm.startPrank(_user1);
        // first one should pass
        applicationNFT.transferFrom(_user1, _user2, 2);
    }

    function testERC721_ApplicationERC721Fuzz_TokenMaxDailyTrades_PositiveNewPeriodB(uint8 _addressIndex) public endWithStopPrank {
        (address _user1, address _user2) = _buildTokenMaxDailyTradesRrestrictiveTagNewPeriodB(_addressIndex);
        assertEq(applicationNFT.balanceOf(_user2), 1);
        _user1;
    }

    function testERC721_ApplicationERC721Fuzz_TokenMaxDailyTrades_NegativeNewPeriodB(uint8 _addressIndex) public endWithStopPrank {
        (address _user1, address _user2) = _buildTokenMaxDailyTradesRrestrictiveTagNewPeriodB(_addressIndex);
        vm.startPrank(_user2);
        vm.expectRevert(abi.encodeWithSignature("OverMaxDailyTrades()"));
        applicationNFT.transferFrom(_user2, _user1, 2);
    }

    function _appRuleTokens() internal endWithStopPrank {
        switchToAppAdministrator();
        for (uint i; i < 30; ) {
            applicationNFT.safeMint(ruleBypassAccount);
            erc721Pricer.setSingleNFTPrice(address(applicationNFT), i, (i + 1) * 10 * ATTO); //setting at $10 * (ID + 1)
            assertEq(erc721Pricer.getNFTPrice(address(applicationNFT), i), (i + 1) * 10 * ATTO);
            unchecked {
                ++i;
            }
        }
    }

    function _buildAccountMaxTransactionValueByRiskScoreRuleNFT(uint8 _addressIndex, uint8 _risk) internal endWithStopPrank returns (address _user1, address _user2, address _user3, address _user4) {
        _appRuleTokens();
        (_user1, _user2, _user3, _user4) = _get4RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        switchToRuleBypassAccount();
        for (uint i; i < 4; i++) applicationNFT.safeTransferFrom(ruleBypassAccount, _user1, i);
        assertEq(applicationNFT.balanceOf(_user1), 4);
        for (uint i = 5; i < 7; i++) applicationNFT.safeTransferFrom(ruleBypassAccount, _user2, i);
        assertEq(applicationNFT.balanceOf(_user2), 2);
        applicationNFT.safeTransferFrom(ruleBypassAccount, _user3, 7);
        applicationNFT.safeTransferFrom(ruleBypassAccount, _user3, 19);
        assertEq(applicationNFT.balanceOf(_user3), 2);
        assertEq(applicationNFT.balanceOf(_user2), 2);

        uint8 risk = _parameterizeRisk(_risk);
        ///Create rule
        uint32 ruleId = createAccountMaxTxValueByRiskRule(riskScoresRuleA, maxBalancesRiskRule);
        setAccountMaxTxValueByRiskRule(ruleId);
        /// we set a risk score for user1 and user 2
        switchToRiskAdmin();
        address[4] memory tempAddresses = [_user1, _user2, _user3, _user4];
        for (uint i; i < tempAddresses.length; i++) applicationAppManager.addRiskScore(tempAddresses[i], risk);
    }

    function testERC721_ApplicationERC721Fuzz_AccountMaxTransactionValueByRiskScoreRuleNFT1(uint8 _addressIndex, uint8 _risk) public endWithStopPrank {
        (address _user1, address _user2, address _user3, address _user4) = _buildAccountMaxTransactionValueByRiskScoreRuleNFT(_addressIndex, _risk);
        _risk = _parameterizeRisk(_risk);
        vm.startPrank(_user1);
        ///Should always pass
        applicationNFT.safeTransferFrom(_user1, _user2, 0); // a 10-dollar NFT
        applicationNFT.safeTransferFrom(_user1, _user2, 1); // a 20-dollar NFT

        if (_risk >= riskScoresRuleA[4]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 20000000000000000000));
        }
        applicationNFT.safeTransferFrom(_user1, _user2, 2); // a 30-dollar NFT

        vm.startPrank(_user2);
        applicationNFT.safeTransferFrom(_user2, _user1, 0); // a 10-dollar NFT

        if (_risk >= riskScoresRuleA[4]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 20000000000000000000));
        } else if (_risk >= riskScoresRuleA[3]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 30000000000000000000));
        } else if (_risk >= riskScoresRuleA[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 40000000000000000000));
        } else if (_risk >= riskScoresRuleA[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 50000000000000000000));
        }
        applicationNFT.safeTransferFrom(_user2, _user1, 5); // a 60-dollar NFT

        vm.startPrank(_user3);
        if (_risk >= riskScoresRuleA[4]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 20000000000000000000));
        } else if (_risk >= riskScoresRuleA[3]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 30000000000000000000));
        } else if (_risk >= riskScoresRuleA[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 40000000000000000000));
        } else if (_risk >= riskScoresRuleA[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 50000000000000000000));
        } else if (_risk >= riskScoresRuleA[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 70000000000000000000));
        }
        applicationNFT.safeTransferFrom(_user3, _user4, 19); // a 200-dollar NFT
    }

    function _buildAccessBalances(uint8 _amountSeed) internal pure returns (uint48, uint48, uint48, uint48) {
        if (_amountSeed < 245) _amountSeed += 10;
        return (_amountSeed, uint48(_amountSeed) + 50, uint48(_amountSeed) + 100, uint48(_amountSeed) + 200);
    }

    function _buildAccountMaxValueByAccessLevelBase(uint8 _addressIndex, uint8 _amountSeed) internal endWithStopPrank returns (address _user1, address _user2, address _user3, address _user4) {
        _appRuleTokens();
        switchToAppAdministrator();
        applicationCoin.transfer(ruleBypassAccount, type(uint256).max);
        (_user1, _user2, _user3, _user4) = _get4RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        switchToRuleBypassAccount();
        applicationNFT.safeTransferFrom(ruleBypassAccount, _user1, 0); // a 10-dollar NFT
        applicationNFT.safeTransferFrom(ruleBypassAccount, _user3, 19); // an 200-dollar NFT
        // we make sure that _amountSeed is between 10 and 255
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _buildAccessBalances(_amountSeed);
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, accessBalance1, accessBalance2, accessBalance3, accessBalance4);
        // setAccountMaxValueByAccessLevelRule(ruleId);
        switchToRuleAdmin();
        applicationHandler.setAccountMaxValueByAccessLevelId(createActionTypeArrayAll(), ruleId);
    }

    function testERC721_ApplicationERC721Fuzz_AccountMaxValueByAccessLevel_NoAccessLevel(uint8 _addressIndex, uint8 _amountSeed) public endWithStopPrank {
        (address _user1, address _user2, address _user3, address _user4) = _buildAccountMaxValueByAccessLevelBase(_addressIndex, _amountSeed);
        vm.startPrank(_user1);
        vm.expectRevert(abi.encodeWithSignature("OverMaxValueByAccessLevel()"));
        applicationNFT.safeTransferFrom(_user1, _user2, 0);
        vm.startPrank(_user2);
        vm.expectRevert("ERC721: caller is not token owner or approved");
        applicationNFT.safeTransferFrom(_user2, _user4, 0);
        vm.startPrank(_user4);
        vm.expectRevert("ERC721: caller is not token owner or approved");
        applicationNFT.safeTransferFrom(_user4, _user1, 0);
        vm.startPrank(_user3);
        vm.expectRevert(abi.encodeWithSignature("OverMaxValueByAccessLevel()"));
        applicationNFT.safeTransferFrom(_user3, _user4, 19);
    }

    function _buildAccountMaxValueByAccessLevelFull(uint8 _addressIndex, uint8 _amountSeed) internal endWithStopPrank returns (address _user1, address _user2, address _user3, address _user4) {
        (_user1, _user2, _user3, _user4) = _buildAccountMaxValueByAccessLevelBase(_addressIndex, _amountSeed);
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(_user3, 3);
        applicationAppManager.addAccessLevel(_user1, 1);
        _user4;
    }

    function testERC721_ApplicationERC721Fuzz_AccountMaxValueByAccessLevel_simple(uint8 _addressIndex, uint8 _amountSeed) public endWithStopPrank {
        (address _user1, address _user2, address _user3, address _user4) = _buildAccountMaxValueByAccessLevelFull(_addressIndex, _amountSeed);
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _buildAccessBalances(_amountSeed);
        vm.startPrank(_user1);
        if (accessBalance3 < 210) vm.expectRevert(abi.encodeWithSignature("OverMaxValueByAccessLevel()"));
        applicationNFT.safeTransferFrom(_user1, _user3, 0);
        (accessBalance1, accessBalance2, accessBalance4, _user2, _user4);
    }

    function _buildAccountMaxValueByAccessLevelWithERC20(uint8 _addressIndex, uint8 _amountSeed) internal endWithStopPrank returns (address _user1, address _user2, address _user3, address _user4) {
        (_user1, _user2, _user3, _user4) = _buildAccountMaxValueByAccessLevelFull(_addressIndex, _amountSeed);
        switchToRuleBypassAccount();
        applicationCoin.transfer(_user1, type(uint256).max);
        assertEq(applicationCoin.balanceOf(_user1), type(uint256).max);
        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(applicationCoin), 1 * ATTO); //setting at $1
        assertEq(erc20Pricer.getTokenPrice(address(applicationCoin)), 1 * ATTO);
        // set the access level for the user4
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(_user4, 4);

        /// let's give user1 a 150-dollar NFT
        switchToRuleBypassAccount();
        applicationNFT.safeTransferFrom(ruleBypassAccount, _user1, 14); // a 150-dollar NFT
        assertEq(applicationNFT.balanceOf(_user1), 2);
    }

    function testERC721_ApplicationERC721Fuzz_AccountMaxValueByAccessLevelWithERC20s(uint8 _addressIndex, uint8 _amountSeed) public endWithStopPrank {
        /// create erc20 token, mint, and transfer to user
        (address _user1, address _user2, address _user3, address _user4) = _buildAccountMaxValueByAccessLevelWithERC20(_addressIndex, _amountSeed);
        (uint48 accessBalance1, uint48 accessBalance2, uint48 accessBalance3, uint48 accessBalance4) = _buildAccessBalances(_amountSeed);
        vm.startPrank(_user1);
        /// let's send 150-dollar worth of dracs to user4. If accessBalance4 allows less than
        /// 300 (150 in NFTs and 150 in erc20s) it should fail when trying to send NFT
        applicationCoin.transfer(_user4, 150 * ATTO);
        if (accessBalance4 < 300) vm.expectRevert(abi.encodeWithSignature("OverMaxValueByAccessLevel()"));
        applicationNFT.safeTransferFrom(_user1, _user4, 14);
        if (accessBalance3 >= 300) assertEq(applicationCoin.balanceOf(_user4), 150 * ATTO);
        console.log(_user2, _user3, accessBalance1, accessBalance2);
    }

    function _buildTokensForValuation(uint8 _addressIndex, uint8 _amountToMint) internal endWithStopPrank returns (address _user1, address _user2, address _user3, address _user4) {
        (_user1, _user2, _user3, _user4) = _get4RandomAddresses(_addressIndex);
        switchToAppAdministrator();
        // we make sure that _amountToMint is between 10 and 255
        if (_amountToMint < 245) _amountToMint += 10;
        uint8 mintAmount = _amountToMint;
        /// mint and load user 1 with 10-255 NFTs
        for (uint i; i < mintAmount; ) {
            applicationNFT.safeMint(_user1);
            erc721Pricer.setSingleNFTPrice(address(applicationNFT), i, 1 * ATTO); //setting at $1
            assertEq(erc721Pricer.getNFTPrice(address(applicationNFT), i), 1 * ATTO);
            unchecked {
                ++i;
            }
        }
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(_user1, 2);
        applicationAppManager.addAccessLevel(_user2, 2);
        applicationAppManager.addAccessLevel(_user3, 1);
        applicationAppManager.addAccessLevel(_user4, 4);

        switchToAppAdministrator();
        /// set 2 tokens above the $1 USD amount of other tokens (tokens 0-9 will always be minted)
        erc721Pricer.setSingleNFTPrice(address(applicationNFT), 2, 50 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(applicationNFT), 3, 25 * ATTO);
        erc721Pricer.setNFTCollectionPrice(address(applicationNFT), 1 * ATTO);
    }

    function testERC721_ApplicationERC721Fuzz_NFTValuationLimit_VariableMint(uint8 _addressIndex, uint8 _amountToMint) public endWithStopPrank {
        (address _user1, address _user2, address _user3, address _user4) = _buildTokensForValuation(_addressIndex, _amountToMint);
        if (_amountToMint < 245) _amountToMint += 10;
        uint8 mintAmount = _amountToMint;
        switchToAppAdministrator();
        /// set the nftHandler nftValuationLimit variable
        ERC721HandlerMainFacet(address(applicationNFTHandler)).setNFTValuationLimit(20);
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, 10, 50, 100, 300);
        setAccountMaxValueByAccessLevelRule(ruleId);

        /// transfer tokens to user 2
        vm.startPrank(_user1);
        applicationNFT.transferFrom(_user1, _user2, 9);
        /// transfer back to user 1
        /**
        Tx fails if the balance of user1 is over the access level of $50USD 
        or 
        if the balance of user 1 is less than the nftValuation limit (will calc the token prices increase above)
        */
        vm.startPrank(_user2);
        if (!applicationAppManager.isAppAdministrator(_user1) && !applicationAppManager.isAppAdministrator(_user2)) {
            if (_amountToMint < 10 || mintAmount > 51) {
                vm.expectRevert(abi.encodeWithSignature("OverMaxValueByAccessLevel()"));
                applicationNFT.transferFrom(_user2, _user1, 9);
            }
        }

        vm.startPrank(_user1);
        /// check token valuation works with increased value tokens
        vm.expectRevert(abi.encodeWithSignature("OverMaxValueByAccessLevel()"));
        applicationNFT.transferFrom(_user1, _user3, 2);
        applicationNFT.transferFrom(_user1, _user4, 2);
    }

    /// Test Account Max Value By Access Level Rule
    function testERC721_ApplicationERC721Fuzz_NFTValuationLimit_VariableValuationLimit(uint8 _addressIndex, uint16 _valuationLimit) public endWithStopPrank {
        (address _user1, address _user2, address _user3, address _user4) = _buildTokensForValuation(_addressIndex, 50);
        switchToAppAdministrator();
        /// set the nftHandler nftValuationLimit variable
        ERC721HandlerMainFacet(address(applicationNFTHandler)).setNFTValuationLimit(_valuationLimit);
        uint32 ruleId = createAccountMaxValueByAccessLevelRule(0, 10, 50, 100, 300);
        setAccountMaxValueByAccessLevelRule(ruleId);
        vm.startPrank(_user1);
        applicationNFT.transferFrom(_user1, _user2, 9);
        /// transfer back to user 1
        /**
        Tx fails if the balance of user1 is over the access level of $50USD 
        or 
        if the balance of user 1 is less than the nftValuation limit (will calc the token prices increase above)
        */
        vm.startPrank(_user2);
        if (!applicationAppManager.isAppAdministrator(_user1) && !applicationAppManager.isAppAdministrator(_user2)) {
            if (_valuationLimit > 49) {
                vm.expectRevert(abi.encodeWithSignature("OverMaxValueByAccessLevel()"));
                applicationNFT.transferFrom(_user2, _user1, 9);
            }
        }
        console.log(_user3, _user4);
    }

    function _buildAccountMinMaxTokenBalance(
        uint8 _addressIndex,
        bytes32 tag1,
        bytes32 tag2,
        bytes32 tag3
    ) internal endWithStopPrank returns (address _user1, address _user2, address _user3, address _user4) {
        /// Set up test variables
        vm.assume(tag1 != "" && tag2 != "" && tag3 != "");
        vm.assume(tag1 != tag2 && tag1 != tag3 && tag2 != tag3);
        (_user1, _user2, _user3, _user4) = _get4RandomAddresses(_addressIndex);
        switchToAppAdministrator();
        for (uint i; i < 3; i++) applicationNFT.safeMint(_user1);
        for (uint i; i < 3; i++) applicationNFT.safeMint(_user2);
        for (uint i; i < 3; i++) applicationNFT.safeMint(_user3);

        // Set up the rule conditions
        vm.warp(Blocktime);
        bytes32[] memory accs = createBytes32Array(tag1, tag2, tag3);
        uint256[] memory minAmounts = createUint256Array(1, 2, 3);
        uint256[] memory maxAmounts = createUint256Array(999999 * 10 ** 69, 999990 * 10 ** 69, 999990 * 10 ** 69);
        // 720 = one month 4380 = six months 17520 = two years
        uint16[] memory periods = createUint16Array(720, 4380, 17520);

        uint32 ruleId = createAccountMinMaxTokenBalanceRule(accs, minAmounts, maxAmounts, periods);
        setAccountMinMaxTokenBalanceRule(address(applicationNFTHandler), ruleId);
        switchToAppAdministrator();
        /// Tag accounts
        applicationAppManager.addTag(_user1, tag1); ///add tag
        applicationAppManager.addTag(_user2, tag2); ///add tag
        applicationAppManager.addTag(_user3, tag3); ///add tag
        /// Transfers
        vm.startPrank(_user1);
        applicationNFT.safeTransferFrom(_user1, _user4, 0);
        applicationNFT.safeTransferFrom(_user1, _user4, 2);
        vm.startPrank(_user2);
        assertEq(applicationNFT.balanceOf(_user2), 3);
        applicationNFT.safeTransferFrom(_user2, _user4, 4); /// Send token4 to user 4
    }

    function testERC721_ApplicationERC721Fuzz_AccountMinMaxTokenBalance_ByDatePositiveBase(uint8 _addressIndex, bytes32 tag1, bytes32 tag2, bytes32 tag3) public endWithStopPrank {
        (address _user1, address _user2, address _user3, address _user4) = _buildAccountMinMaxTokenBalance(_addressIndex, tag1, tag2, tag3);
        assertEq(applicationNFT.balanceOf(_user1), 1);
        assertEq(applicationNFT.balanceOf(_user2), 2);
        console.log(_user3, _user4);
    }

    function testERC721_ApplicationERC721Fuzz_AccountMinMaxTokenBalance_ByDateNegativeMinBalance(uint8 _addressIndex, bytes32 tag1, bytes32 tag2, bytes32 tag3) public endWithStopPrank {
        (address _user1, address _user2, address _user3, address _user4) = _buildAccountMinMaxTokenBalance(_addressIndex, tag1, tag2, tag3);
        vm.startPrank(_user1);
        vm.expectRevert(abi.encodeWithSignature("TxnInFreezeWindow()"));
        applicationNFT.safeTransferFrom(_user1, _user4, 1); /// Fails because User1 cannot have balanceOf less than 1
        vm.startPrank(_user2);
        vm.expectRevert(abi.encodeWithSignature("TxnInFreezeWindow()"));
        applicationNFT.safeTransferFrom(_user2, _user4, 3); /// Fails because User2 cannot have balanceOf less than 2
        console.log(_user3);
    }

    function testERC721_ApplicationERC721Fuzz_AccountMinMaxTokenBalance_ByDatePositiveNewPeriod(uint8 _addressIndex, bytes32 tag1, bytes32 tag2, bytes32 tag3) public endWithStopPrank {
        (address _user1, address _user2, address _user3, address _user4) = _buildAccountMinMaxTokenBalance(_addressIndex, tag1, tag2, tag3);
        /// warp to allow user 1 to transfer
        vm.warp(Blocktime + 725 hours);
        vm.startPrank(_user1);
        applicationNFT.safeTransferFrom(_user1, _user4, 1);

        /// warp to allow user 2 to transfer
        vm.warp(Blocktime + 4385 hours);
        vm.startPrank(_user2);
        applicationNFT.safeTransferFrom(_user2, _user4, 3);

        /// warp to allow user 3 to transfer
        vm.warp(Blocktime + 17525 hours);
        vm.startPrank(_user3);
        applicationNFT.safeTransferFrom(_user3, _user4, 6);
    }

    function _buildAccountMaxTransactionValueByRiskScoreWithPeriod(uint8 _risk, uint8 _period) internal endWithStopPrank returns (address _user1, address _user2, uint8 risk, uint8 period) {
        switchToAppAdministrator();
        period = _period > 6 ? _period / 6 + 1 : 1;
        risk = _parameterizeRisk(_risk);
        _user1 = address(0xaa);
        _user2 = address(0x22);
        /// we mint some NFTs for user 1 and give them a price
        for (uint i; i < 6; i++) applicationNFT.safeMint(_user1);
        erc721Pricer.setSingleNFTPrice(address(applicationNFT), 0, 1);
        erc721Pricer.setSingleNFTPrice(address(applicationNFT), 1, 1 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(applicationNFT), 2, 10_000 * ATTO - 1);
        erc721Pricer.setSingleNFTPrice(address(applicationNFT), 3, 100_000_000 * ATTO - 10_000 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(applicationNFT), 4, 1_000_000_000_000 * ATTO - 100_000_000 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(applicationNFT), 5, 1 * ATTO);
        /// we mint some NFTs for user 1 and give them a price
        for (uint i; i < 6; i++) applicationNFT.safeMint(_user2);
        erc721Pricer.setSingleNFTPrice(address(applicationNFT), 6, 1 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(applicationNFT), 7, 1 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(applicationNFT), 8, 90_000 * ATTO - 1);
        erc721Pricer.setSingleNFTPrice(address(applicationNFT), 9, 900_000_000 * ATTO - 90_000 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(applicationNFT), 10, 9_000_000_000_000 * ATTO - 900_000_000 * ATTO);
        erc721Pricer.setSingleNFTPrice(address(applicationNFT), 11, 1 * ATTO);

        uint32 ruleId = createAccountMaxTxValueByRiskRule(riskScoresRuleB, createUint48Array(100_000_000, 10_000, 1), period);
        setAccountMaxTxValueByRiskRule(ruleId);
        /// we set a risk score for user1
        switchToRiskAdmin();
        applicationAppManager.addRiskScore(_user1, risk);

        /// we start the prank exactly at the time when the rule starts taking effect + 1 full period + 1 minute
        uint256 startTestAt = (block.timestamp + (uint256(period) * (1 hours)) + 1 minutes);
        vm.warp(startTestAt);
    }

    function testERC721_ApplicationERC721Fuzz_AccountMaxTransactionValueByRiskScore_SenderFirstPeriod(uint8 _risk, uint8 _period) public endWithStopPrank {
        (address _user1, address _user2, uint8 risk, uint8 period) = _buildAccountMaxTransactionValueByRiskScoreWithPeriod(_risk, _period);
        _risk = _parameterizeRisk(_risk);

        /// TEST RULE ON SENDER
        /// we start making transfers
        vm.startPrank(_user1);
        /// first we send only 1 token which shouldn't trigger any risk check
        applicationNFT.safeTransferFrom(_user1, _user2, 0);
        /// 1
        /// let's go to the future in the middle of the period
        vm.warp(block.timestamp + (uint256(period) * 1 hours) / 2);
        /// now, if the user's risk profile is in the highest range, this transfer should revert
        if (_risk >= riskScoresRuleB[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 1000000000000000000));
        }
        applicationNFT.safeTransferFrom(_user1, _user2, 1);
        /// 2
        /// if the user's risk profile is in the second to the highest range, this transfer should revert
        if (_risk >= riskScoresRuleB[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 1000000000000000000));
        } else if (_risk >= riskScoresRuleB[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 10000000000000000000000));
        }
        applicationNFT.safeTransferFrom(_user1, _user2, 2);
        /// 10_001
        /// if the user's risk profile is in the second to the lowest range, this transfer should revert
        if (_risk >= riskScoresRuleB[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 1000000000000000000));
        } else if (_risk >= riskScoresRuleB[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 10000000000000000000000));
        } else if (_risk >= riskScoresRuleB[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 100000000000000000000000000));
        }
        console.log(risk);
        applicationNFT.safeTransferFrom(_user1, _user2, 3);
        /// 100_000_000 - 10_000 + 10_001 = 100_000_000 + 1 = 100_000_001
        if (_risk >= riskScoresRuleB[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 1000000000000000000));
        } else if (_risk >= riskScoresRuleB[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 10000000000000000000000));
        } else if (_risk >= riskScoresRuleB[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 100000000000000000000000000));
        }
        console.log(risk);
        applicationNFT.safeTransferFrom(_user1, _user2, 4);
        /// if passed: 1_000_000_000_000 - 100_000_000 + 100_000_001 = 1_000_000_000_000 + 1 = 1_000_000_000_001
    }

    function testERC721_ApplicationERC721Fuzz_AccountMaxTransactionValueByRiskScore_SenderNewPeriod(uint8 _risk, uint8 _period) public endWithStopPrank {
        (address _user1, address _user2, uint8 risk, uint8 period) = _buildAccountMaxTransactionValueByRiskScoreWithPeriod(_risk, _period);
        vm.startPrank(_user1);
        /// we jump to the next period and make sure it still works.
        vm.warp(block.timestamp + (uint256(period) * 1 hours) / 2);
        applicationNFT.safeTransferFrom(_user1, _user2, 5);
        console.log(risk);
    }

    function _buildAccountMaxTransactionValueByRiskScoreWithPeriodRecipient(uint8 _risk, uint8 _period) internal endWithStopPrank returns (address _user1, address _user2, uint8 risk, uint8 period) {
        (_user1, _user2, risk, period) = _buildAccountMaxTransactionValueByRiskScoreWithPeriod(_risk, _period);
        /// let's go to the future in the middle of the period
        vm.warp(block.timestamp + (9 * (uint256(period) * 1 hours)) / 2);
        /// TEST RULE ON RECIPIENT
        maxSizeRiskRule[0] = 900_000_000;
        maxSizeRiskRule[1] = 90_000;
        maxSizeRiskRule[2] = 1;
        riskScoresRuleB[0] = 1;
        riskScoresRuleB[1] = 40;
        riskScoresRuleB[2] = 90;

        /// we give some trillions to _user1 to spend
        switchToRuleAdmin();
        /// let's deactivate the rule before minting to avoid triggering the rule
        applicationHandler.activateAccountMaxTxValueByRiskScore(createActionTypeArrayAll(), false);

        uint32 ruleId = createAccountMaxTxValueByRiskRule(createUint8Array(1, 40, 90), createUint48Array(900_000_000, 90_000, 1), period);
        setAccountMaxTxValueByRiskRule(ruleId);
    }

    function testERC721_ApplicationERC721Fuzz_AccountMaxTransactionValueByRiskScore_RecipientFirstPeriod(uint8 __risk, uint8 _period) public endWithStopPrank {
        (address _user1, address _user2, uint8 _risk, uint8 period) = _buildAccountMaxTransactionValueByRiskScoreWithPeriodRecipient(__risk, _period);
        vm.startPrank(_user2);
        /// first we send only 1 token which shouldn't trigger any risk check
        applicationNFT.safeTransferFrom(_user2, _user1, 6);
        /// 1
        /// now, if the _user's risk profile is in the highest range, this transfer should revert
        if (_risk >= riskScoresRuleB[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 1000000000000000000));
        }
        applicationNFT.safeTransferFrom(_user2, _user1, 7);
        /// 2
        /// if the _user's risk profile is in the second to the highest range, this transfer should revert
        if (_risk >= riskScoresRuleB[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 1000000000000000000));
        } else if (_risk >= riskScoresRuleB[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 90000000000000000000000));
        }
        applicationNFT.safeTransferFrom(_user2, _user1, 8);
        /// 90_001
        /// if the _user's risk profile is in the lowest range, this transfer should revert
        if (_risk >= riskScoresRuleB[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 1000000000000000000));
        } else if (_risk >= riskScoresRuleB[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 90000000000000000000000));
        } else if (_risk >= riskScoresRuleB[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 900000000000000000000000000));
        }
        applicationNFT.safeTransferFrom(_user2, _user1, 9);
        /// 900_000_000 - 90_000 + 90_001 = 900_000_000 + 1 = 900_000_001
        if (_risk >= riskScoresRuleB[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 1000000000000000000));
        } else if (_risk >= riskScoresRuleB[1]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 90000000000000000000000));
        } else if (_risk >= riskScoresRuleB[0]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 900000000000000000000000000));
        }
        applicationNFT.safeTransferFrom(_user2, _user1, 10);
        /// if passed: 9_000_000_000_000 - 900_000_000 + 900_000_001  = 9_000_000_000_000 + 1 = 9_000_000_000_001
        console.log(period);
    }

    function testERC721_ApplicationERC721Fuzz_AccountMaxTransactionValueByRiskScore_RecipientNewPeriod(uint8 _risk, uint8 _period) public endWithStopPrank {
        (address _user1, address _user2, uint8 risk, uint8 period) = _buildAccountMaxTransactionValueByRiskScoreWithPeriodRecipient(_risk, _period);
        vm.startPrank(_user2);
        /// we jump to the next period and make sure it still works.
        vm.warp(block.timestamp + (uint256(period) * 1 hours));
        applicationNFT.safeTransferFrom(_user2, _user1, 11);
        console.log(risk);
    }

    function testERC721_ApplicationERC721Fuzz_AccountMaxTransactionValueByRiskScore_burn(uint8 _risk, uint8 _period) public endWithStopPrank {
        (address _user1, address _user2, uint8 risk, uint8 period) = _buildAccountMaxTransactionValueByRiskScoreWithPeriodRecipient(_risk, _period);
        _risk = _parameterizeRisk(_risk);
        /// test burn while rule is active
        vm.startPrank(_user2);
        /// we jump to the next period and make sure it still works.
        vm.warp(block.timestamp + (uint256(period) * 1 hours));
        applicationNFT.safeTransferFrom(_user2, _user1, 11);
        vm.startPrank(_user1);
        if (risk >= riskScoresRuleB[2]) {
            bytes4 selector = bytes4(keccak256("OverMaxTxValueByRiskScore(uint8,uint256)"));
            vm.expectRevert(abi.encodeWithSelector(selector, _risk, 1000000000000000000));
            applicationNFT.burn(11);
            vm.warp(block.timestamp + (uint256(period) * 2 hours));
            applicationNFT.burn(11);
        }
    }

    function testERC721_ApplicationERC721Fuzz_AccountMaxValueByRiskScoreNFT(uint32 priceA, uint32 priceB, uint16 priceC, uint8 _riskScore) public endWithStopPrank {
        vm.assume(priceA > 0 && priceB > 0 && priceC > 0);
        uint8 riskScore = uint8((uint16(_riskScore) * 100) / 254);
        uint8[] memory riskScores = createUint8Array(0, 10, 40, 80, 99);
        uint48[] memory balanceLimits = createUint48Array(10_000_000, 100_000, 1_000, 500, 10);
        //address[] memory addressList = getUniqueAddresses(_addressIndex % ADDRESSES.length, 4);
        address _user1 = address(0xff11);
        address _user2 = address(0xaa22);
        switchToAppAdministrator();
        applicationNFT.safeMint(_user1);
        erc721Pricer.setSingleNFTPrice(address(applicationNFT), 0, priceA);
        applicationNFT.safeMint(_user1);
        erc721Pricer.setSingleNFTPrice(address(applicationNFT), 1, priceB);
        applicationNFT.safeMint(_user1);
        erc721Pricer.setSingleNFTPrice(address(applicationNFT), 2, priceC);

        switchToRiskAdmin();
        // we apply random risk score to user2
        applicationAppManager.addRiskScore(_user2, riskScore);

        // we find the max balance user2
        uint32 maxValueForUser2;
        for (uint i; i < balanceLimits.length - 1; i++) {
            if (riskScore < riskScores[i]) {
                maxValueForUser2 = uint32(balanceLimits[i]);
            } else {
                maxValueForUser2 = uint32(balanceLimits[3]);
            }
        }

        uint32 ruleId = createAccountMaxValueByRiskRule(riskScores, createUint48Array(10_000_000, 100_000, 1_000, 500, 10));
        setAccountMaxValueByRiskRule(ruleId);
        vm.startPrank(_user1);
        if (priceA >= uint112(maxValueForUser2) * ATTO) vm.expectRevert(abi.encodeWithSignature("OverMaxAccValueByRiskScore()"));
        applicationNFT.safeTransferFrom(_user1, _user2, 0);
        if (priceA <= uint112(maxValueForUser2) * ATTO) {
            if (uint64(priceA) + uint64(priceB) >= uint112(maxValueForUser2) * ATTO) vm.expectRevert(abi.encodeWithSignature("OverMaxAccValueByRiskScore()"));
            applicationNFT.safeTransferFrom(_user1, _user2, 1);
            if (uint64(priceA) + uint64(priceB) < uint112(maxValueForUser2) * ATTO) {
                if (uint64(priceA) + uint64(priceB) + uint64(priceC) > uint112(maxValueForUser2) * ATTO) vm.expectRevert(abi.encodeWithSignature("OverMaxAccValueByRiskScore()"));
                applicationNFT.safeTransferFrom(_user1, _user2, 2);
            }
        }

        /// test if user can burn NFT with risk score assigned
        /// admin sets NFT price above highest risk limit to ensure burn is unaffected
        switchToAppAdministrator();
        erc721Pricer.setNFTCollectionPrice(address(applicationNFT), 0); // Resetting the default price to $0 to ensure mint is successful
        applicationNFT.safeMint(_user2);
        erc721Pricer.setSingleNFTPrice(address(applicationNFT), 3, 1_000_000_000_000);
        /// user 2 burns token
        vm.startPrank(_user2);
        applicationNFT.burn(3);
    }

    function testERC721_ApplicationERC721Fuzz_AccountMaxValueOutByAccessLevel(uint8 _addressIndex, uint8 _accessLevel) public endWithStopPrank {
        switchToAppAdministrator();
        for (uint i; i < 30; i++) {
            applicationNFT.safeMint(appAdministrator);
            erc721Pricer.setSingleNFTPrice(address(applicationNFT), i, (i + 1) * 10 * ATTO); //setting at $10 * (ID + 1)
            assertEq(erc721Pricer.getNFTPrice(address(applicationNFT), i), (i + 1) * 10 * ATTO);
        }
        (address _user1, address _user2, address _user3, address _user4) = _get4RandomAddresses(_addressIndex);
        /// set up a non admin user with tokens
        applicationNFT.safeTransferFrom(appAdministrator, _user1, 0); // a 10-dollar NFT
        assertEq(applicationNFT.balanceOf(_user1), 1);
        applicationNFT.safeTransferFrom(appAdministrator, _user3, 1); // an 20-dollar NFT
        assertEq(applicationNFT.balanceOf(_user3), 1);
        applicationNFT.safeTransferFrom(appAdministrator, _user4, 4); // a 50-dollar NFT
        assertEq(applicationNFT.balanceOf(_user4), 1);
        applicationNFT.safeTransferFrom(appAdministrator, _user4, 19); // a 200-dollar NFT
        assertEq(applicationNFT.balanceOf(_user4), 2);

        /// ERC20 tokens priced $1 USD
        applicationCoin.transfer(_user1, 1000 * ATTO);
        assertEq(applicationCoin.balanceOf(_user1), 1000 * ATTO);
        applicationCoin.transfer(_user2, 25 * ATTO);
        assertEq(applicationCoin.balanceOf(_user2), 25 * ATTO);
        applicationCoin.transfer(_user3, 10 * ATTO);
        assertEq(applicationCoin.balanceOf(_user3), 10 * ATTO);
        applicationCoin.transfer(_user4, 50 * ATTO);
        assertEq(applicationCoin.balanceOf(_user4), 50 * ATTO);
        erc20Pricer.setSingleTokenPrice(address(applicationCoin), 1 * ATTO); //setting at $1
        assertEq(erc20Pricer.getTokenPrice(address(applicationCoin)), 1 * ATTO);

        /// ensure access level is between 0-4
        if (_accessLevel > 4) {
            _accessLevel = 4;
        }
        /// create rule params
        uint32 ruleId = createAccountMaxValueOutByAccessLevelRule(0, 10, 20, 50, 250);
        setAccountMaxValueOutByAccessLevelRule(ruleId);
        switchToRuleBypassAccount();
        /// assign accessLevels to users
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(_user1, _accessLevel);
        applicationAppManager.addAccessLevel(_user3, _accessLevel);
        applicationAppManager.addAccessLevel(_user4, _accessLevel);
        /// set token pricing

        ///perform transfers
        vm.startPrank(_user1);
        if (_accessLevel < 1) vm.expectRevert(abi.encodeWithSignature("OverMaxValueOutByAccessLevel()"));
        applicationNFT.safeTransferFrom(_user1, _user2, 0);

        vm.startPrank(_user3);
        if (_accessLevel < 2) vm.expectRevert(abi.encodeWithSignature("OverMaxValueOutByAccessLevel()"));
        applicationNFT.safeTransferFrom(_user3, _user2, 1);

        vm.startPrank(_user4);
        if (_accessLevel < 3) vm.expectRevert(abi.encodeWithSignature("OverMaxValueOutByAccessLevel()"));
        applicationNFT.safeTransferFrom(_user4, _user2, 4);

        /// transfer erc20 tokens
        vm.startPrank(_user4);
        if (_accessLevel < 4) vm.expectRevert(abi.encodeWithSignature("OverMaxValueOutByAccessLevel()"));
        applicationCoin.transfer(_user2, 50 * ATTO);

        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(_user2, _accessLevel);

        /// reduce pricing
        switchToAppAdministrator();
        erc20Pricer.setSingleTokenPrice(address(applicationCoin), 5 * (10 ** 17)); //setting at $.50
        assertEq(erc20Pricer.getTokenPrice(address(applicationCoin)), 5 * (10 ** 17));

        vm.startPrank(_user2);
        if (_accessLevel < 2) vm.expectRevert(abi.encodeWithSignature("OverMaxValueOutByAccessLevel()"));
        applicationCoin.transfer(_user4, 25 * ATTO);
    }

    function testERC721_ApplicationERC721Fuzz_TokenMaxSupplyVolatility(uint8 _addressIndex, uint16 volLimit) public endWithStopPrank {
        switchToAppAdministrator();
        /// test params
        vm.assume(volLimit < 9999 && volLimit > 0);
        if (volLimit < 100) volLimit = 100;
        vm.warp(Blocktime);
        address _rich_user = getUniqueAddresses(_addressIndex % ADDRESSES.length, 5)[0];
        /// mint initial supply
        for (uint i = 0; i < 10; i++) applicationNFT.safeMint(appAdministrator);

        applicationNFT.safeTransferFrom(appAdministrator, _rich_user, 9);
        /// create and activate rule
        uint32 ruleId = createTokenMaxSupplyVolatilityRule(volLimit, 24, Blocktime, 0);
        setTokenMaxSupplyVolatilityRule(address(applicationNFTHandler), ruleId);
        /// determine the maximum burn/mint amount for inital test
        uint256 maxVol = uint256(volLimit) / 1000;
        /// make sure that transfer under the threshold works
        switchToAppAdministrator();
        if (maxVol >= 1) {
            for (uint i = 0; i < maxVol - 1; i++) {
                applicationNFT.safeMint(_rich_user);
            }
            assertEq(applicationNFT.balanceOf(_rich_user), maxVol);
        }
        if (maxVol == 0) {
            vm.expectRevert(abi.encodeWithSignature("OverMaxSupplyVolatility()"));
            applicationNFT.safeMint(_rich_user);
        }
        if (maxVol == 0) {
            vm.expectRevert(abi.encodeWithSignature("OverMaxSupplyVolatility()"));
            applicationNFT.safeMint(_rich_user);
        }
        /// at vol limit
        vm.startPrank(_rich_user);
        if ((10000 / applicationNFT.totalSupply()) > volLimit) {
            vm.expectRevert(abi.encodeWithSignature("OverMaxSupplyVolatility()"));
            applicationNFT.burn(9);
        } else {
            applicationNFT.burn(9);
            switchToAppAdministrator();
            applicationNFT.safeMint(_rich_user); // token 10
            vm.startPrank(_rich_user);
            applicationNFT.burn(10);
            switchToAppAdministrator();
            applicationNFT.safeMint(_rich_user);
            vm.startPrank(_rich_user);
            applicationNFT.burn(11);
        }
    }

    function testERC721_ApplicationERC721Fuzz_AdminMinTokenBalance(uint32 daysForward, uint8 _addressIndex) public endWithStopPrank {
        switchToAppAdministrator();
        address _user1 = getUniqueAddresses(_addressIndex % ADDRESSES.length, 5)[2];
        /// Mint TokenId 0-6 to ruleBypassAccount
        for (uint i; i < 7; i++) applicationNFT.safeMint(ruleBypassAccount);
        /// we create a rule that sets the minimum amount to 5 tokens to be tranferable in 1 year
        uint32 ruleId = createAdminMinTokenBalanceRule(5, uint64(block.timestamp + 365 days));
        setAdminMinTokenBalanceRule(address(applicationNFTHandler), ruleId);
        /// check that we cannot change the rule or turn it off while the current rule is still active
        vm.expectRevert(0xd66c3008);
        ERC721HandlerMainFacet(address(applicationNFTHandler)).activateAdminMinTokenBalance(_createActionsArray(), false);
        vm.expectRevert(0xd66c3008);
        ERC721HandlerMainFacet(address(applicationNFTHandler)).setAdminMinTokenBalanceId(_createActionsArray(), ruleId);

        switchToRuleBypassAccount();
        /// These transfers should pass
        applicationNFT.safeTransferFrom(ruleBypassAccount, _user1, 0);
        applicationNFT.safeTransferFrom(ruleBypassAccount, _user1, 1);
        /// This one fails
        vm.expectRevert(abi.encodeWithSignature("UnderMinBalance()"));
        applicationNFT.safeTransferFrom(ruleBypassAccount, _user1, 2);

        vm.warp(Blocktime + daysForward);
        if (daysForward < 365 days) vm.expectRevert(abi.encodeWithSignature("UnderMinBalance()"));
        applicationNFT.safeTransferFrom(ruleBypassAccount, _user1, 2);
        switchToRuleAdmin();
        if (daysForward >= 365 days) {
            ERC721HandlerMainFacet(address(applicationNFTHandler)).activateAdminMinTokenBalance(_createActionsArray(), false);
            ERC721HandlerMainFacet(address(applicationNFTHandler)).setAdminMinTokenBalanceId(_createActionsArray(), ruleId);
        }
    }

    function testERC721_ApplicationERC721Fuzz_TokenMaxTradingVolumeFuzzNFT(uint8 _addressIndex, uint8 _period, uint16 _maxPercent) public endWithStopPrank {
        if (_period == 0) _period = 1;
        //since NFT's take so long to mint, don't test for below 10% because the test pool will only be 10 NFT's
        if (_maxPercent < 100) _maxPercent = 100;
        if (_maxPercent > 9999) _maxPercent = 9999;
        address[] memory addressList = getUniqueAddresses(_addressIndex % ADDRESSES.length, 2);
        address _rich_user = addressList[0];
        address _user1 = addressList[1];
        switchToAppAdministrator();
        /// load non admin users with nft's
        // mint 10 nft's to non admin user
        for (uint i = 0; i < 10; i++) applicationNFT.safeMint(_rich_user);

        // apply the rule

        uint32 ruleId = createTokenMaxTradingVolumeRule(_maxPercent, _period, Blocktime, 0);
        setTokenMaxTradingVolumeRule(address(applicationNFTHandler), ruleId);
        /// determine the maximum transfer amount
        uint256 maxSize = uint256(_maxPercent) / 1000;
        console.logUint(maxSize);
        vm.startPrank(_rich_user);
        /// make sure that transfer under the threshold works
        if (maxSize > 1) {
            for (uint i = 0; i < maxSize - 1; i++) {
                applicationNFT.safeTransferFrom(_rich_user, _user1, i);
            }
            assertEq(applicationNFT.balanceOf(_user1), maxSize - 1);
        }
        /// Now break the rule
        if (maxSize == 0) {
            vm.expectRevert(0x009da0ce);
            applicationNFT.safeTransferFrom(_rich_user, _user1, 0);
        } else {
            /// account for decimal percentages
            if (uint256(_maxPercent) % 1000 == 0) {
                vm.expectRevert(0x009da0ce);
                applicationNFT.safeTransferFrom(_rich_user, _user1, maxSize - 1);
            } else {
                applicationNFT.safeTransferFrom(_rich_user, _user1, maxSize - 1);
                vm.expectRevert(0x009da0ce);
                applicationNFT.safeTransferFrom(_rich_user, _user1, maxSize);
            }
        }
    }

    function testERC721_ApplicationERC721Fuzz_TokenMinHoldTime(uint8 _addressIndex, uint32 _hours) public endWithStopPrank {
        (address _user1, address _user2) = _get2RandomAddresses(_addressIndex);
        switchToRuleAdmin();
        // hold time range must be between 1 hour and 5 years
        if (_hours == 0 || _hours > 43830) {
            if (_hours == 0) {
                vm.expectRevert(abi.encodeWithSignature("ZeroValueNotPermited()"));
            } else {
                vm.expectRevert(abi.encodeWithSignature("PeriodExceeds5Years()"));
            }
            ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).setTokenMinHoldTime(_createActionsArray(), _hours);
        } else {
            /// set the rule for x hours
            ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).setTokenMinHoldTime(_createActionsArray(), _hours);
            assertEq(ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).getTokenMinHoldTimePeriod(ActionTypes.P2P_TRANSFER), _hours);
            // mint 1 nft to non admin user(this should set their ownership start time)
            switchToAppAdministrator();
            applicationNFT.safeMint(_user1);
            vm.startPrank(_user1);
            // transfer should fail
            vm.expectRevert(0x5f98112f);
            applicationNFT.safeTransferFrom(_user1, _user2, 0);
            // move forward in time x hours and it should pass
            Blocktime = Blocktime + (_hours * 1 hours);
            vm.warp(Blocktime);
            applicationNFT.safeTransferFrom(_user1, _user2, 0);
            // the original owner was able to transfer but the new owner should not be able to because the time resets
            vm.startPrank(_user2);
            vm.expectRevert(0x5f98112f);
            applicationNFT.safeTransferFrom(_user2, _user1, 0);
            // move forward in time x hours and it should pass
            Blocktime = Blocktime + (_hours * 1 hours);
            vm.warp(Blocktime);
            applicationNFT.safeTransferFrom(_user2, _user1, 0);
        }
    }
}
