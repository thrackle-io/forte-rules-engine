// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/util/TestCommonFoundry.sol";
import "test/util/RuleCreation.sol";
import "test/client/token/ERC721/util/ERC721Util.sol";

abstract contract RuleProcessorDiamondCommonTests is Test, TestCommonFoundry, ERC721Util {
    /// Test Diamond upgrade
    function testProtocol_RuleProcessorDiamond_UpgradeRuleProcessor() public endWithStopPrank ifDeploymentTestsEnabled {
        _facetCutSetUp();
        console.log("ERC173Facet owner: ");
        console.log(ERC173Facet(address(ruleProcessor)).owner());
        // call a function
        assertEq("good", SampleFacet(address(ruleProcessor)).sampleFunction());
    }

    function testProtocol_RuleProcessorDiamond_UpgradeTransferOwnership() public endWithStopPrank ifDeploymentTestsEnabled {
        // must be the owner for upgrade
        switchToSuperAdmin();
        _facetCutSetUp();
        /// test transfer ownership
        address newOwner = address(0xB00);
        ERC173Facet(address(ruleProcessor)).transferOwnership(newOwner);
        address retrievedOwner = ERC173Facet(address(ruleProcessor)).owner();
        assertEq(retrievedOwner, newOwner);
    }

    function testProtocol_RuleProcessorDiamond_UpgradeTransferOwnershipCallFunction() public endWithStopPrank ifDeploymentTestsEnabled {
        _facetCutSetUp();
        /// test transfer ownership
        address newOwner = address(0xB00);
        ERC173Facet(address(ruleProcessor)).transferOwnership(newOwner);
        address retrievedOwner = ERC173Facet(address(ruleProcessor)).owner();
        assertEq(retrievedOwner, newOwner);
        vm.stopPrank();
        vm.startPrank(newOwner);
        // call a function
        assertEq("good", SampleFacet(address(ruleProcessor)).sampleFunction());
    }

    function testProtocol_RuleProcessorDiamond_UpgradeTransferOwnership_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _facetCutSetUp();
        /// test transfer ownership
        address newOwner = address(0xB00);
        ERC173Facet(address(ruleProcessor)).transferOwnership(newOwner);
        address retrievedOwner = ERC173Facet(address(ruleProcessor)).owner();
        assertEq(retrievedOwner, newOwner);
        /// test that an onlyOwner function will fail when called by not the owner
        vm.expectRevert("UNAUTHORIZED");
        SampleFacet(address(ruleProcessor)).sampleFunction();
    }

    function testProtocol_RuleProcessorDiamond_UpgradeRuleProcessor_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _facetCutSetUp();
        /// transfer ownership
        address newOwner = address(0xB00);
        ERC173Facet(address(ruleProcessor)).transferOwnership(newOwner);
        //build new cut struct
        SampleUpgradeFacet testFacet = new SampleUpgradeFacet();
        FacetCut[] memory cut = new FacetCut[](1);
        cut[0] = (FacetCut({facetAddress: address(testFacet), action: FacetCutAction.Add, functionSelectors: generateSelectors("SampleUpgradeFacet")}));
        // test that account that isn't the owner cannot upgrade
        switchToSuperAdmin();
        //upgrade diamond
        vm.expectRevert("UNAUTHORIZED");
        IDiamondCut(address(ruleProcessor)).diamondCut(cut, address(0x0), "");
    }

    function _facetCutSetUp() internal {
        // must be the owner for upgrade
        switchToSuperAdmin();
        SampleFacet _sampleFacet = new SampleFacet();
        //build cut struct
        FacetCut[] memory cut = new FacetCut[](1);
        cut[0] = (FacetCut({facetAddress: address(_sampleFacet), action: FacetCutAction.Add, functionSelectors: generateSelectors("SampleFacet")}));
        // check event emission 
        vm.expectEmit(true, true, true, false);
        emit IDiamondCut.DiamondCut(cut, address(0x0), "");
        //upgrade diamond
        IDiamondCut(address(ruleProcessor)).diamondCut(cut, address(0x0), "");
    }

    /// Test Diamond Versioning
    function testProtocol_RuleProcessorDiamond_RuleProcessorVersion() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToSuperAdmin();
        // update version
        VersionFacet(address(ruleProcessor)).updateVersion("1,0,0"); // commas are used here to avoid upgrade_version-script replacements
        string memory version = VersionFacet(address(ruleProcessor)).version();
        console.log(version);
        assertEq(version, "1,0,0");
    }

    function testProtocol_RuleProcessorDiamond_RuleProcessorVersion2() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToSuperAdmin();
        // update version
        VersionFacet(address(ruleProcessor)).updateVersion("2.1.0"); // upgrade_version script will replace this version
        string memory version = VersionFacet(address(ruleProcessor)).version();
        console.log(version);
        assertEq(version, "2.1.0");
    }

    function testProtocol_RuleProcessorDiamond_RuleProcessorVersion_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToSuperAdmin();
        // update version
        VersionFacet(address(ruleProcessor)).updateVersion("2.1.0"); // upgrade_version script will replace this version
        string memory version = VersionFacet(address(ruleProcessor)).version();
        console.log(version);
        assertEq(version, "2.1.0");
        // test that no other than the owner can update the version
        vm.stopPrank();
        if (vm.envAddress("DEPLOYMENT_OWNER") != address(0x0)) {
            vm.startPrank(user1, user1);
        } else {
            switchToAppAdministrator();
        }
        vm.expectRevert("UNAUTHORIZED");
        VersionFacet(address(ruleProcessor)).updateVersion("6,6,6"); // this is done to avoid upgrade_version-script replace this version
    }

    /************************ AccountMaxTradeSize *************************/
    function _createAccountMaxTradeSetUp() internal returns (uint32) {
        switchToRuleAdmin();
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxTradeSize(
            address(applicationAppManager),
            createBytes32Array("Oscar", "Tayler", "Shane"),
            createUint240Array(1000, 2000, 3000),
            createUint16Array(24, 36, 48),
            Blocktime
        );
        return ruleId;
    }

    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_AccountMaxTradeSizeSetting() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32 _index = _createAccountMaxTradeSetUp();
        TaggedRules.AccountMaxTradeSize memory rule = ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).getAccountMaxTradeSize(_index, "Oscar");
        assertEq(rule.maxSize, 1000);
        assertEq(rule.period, 24);
        assertEq(_index, 0);
    }

    /// Test only ruleAdministrators can add AccountMaxTradeSize Rule
    function testProtocol_RuleProcessorDiamond_AccountMaxTradeSizeSettingWithoutAppAdministratorAccount() public endWithStopPrank ifDeploymentTestsEnabled {
        vm.startPrank(address(0xDEAD)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxTradeSize(address(applicationAppManager), createBytes32Array("Oscar"), createUint240Array(1000), createUint16Array(24), Blocktime);
    }

    /// Test mismatched arrays sizes
    function testProtocol_RuleProcessorDiamond_AccountMaxTradeSizeSettingWithArraySizeMismatch() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        vm.expectRevert(0x028a6c58);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxTradeSize(
            address(applicationAppManager),
            createBytes32Array("Oscar", "Tayler", "Shane"),
            createUint240Array(1000),
            createUint16Array(24),
            Blocktime
        );
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_AccountMaxTradeSizeTotalRules() public endWithStopPrank ifDeploymentTestsEnabled {
        uint256[101] memory _indexes;
        for (uint8 i = 0; i < _indexes.length; i++) {
            _indexes[i] = _createAccountMaxTradeSetUp();
        }
        assertEq(ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).getTotalAccountMaxTradeSize(), _indexes.length);
    }

    /************************ PurchaseFeeByVolumeRule **********************/
    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_PurchaseFeeByVolumeRuleSetting() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addPurchaseFeeByVolumeRule(address(applicationAppManager), 5000000000000000000000000000000000, 100);
        assertEq(_index, 0);
        NonTaggedRules.TokenPurchaseFeeByVolume memory rule = RuleDataFacet(address(ruleProcessor)).getPurchaseFeeByVolumeRule(_index);
        assertEq(rule.rateIncreased, 100);
    }

    /// Test only ruleAdministrators can add PurchaseFeeByVolumeRule
    function testProtocol_RuleProcessorDiamond_PurchaseFeeByVolumeRuleSettingRuleWithoutAppAdministratorAccount() public endWithStopPrank ifDeploymentTestsEnabled {
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addPurchaseFeeByVolumeRule(address(applicationAppManager), 5000000000000000000000000000000000, 100);
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_TotalRulesOnPurchaseFeeByVolume() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint256[101] memory _indexes;
        for (uint8 i = 0; i < 101; i++) {
            _indexes[i] = RuleDataFacet(address(ruleProcessor)).addPurchaseFeeByVolumeRule(address(applicationAppManager), 500 + i, 1 + i);
        }
        assertEq(RuleDataFacet(address(ruleProcessor)).getTotalTokenPurchaseFeeByVolumeRules(), _indexes.length);
    }

    /*********************** TokenMaxPriceVolatility ************************/
    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_TokenMaxPriceVolatilitySetting() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addTokenMaxPriceVolatility(address(applicationAppManager), 5000, 60, 12, totalSupply);
        assertEq(_index, 0);
        NonTaggedRules.TokenMaxPriceVolatility memory rule = RuleDataFacet(address(ruleProcessor)).getTokenMaxPriceVolatility(_index);
        assertEq(rule.hoursFrozen, 12);
    }

    function testProtocol_RuleProcessorDiamond_TokenMaxPriceVolatilitySetting_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        vm.expectRevert(0x71724ffd);
        RuleDataFacet(address(ruleProcessor)).addTokenMaxPriceVolatility(address(0), 666, 100, 16, totalSupply);
    }

    /// Test only ruleAdministrators can add TokenMaxPriceVolatility Rule
    function testProtocol_RuleProcessorDiamond_TokenMaxPriceVolatilitySettingWithoutAppAdministratorAccount() public endWithStopPrank ifDeploymentTestsEnabled {
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addTokenMaxPriceVolatility(address(applicationAppManager), 5000, 60, 24, totalSupply);
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_TokenMaxPriceVolatilityTotalRules() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint256[101] memory _indexes;
        for (uint8 i = 0; i < 101; i++) {
            _indexes[i] = RuleDataFacet(address(ruleProcessor)).addTokenMaxPriceVolatility(address(applicationAppManager), 5000 + i, 60 + i, 24 + i, totalSupply);
        }
        assertEq(RuleDataFacet(address(ruleProcessor)).getTotalTokenMaxPriceVolatility(), _indexes.length);
    }

    /*********************** MaxTradingVolume Rule ************************/
    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_TokenMaxTradingVolumeRuleSetting() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addTokenMaxTradingVolume(address(applicationAppManager), 1000, 2, Blocktime, 0);
        assertEq(_index, 0);
        NonTaggedRules.TokenMaxTradingVolume memory rule = ERC20RuleProcessorFacet(address(ruleProcessor)).getTokenMaxTradingVolume(_index);
        assertEq(rule.startTime, Blocktime);
    }

    function testProtocol_RuleProcessorDiamond_TokenMaxTradingVolumeRuleSetting_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        vm.expectRevert(0x71724ffd);
        RuleDataFacet(address(ruleProcessor)).addTokenMaxTradingVolume(address(0), 2000, 1, 12, 1_000_000_000_000_000 * 10 ** 18);
    }

    /// Test only ruleAdministrators can add Max Trading Volume Rule
    function testProtocol_RuleProcessorDiamond_TokenMaxTradingVolumeRuleSettingWithoutappAdministratorAccount() public endWithStopPrank ifDeploymentTestsEnabled {
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addTokenMaxTradingVolume(address(applicationAppManager), 4000, 2, 23, 0);
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_TokenMaxTradingVolumeRuleTotalRules() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint256[101] memory _indexes;
        for (uint8 i = 0; i < 101; i++) {
            _indexes[i] = RuleDataFacet(address(ruleProcessor)).addTokenMaxTradingVolume(address(applicationAppManager), 5000 + i, 60 + i, Blocktime, 0);
        }
        assertEq(ERC20RuleProcessorFacet(address(ruleProcessor)).getTotalTokenMaxTradingVolume(), _indexes.length);
    }

    /*********************** TokenMinTransactionSize ************************/
    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_TokenMinTransactionSizeSetting() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addTokenMinTxSize(address(applicationAppManager), 500000000000000);
        assertEq(_index, 0);
        NonTaggedRules.TokenMinTxSize memory rule = ERC20RuleProcessorFacet(address(ruleProcessor)).getTokenMinTxSize(_index);
        assertEq(rule.minSize, 500000000000000);
    }

    /// Test only ruleAdministrators can add TokenMinTransactionSize Rule
    function testProtocol_RuleProcessorDiamond_TokenMinTransactionSizeSettingRuleWithoutAppAdministratorAccount() public endWithStopPrank ifDeploymentTestsEnabled {
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addTokenMinTxSize(address(applicationAppManager), 500000000000000);
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_TokenMinTransactionSizeTotalRules() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint256[101] memory _indexes;
        for (uint8 i = 0; i < 101; i++) {
            _indexes[i] = RuleDataFacet(address(ruleProcessor)).addTokenMinTxSize(address(applicationAppManager), 5000 + i);
        }
        assertEq(ERC20RuleProcessorFacet(address(ruleProcessor)).getTotalTokenMinTxSize(), _indexes.length);
    }

    /*********************** AccountMinMaxTokenBalance *******************/
    function _setUpMinMaxTokenRule() internal returns (uint32) {
        switchToRuleAdmin();
        bytes32[] memory accs = createBytes32Array("Oscar", "Tayler", "Shane");
        uint256[] memory min = createUint256Array(100000000, 20000000, 3000000);
        uint256[] memory max = createUint256Array(10000000000000000000000000000000000000, 1000 * BIGNUMBER, 10000 * BIGNUMBER);
        uint16[] memory empty;
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        return ruleId;
    }

    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceSetting() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32 _index = _setUpMinMaxTokenRule();
        assertEq(_index, 0);
        TaggedRules.AccountMinMaxTokenBalance memory rule = ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).getAccountMinMaxTokenBalance(_index, "Oscar");
        assertEq(rule.min, 100000000);
        assertEq(rule.max, 10000000000000000000000000000000000000);
    }

    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceSetting_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint16[] memory empty;
        vm.expectRevert(0x71724ffd);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
            address(0),
            createBytes32Array("Oscar"),
            createUint256Array(1000),
            createUint256Array(10000000000000000000000000000000000000),
            empty,
            uint64(Blocktime)
        );
    }

    /// Test only ruleAdministrators can add Min Max Token Balance Rule
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceSettingWithoutAppAdministratorAccount() public endWithStopPrank ifDeploymentTestsEnabled {
        uint16[] memory empty;
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
            address(applicationAppManager),
            createBytes32Array("Oscar"),
            createUint256Array(1000),
            createUint256Array(10000000000000000000000000000000000000),
            empty,
            uint64(Blocktime)
        );
    }

    /// Test mismatched arrays sizes
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceSettingWithArraySizeMismatch() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint16[] memory empty;
        vm.expectRevert(0x028a6c58);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
            address(applicationAppManager),
            createBytes32Array("Oscar", "Tayler", "Shane"),
            createUint256Array(1000),
            createUint256Array(10000000000000000000000000000000000000),
            empty,
            uint64(Blocktime)
        );
    }

    /// Test inverted limits
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceAddWithInvertedLimits() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint16[] memory empty;
        vm.expectRevert(0xeeb9d4f7);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
            address(applicationAppManager),
            createBytes32Array("Oscar"),
            createUint256Array(999999 * BIGNUMBER),
            createUint256Array(100),
            empty,
            uint64(Blocktime)
        );
    }

    /// Test mixing Periodic and Non-Periodic cases
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceAddMixedPeriodicAndNonPeriodic() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        vm.expectRevert(0xb75194a4);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
            address(applicationAppManager),
            createBytes32Array("Oscar", "Shane"),
            createUint256Array(10, 20),
            createUint256Array(999999 * BIGNUMBER, 999999 * BIGNUMBER),
            createUint16Array(10, 0),
            uint64(Blocktime)
        );
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceTotalRules() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint256[101] memory _indexes;
        uint16[] memory empty;
        for (uint8 i = 0; i < _indexes.length; i++) {
            _indexes[i] = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
                address(applicationAppManager),
                createBytes32Array("Oscar"),
                createUint256Array(100),
                createUint256Array(999999 * BIGNUMBER),
                empty,
                uint64(Blocktime)
            );
        }
        assertEq(ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).getTotalAccountMinMaxTokenBalances(), _indexes.length);
    }

    function _setUpMinMaxTokenRuleWithPeriods() internal returns (uint32) {
        switchToRuleAdmin();
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
            address(applicationAppManager),
            createBytes32Array("Oscar", "Tayler", "Shane"),
            createUint256Array(1000, 2000, 3000),
            createUint256Array(999999 * BIGNUMBER, 999999 * BIGNUMBER, 999999 * BIGNUMBER),
            createUint16Array(100, 101, 102),
            uint64(Blocktime)
        );
        return ruleId;
    }

    /// With Hold Periods
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceSettingWithPeriod() public endWithStopPrank ifDeploymentTestsEnabled {
        uint32 _index = _setUpMinMaxTokenRuleWithPeriods();
        assertEq(_index, 0);
        TaggedRules.AccountMinMaxTokenBalance memory rule = ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).getAccountMinMaxTokenBalance(_index, "Oscar");
        assertEq(rule.min, 1000);
        assertEq(rule.period, 100);
    }

    /// Test Account Min Max Token Balance while not admin
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceSettingNotAdmin() public endWithStopPrank ifDeploymentTestsEnabled {
        vm.startPrank(address(0xDEAD));
        vm.expectRevert(0xd66c3008);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
            address(applicationAppManager),
            createBytes32Array("Oscar", "Tayler", "Shane"),
            createUint256Array(1000, 2000, 3000),
            createUint256Array(999999 * BIGNUMBER, 999999 * BIGNUMBER, 999999 * BIGNUMBER),
            createUint16Array(100, 101, 102),
            uint64(Blocktime)
        );
    }

    /// Test for proper array size mismatch error
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceSettingSizeMismatch() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        vm.expectRevert(0x028a6c58);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
            address(applicationAppManager),
            createBytes32Array("Oscar"),
            createUint256Array(100),
            createUint256Array(999999 * BIGNUMBER),
            createUint16Array(100, 101),
            uint64(Blocktime)
        );
    }

    /*********************** TokenMaxSupplyVolatility ************************/
    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_TokenMaxSupplyVolatilitySetting() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addTokenMaxSupplyVolatility(address(applicationAppManager), 6500, 24, Blocktime, totalSupply);
        assertEq(_index, 0);
        NonTaggedRules.TokenMaxSupplyVolatility memory rule = ERC20RuleProcessorFacet(address(ruleProcessor)).getTokenMaxSupplyVolatility(_index);
        assertEq(rule.startTime, Blocktime);

        _index = RuleDataFacet(address(ruleProcessor)).addTokenMaxSupplyVolatility(address(applicationAppManager), 5000, 24, Blocktime, totalSupply);
        assertEq(_index, 1);
        rule = ERC20RuleProcessorFacet(address(ruleProcessor)).getTokenMaxSupplyVolatility(_index);
        assertEq(rule.startTime, Blocktime);
    }

    /// Test only ruleAdministrators can add TokenMaxSupplyVolatility Rule
    function testProtocol_RuleProcessorDiamond_TokenMaxSupplyVolatilitySettingRuleWithoutAppAdministratorAccount() public endWithStopPrank ifDeploymentTestsEnabled {
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addTokenMaxSupplyVolatility(address(applicationAppManager), 6500, 24, Blocktime, totalSupply);
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_TokenMaxSupplyVolatilityTotalRules() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint256[101] memory _indexes;
        for (uint8 i = 0; i < 101; i++) {
            _indexes[i] = RuleDataFacet(address(ruleProcessor)).addTokenMaxSupplyVolatility(address(applicationAppManager), 6500 + i, 24 + i, 12, totalSupply);
        }
        assertEq(ERC20RuleProcessorFacet(address(ruleProcessor)).getTotalTokenMaxSupplyVolatility(), _indexes.length);
    }

    /*********************** AccountApproveDenyOracle ************************/
    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_AccountApproveDenyOracleDeny() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 0, address(59));
        assertEq(_index, 0);
        NonTaggedRules.AccountApproveDenyOracle memory rule = ERC20RuleProcessorFacet(address(ruleProcessor)).getAccountApproveDenyOracle(_index);
        assertEq(rule.oracleType, 0);
        assertEq(rule.oracleAddress, address(59));
        _index = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 1, address(79));
        assertEq(_index, 1);
        rule = ERC20RuleProcessorFacet(address(ruleProcessor)).getAccountApproveDenyOracle(_index);
        assertEq(rule.oracleType, 1);
    }

    function testProtocol_RuleProcessorDiamond_AccountApproveDenyOracleApprove() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 1, address(79));
        assertEq(_index, 0);
        NonTaggedRules.AccountApproveDenyOracle memory rule = ERC20RuleProcessorFacet(address(ruleProcessor)).getAccountApproveDenyOracle(_index);
        assertEq(rule.oracleType, 1);
    }

    /// Test only ruleAdministrators can add AccountApproveDenyOracle Rule
    function testProtocol_RuleProcessorDiamond_AccountApproveDenyOracleSettingWithoutAppAdministratorAccount() public endWithStopPrank ifDeploymentTestsEnabled {
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 0, address(59));
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_AccountApproveDenyOracleTotalRules() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint256[101] memory _indexes;
        for (uint8 i = 0; i < 101; i++) {
            _indexes[i] = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 0, address(59));
        }
        assertEq(ERC20RuleProcessorFacet(address(ruleProcessor)).getTotalAccountApproveDenyOracle(), _indexes.length);
    }

    /*********************** AccountApproveDenyOracleFlexible ************************/
    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_AccountApproveDenyOracleFlexibleDeny() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracleFlexible(address(applicationAppManager), 0, 0, address(59));
        assertEq(_index, 0);
        NonTaggedRules.AccountApproveDenyOracleFlexible memory rule = ERC20RuleProcessorFacet(address(ruleProcessor)).getAccountApproveDenyOracleFlexible(_index);
        assertEq(rule.oracleType, 0);
        assertEq(rule.oracleAddress, address(59));
        _index = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracleFlexible(address(applicationAppManager), 1, 0, address(79));
        assertEq(_index, 1);
        rule = ERC20RuleProcessorFacet(address(ruleProcessor)).getAccountApproveDenyOracleFlexible(_index);
        assertEq(rule.oracleType, 1);
    }

    function testProtocol_RuleProcessorDiamond_AccountApproveDenyOracleFlexibleApprove() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracleFlexible(address(applicationAppManager), 1, 0, address(79));
        assertEq(_index, 0);
        NonTaggedRules.AccountApproveDenyOracleFlexible memory rule = ERC20RuleProcessorFacet(address(ruleProcessor)).getAccountApproveDenyOracleFlexible(_index);
        assertEq(rule.oracleType, 1);
    }

    /// Test only ruleAdministrators can add AccountApproveDenyOracle Rule
    function testProtocol_RuleProcessorDiamond_AccountApproveDenyOracleFlexibleSettingWithoutAppAdministratorAccount() public endWithStopPrank ifDeploymentTestsEnabled {
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 0, address(59));
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_AccountApproveDenyOracleFlexibleTotalRules() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint256[101] memory _indexes;
        for (uint8 i = 0; i < 101; i++) {
            _indexes[i] = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracleFlexible(address(applicationAppManager), 0, 1, address(59));
        }
        assertEq(ERC20RuleProcessorFacet(address(ruleProcessor)).getTotalAccountApproveDenyOracleFlexible(), _indexes.length);
    }

    /*********************** TokenMaxDailyTrades ************************/
    function testProtocol_RuleProcessorDiamond_TokenMaxDailyTrades() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        bytes32[] memory nftTags = createBytes32Array("BoredGrape", "DiscoPunk");
        uint8[] memory tradesAllowed = createUint8Array(1, 5);
        uint32 _index = TaggedRuleDataFacet(address(ruleProcessor)).addTokenMaxDailyTrades(address(applicationAppManager), nftTags, tradesAllowed, Blocktime);
        assertEq(_index, 0);
        TaggedRules.TokenMaxDailyTrades memory rule = ERC721TaggedRuleProcessorFacet(address(ruleProcessor)).getTokenMaxDailyTrades(_index, nftTags[0]);
        assertEq(rule.tradesAllowedPerDay, 1);
        rule = ERC721TaggedRuleProcessorFacet(address(ruleProcessor)).getTokenMaxDailyTrades(_index, nftTags[1]);
        assertEq(rule.tradesAllowedPerDay, 5);
    }

    /// Test only ruleAdministrators can add TokenMaxDailyTrades Rule
    function testProtocol_RuleProcessorDiamond_TokenMaxDailyTradesSettingRuleWithoutAppAdministratorAccount() public endWithStopPrank ifDeploymentTestsEnabled {
        bytes32[] memory nftTags = createBytes32Array("BoredGrape", "DiscoPunk");
        uint8[] memory tradesAllowed = createUint8Array(1, 5);
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        TaggedRuleDataFacet(address(ruleProcessor)).addTokenMaxDailyTrades(address(applicationAppManager), nftTags, tradesAllowed, Blocktime);
    }

    /// Test Token Max Daily Trades Rule with Blank Tags
    function testProtocol_RuleProcessorDiamond_TokenMaxDailyTradesRulesBlankTag_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        bytes32[] memory nftTags = createBytes32Array("");
        uint8[] memory tradesAllowed = createUint8Array(1);
        uint32 _index = TaggedRuleDataFacet(address(ruleProcessor)).addTokenMaxDailyTrades(address(applicationAppManager), nftTags, tradesAllowed, Blocktime);
        assertEq(_index, 0);
        TaggedRules.TokenMaxDailyTrades memory rule = ERC721TaggedRuleProcessorFacet(address(ruleProcessor)).getTokenMaxDailyTrades(_index, nftTags[0]);
        assertEq(rule.tradesAllowedPerDay, 1);
    }

    /// Test Token Max Daily Trades Rule with negative case
    function testProtocol_RuleProcessorDiamond_TokenMaxDailyTradesRulesBlankTag_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        bytes32[] memory nftTags = createBytes32Array("", "BoredGrape");
        uint8[] memory tradesAllowed = createUint8Array(1, 5);
        vm.expectRevert(0x6bb35a99);
        TaggedRuleDataFacet(address(ruleProcessor)).addTokenMaxDailyTrades(address(applicationAppManager), nftTags, tradesAllowed, Blocktime);
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_TokenMaxDailyTradesTotalRules() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        bytes32[] memory nftTags = createBytes32Array("BoredGrape", "DiscoPunk");
        uint8[] memory tradesAllowed = createUint8Array(1, 5);
        uint256[101] memory _indexes;
        for (uint8 i = 0; i < 101; i++) {
            _indexes[i] = TaggedRuleDataFacet(address(ruleProcessor)).addTokenMaxDailyTrades(address(applicationAppManager), nftTags, tradesAllowed, Blocktime);
        }
        assertEq(ERC721TaggedRuleProcessorFacet(address(ruleProcessor)).getTotalTokenMaxDailyTrades(), _indexes.length);
    }

    /**************** Account Max Value by Access Level Rule  ****************/
    /// Test Adding AccountMaxValueByAccessLevel
    function testProtocol_RuleProcessorDiamond_AccountMaxValueByAccessLevelRuleAdd() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint48[] memory balanceAmounts = createUint48Array(10, 100, 500, 1000, 1000);
        uint32 _index = AppRuleDataFacet(address(ruleProcessor)).addAccountMaxValueByAccessLevel(address(applicationAppManager), balanceAmounts);
        /// account for already deployed contract that has AccessLevelBalanceRule added
        uint256 testBalance = ApplicationAccessLevelProcessorFacet(address(ruleProcessor)).getAccountMaxValueByAccessLevel(_index, 2);
        assertEq(testBalance, 500);
    }

    /// Test Adding AccountMaxValueByAccessLevel while not admin
    function testProtocol_RuleProcessorDiamond_AccountMaxValueByAccessLevelAddNotAdmin() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint48[] memory balanceAmounts;
        vm.stopPrank(); //stop interacting as the super admin
        vm.startPrank(address(0xDEAD)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        AppRuleDataFacet(address(ruleProcessor)).addAccountMaxValueByAccessLevel(address(applicationAppManager), balanceAmounts);
    }

    /// Test AccountMaxValueByAccessLevel total Rules
    function testProtocol_RuleProcessorDiamond_AccountMaxValueByAccessLevelTotalRules() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint256[101] memory _indexes;
        uint48[] memory balanceAmounts = createUint48Array(10, 100, 500, 1000, 1000);
        for (uint8 i = 0; i < _indexes.length; i++) {
            _indexes[i] = AppRuleDataFacet(address(ruleProcessor)).addAccountMaxValueByAccessLevel(address(applicationAppManager), balanceAmounts);
        }
        uint256 result = ApplicationAccessLevelProcessorFacet(address(ruleProcessor)).getTotalAccountMaxValueByAccessLevel();
        assertEq(result, _indexes.length);
    }

    /***************** RULE PROCESSING *****************/
    /// Test Token Min Transaction Size while not admin
    function testProtocol_RuleProcessorDiamond_TokenMinTransactionSizeNotPassingByNonAdmin() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToUser();
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addTokenMinTxSize(address(applicationAppManager), 1000);
    }

    /// Test Token Min Transaction Size
    function testProtocol_RuleProcessorDiamond_TokenMinTransactionSize() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint32 index = RuleDataFacet(address(ruleProcessor)).addTokenMinTxSize(address(applicationAppManager), 2222);
        switchToUser();
        ERC20RuleProcessorFacet(address(ruleProcessor)).checkTokenMinTxSize(index, 2222);
    }

    /// Test Token Min Transaction Size fail scenario
    function testProtocol_RuleProcessorDiamond_TokenMinTransactionSizeNotPassing() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint32 index = RuleDataFacet(address(ruleProcessor)).addTokenMinTxSize(address(applicationAppManager), 420);
        vm.expectRevert(0x7a78c901);
        ERC20RuleProcessorFacet(address(ruleProcessor)).checkTokenMinTxSize(index, 400);
    }

    /// Test Account Min Max Token Balance Rule
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceCheck() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint16[] memory empty;
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
            address(applicationAppManager),
            createBytes32Array("Oscar", "Tayler", "Shane"),
            createUint256Array(10, 20, 30),
            createUint256Array(1000000000, 1000000000, 1000000000),
            empty,
            uint64(Blocktime)
        );
        switchToAppAdministrator();
        applicationAppManager.addTag(user1, "Oscar"); //add tag
        assertTrue(applicationAppManager.hasTag(user1, "Oscar"));
        switchToSuperAdmin();
        applicationCoin.mint(user1, 10000);
        uint256 amount = 10;
        bytes32[] memory tags = applicationAppManager.getAllTags(user1);
        switchToUser();
        ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).checkAccountMinTokenBalance(applicationCoin.balanceOf(user1), tags, amount, ruleId);
    }

    /// Test Account Min Max Token Balance fail scenario
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceCheck_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        uint16[] memory empty;
        switchToRuleAdmin();
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
            address(applicationAppManager),
            createBytes32Array("Oscar", "Tayler", "Shane"),
            createUint256Array(10, 20, 30),
            createUint256Array(1000000000, 1000000000, 1000000000),
            empty,
            uint64(Blocktime)
        );
        switchToAppAdministrator();
        applicationAppManager.addTag(user1, "Oscar"); //add tag
        assertTrue(applicationAppManager.hasTag(user1, "Oscar"));
        switchToSuperAdmin();
        uint256 amount = 10000000000000000000000;
        applicationCoin.mint(user1, amount);
        assertEq(applicationCoin.balanceOf(user1), amount);
        bytes32[] memory tags = applicationAppManager.getAllTags(user1);
        uint256 balance = applicationCoin.balanceOf(user1);
        switchToUser();
        vm.expectRevert(abi.encodeWithSignature("UnderMinBalance()"));
        ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).checkAccountMinTokenBalance(balance, tags, amount, ruleId);
    }

    /// Test Max Tag Enforcement Through Account Min Max Token Balance Rule
    function testProtocol_RuleProcessorDiamond_MaxTagEnforcementThroughAccountMinMaxTokenBalance() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint16[] memory empty;
        // add rule at ruleId 0
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
            address(applicationAppManager),
            createBytes32Array("Oscar", "Tayler", "Shane"),
            createUint256Array(10, 20, 30),
            createUint256Array(1000000000, 1000000000, 1000000000),
            empty,
            uint64(Blocktime)
        );
        switchToAppAdministrator();
        for (uint i = 1; i < 11; i++) {
            applicationAppManager.addTag(user1, bytes32(i)); //add tag
        }
        uint256 amount = 1;
        bytes32[] memory tags = new bytes32[](11);
        for (uint i = 1; i < 12; i++) {
            tags[i - 1] = bytes32(i); //add tag
        }
        console.log(uint(tags[10]));
        switchToUser();
        vm.expectRevert(0xa3afb2e2);
        ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).checkAccountMinTokenBalance(10000000000000000000000, tags, amount, ruleId);
    }

    /// Test Account Min Max Balance Rule With Blank Tag Negative Case
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceBlankTagCheck_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        applicationCoin.mint(superAdmin, totalSupply);
        switchToRuleAdmin();
        uint16[] memory empty;
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
            address(applicationAppManager),
            createBytes32Array(""),
            createUint256Array(10),
            createUint256Array(10000),
            empty,
            uint64(Blocktime)
        );
        switchToSuperAdmin();
        uint256 amount = 10000000000000000000000000;
        bytes32[] memory tags = applicationAppManager.getAllTags(superAdmin);
        assertEq(applicationCoin.balanceOf(superAdmin), 100000000000);
        uint256 balance = applicationCoin.balanceOf(superAdmin);
        vm.expectRevert(abi.encodeWithSignature("OverMaxBalance()"));
        ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).checkAccountMaxTokenBalance(balance, tags, amount, ruleId);
    }

    /// Test Account Min Max Token Balance Rule with Blank Tags
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceBlankTag() public endWithStopPrank ifDeploymentTestsEnabled {
        applicationCoin.mint(superAdmin, totalSupply);
        switchToRuleAdmin();
        uint16[] memory empty;
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
            address(applicationAppManager),
            createBytes32Array(""),
            createUint256Array(10),
            createUint256Array(10000),
            empty,
            uint64(Blocktime)
        );
        uint256 amount = 1;
        assertEq(applicationCoin.balanceOf(superAdmin), totalSupply);
        bytes32[] memory tags = applicationAppManager.getAllTags(superAdmin);
        ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).checkAccountMinTokenBalance(applicationCoin.balanceOf(superAdmin), tags, amount, ruleId);
    }

    /// Test Account Min Max Token Balance Rule with Blank Tags negative case
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceBlankTagCreationCheck_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint16[] memory empty;
        // Can't add a blank and specific tag together
        vm.expectRevert(0x6bb35a99);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
            address(applicationAppManager),
            createBytes32Array("", "Shane"),
            createUint256Array(10, 10),
            createUint256Array(10000, 10000),
            empty,
            uint64(Blocktime)
        );
    }

    /// Test Adding Account Min Max Token Balance Rule with Blank Tags
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceBlankTagCreationCheck_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        uint16[] memory empty;
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
            address(applicationAppManager),
            createBytes32Array(""),
            createUint256Array(10),
            createUint256Array(10000),
            empty,
            uint64(Blocktime)
        );
    }

    /// Test Account Min Max Token Balance Rule Fail Scenario
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceCheck_UnderMinBalance() public endWithStopPrank ifDeploymentTestsEnabled {
        applicationCoin.mint(superAdmin, totalSupply);
        switchToRuleAdmin();
        uint16[] memory empty;
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
            address(applicationAppManager),
            createBytes32Array("Oscar", "Tayler", "Shane"),
            createUint256Array(10, 20, 30),
            createUint256Array(10000000000 * ATTO, 10000000000 * ATTO, 10000000000 * ATTO),
            empty,
            uint64(Blocktime)
        );
        switchToAppAdministrator();
        applicationAppManager.addTag(superAdmin, "Oscar"); //add tag
        assertTrue(applicationAppManager.hasTag(superAdmin, "Oscar"));
        uint256 balance = applicationCoin.balanceOf(superAdmin);
        uint256 amount = balance - 5; // we try to only leave 5 wei to trigger the rule
        assertEq(applicationCoin.balanceOf(superAdmin), totalSupply);
        bytes32[] memory tags = applicationAppManager.getAllTags(superAdmin);
        vm.expectRevert(abi.encodeWithSignature("UnderMinBalance()"));
        ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).checkAccountMinTokenBalance(balance, tags, amount, ruleId);
    }

    /// Test Account Min Max Balance Rule With Blank Tags
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceBlankTagProcessChecks() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        applicationCoin.mint(superAdmin, totalSupply);
        uint16[] memory empty;
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
            address(applicationAppManager),
            createBytes32Array(""),
            createUint256Array(10),
            createUint256Array(10000000000 * ATTO),
            empty,
            uint64(Blocktime)
        );
        uint256 amount = 999;
        assertEq(applicationCoin.balanceOf(superAdmin), totalSupply);
        bytes32[] memory tags = applicationAppManager.getAllTags(superAdmin);
        ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).checkAccountMaxTokenBalance(applicationCoin.balanceOf(superAdmin), tags, amount, ruleId);
    }

    /// Test Account Min Max Balance Check Fail Scenario
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceChecks_OverMaxBalance() public endWithStopPrank ifDeploymentTestsEnabled {
        applicationCoin.mint(superAdmin, totalSupply);
        switchToRuleAdmin();
        uint16[] memory empty;
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(
            address(applicationAppManager),
            createBytes32Array("Oscar", "Tayler", "Shane"),
            createUint256Array(10, 20, 30),
            createUint256Array(10000000000 * ATTO, 10000000000 * ATTO, 10000000000 * ATTO),
            empty,
            uint64(Blocktime)
        );
        switchToAppAdministrator();
        applicationAppManager.addTag(superAdmin, "Oscar"); //add tag
        assertTrue(applicationAppManager.hasTag(superAdmin, "Oscar"));
        uint256 balance = applicationCoin.balanceOf(superAdmin);
        uint256 amount = (10000000000 * ATTO) + 1;
        bytes32[] memory tags = applicationAppManager.getAllTags(superAdmin);
        vm.expectRevert(abi.encodeWithSignature("OverMaxBalance()"));
        ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).checkAccountMaxTokenBalance(balance, tags, amount, ruleId);
    }

    /// Test Account Min Max Token Balance Rule NFT
    function _setUpMinMaxBalanceRuleNFT() internal {
        switchToAppAdministrator();
        /// mint 6 NFTs to appAdministrator for transfer
        for (uint256 i; i < 6; i++) {
            applicationNFT.safeMint(appAdministrator);
        }
        ///Add Tag to account
        applicationAppManager.addTag(user, "Oscar"); ///add tag
        assertTrue(applicationAppManager.hasTag(user, "Oscar"));
        applicationAppManager.addTag(user2, "Oscar"); ///add tag
        assertTrue(applicationAppManager.hasTag(user2, "Oscar"));
        applicationAppManager.addTag(user3, "Oscar"); ///add tag
        assertTrue(applicationAppManager.hasTag(user3, "Oscar"));

        switchToRuleAdmin();
        // add the actual rule
        uint32 ruleId = createAccountMinMaxTokenBalanceRule(createBytes32Array("Oscar"), createUint256Array(1), createUint256Array(6));
        setAccountMinMaxTokenBalanceRule(address(applicationNFTHandler), ruleId);
    }

    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceRuleNFT() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpMinMaxBalanceRuleNFT();
        switchToAppAdministrator();
        ///transfer tokenId 3 and 4 to user1
        applicationNFT.transferFrom(appAdministrator, user, 3);
        applicationNFT.transferFrom(appAdministrator, user, 4);
        assertEq(applicationNFT.balanceOf(user), 2);
        ///perform transfer that checks rule
        switchToUser();
        applicationNFT.transferFrom(user, user2, 3);
        assertEq(applicationNFT.balanceOf(user2), 1);
        assertEq(applicationNFT.balanceOf(user), 1);
    }

    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceRuleNFT_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpMinMaxBalanceRuleNFT();
        switchToAppAdministrator();
        ///transfer tokenId 3 and 4 to user1
        applicationNFT.transferFrom(appAdministrator, user, 3);
        assertEq(applicationNFT.balanceOf(user), 1);
        /// make sure the minimum rules fail results in revert
        switchToUser();
        vm.expectRevert(0x3e237976);
        applicationNFT.transferFrom(user, user3, 3);
    }

    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceRuleNFTBurn_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpMinMaxBalanceRuleNFT();
        switchToAppAdministrator();
        applicationNFT.safeMint(user);
        applicationNFT.safeMint(user);
        // transfer to user1 to exceed limit
        switchToUser();
        /// test that burn works with rule
        applicationNFT.burn(6);
    }

    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceRuleNFTBurn_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        _setUpMinMaxBalanceRuleNFT();
        switchToAppAdministrator();
        applicationNFT.safeMint(user);
        // transfer to user1 to exceed limit
        switchToUser();
        vm.expectRevert(0x3e237976);
        applicationNFT.burn(6);
    }

    /// Test Account Approve Deny Oracle NFT
    function testProtocol_RuleProcessorDiamond_AccountApproveDenyOracleNFT_Positive() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        for (uint256 i; i < 5; i++) {
            applicationNFT.safeMint(user);
        }
        assertEq(applicationNFT.balanceOf(user), 5);
        // add a blocked address
        badBoys.push(address(70));
    
        switchToAppAdministrator();
        
        oracleDenied.addToDeniedList(badBoys);
        switchToAppAdministrator();
        // add the rule.
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        setAccountApproveDenyOracleRule(address(applicationNFTHandler), ruleId);
        ///perform transfer that checks rule
        switchToUser();
        applicationNFT.transferFrom(user, user2, 0);
        assertEq(applicationNFT.balanceOf(user2), 1);
    }

    function testProtocol_RuleProcessorDiamond_AccountApproveDenyOracleNFTDeny_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        for (uint256 i; i < 5; i++) {
            applicationNFT.safeMint(user);
        }
        assertEq(applicationNFT.balanceOf(user), 5);
        // add a blocked address
        badBoys.push(address(70));
        
        switchToAppAdministrator();
        
        oracleDenied.addToDeniedList(badBoys);
        switchToAppAdministrator();
        // add the rule.
        uint32 ruleId = createAccountApproveDenyOracleRule(0);
        setAccountApproveDenyOracleRule(address(applicationNFTHandler), ruleId);
        // test that the oracle works
        vm.expectRevert(abi.encodeWithSignature("AddressIsDenied()"));
        switchToUser();
        applicationNFT.transferFrom(user, address(70), 1);
        assertEq(applicationNFT.balanceOf(address(70)), 0);
    }

    function testProtocol_RuleProcessorDiamond_AccountApproveDenyOracleNFTApprove_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        for (uint256 i; i < 5; i++) {
            applicationNFT.safeMint(user);
        }
        assertEq(applicationNFT.balanceOf(user), 5);
        goodBoys.push(address(59));
        switchToAppAdministrator();

        oracleApproved.addToApprovedList(goodBoys);
        switchToAppAdministrator();
        uint32 ruleId = createAccountApproveDenyOracleRule(1);
        setAccountApproveDenyOracleRule(address(applicationNFTHandler), ruleId);
        switchToUser();
        vm.expectRevert(0xcafd3316);
        applicationNFT.transferFrom(user, address(88), 3);
    }

    function testProtocol_RuleProcessorDiamond_AccountApproveDenyOracleNFTInvalidType_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToRuleAdmin();
        bytes4 selector = bytes4(keccak256("InvalidOracleType(uint8)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 2));
        RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 2, address(oracleApproved));
    }

    function testProtocol_RuleProcessorDiamond_TokenMaxDailyTradesRuleInNFT() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        for (uint256 i; i < 5; i++) {
            applicationNFT.safeMint(user);
        }
        assertEq(applicationNFT.balanceOf(user), 5);
        applicationAppManager.addTag(address(applicationNFT), "DiscoPunk"); ///add tag
        // add the rule
        uint32 ruleId = createTokenMaxDailyTradesRule("BoredGrape", "DiscoPunk", 1, 5);
        setTokenMaxDailyTradesRule(address(applicationNFTHandler), ruleId);
        // ensure standard transfer works by transferring 1 to user2 and back(2 trades)
        switchToUser();
        applicationNFT.transferFrom(user, user2, 0);
        assertEq(applicationNFT.balanceOf(user2), 1);
        vm.stopPrank();
        vm.startPrank(user2, user2);
        applicationNFT.transferFrom(user2, user1, 0);
        assertEq(applicationNFT.balanceOf(user2), 0);
    }

    function testProtocol_RuleProcessorDiamond_TokenMaxDailyTradesRuleInNFT_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        switchToAppAdministrator();
        for (uint256 i; i < 5; i++) {
            applicationNFT.safeMint(user1);
        }
        assertEq(applicationNFT.balanceOf(user1), 5);
        applicationAppManager.addTag(address(applicationNFT), "DiscoPunk"); ///add tag
        // add the rule.
        uint32 ruleId = createTokenMaxDailyTradesRule("BoredGrape", "DiscoPunk", 1, 5);
        setTokenMaxDailyTradesRule(address(applicationNFTHandler), ruleId);

        // ensure standard transfer works by transferring 1 to user2 and back(2 trades)
        vm.stopPrank();
        vm.startPrank(user1, user1);
        applicationNFT.transferFrom(user1, user2, 0);
        assertEq(applicationNFT.balanceOf(user2), 1);
        vm.stopPrank();
        vm.startPrank(user2, user2);
        applicationNFT.transferFrom(user2, user1, 0);
        assertEq(applicationNFT.balanceOf(user2), 0);
        // set to a tag that only allows 1 transfer
        switchToAppAdministrator();
        applicationAppManager.removeTag(address(applicationNFT), "DiscoPunk"); ///add tag
        applicationAppManager.addTag(address(applicationNFT), "BoredGrape"); ///add tag
        // perform 1 transfer
        vm.stopPrank();
        vm.startPrank(user1, user1);
        applicationNFT.transferFrom(user1, user2, 1);
        assertEq(applicationNFT.balanceOf(user2), 1);
        vm.stopPrank();
        vm.startPrank(user2, user2);
        // this one should fail because it is more than 1 in 24 hours
        vm.expectRevert(abi.encodeWithSignature("OverMaxDailyTrades()"));
        applicationNFT.transferFrom(user2, user1, 1);
        assertEq(applicationNFT.balanceOf(user2), 1);
    }

    function testProtocol_RuleProcessorDiamond_TokenMaxDailyTradesRuleInNFTSecondTradeWindow_Negative() public endWithStopPrank ifDeploymentTestsEnabled {
        vm.warp(Blocktime);
        switchToAppAdministrator();
        for (uint256 i; i < 5; i++) {
            applicationNFT.safeMint(user1);
        }
        applicationNFT.safeMint(user2);
        assertEq(applicationNFT.balanceOf(user1), 5);
        assertEq(applicationNFT.balanceOf(user2), 1);
        applicationAppManager.addTag(address(applicationNFT), "BoredGrape"); ///add tag
        // add the rule.
        uint32 ruleId = createTokenMaxDailyTradesRule("BoredGrape", "DiscoPunk", 1, 5);
        setTokenMaxDailyTradesRule(address(applicationNFTHandler), ruleId);
        // add a day to the time
        vm.warp(block.timestamp + 1 days);
        vm.stopPrank();
        vm.startPrank(user2, user2);
        applicationNFT.transferFrom(user2, user1, 5);
        assertEq(applicationNFT.balanceOf(user2), 0);
        vm.stopPrank();
        vm.startPrank(user1, user1);
        // first one should pass
        applicationNFT.transferFrom(user1, user2, 2);
        vm.stopPrank();
        vm.startPrank(user2, user2);
        // this one should fail because it is more than 1 in 24 hours
        vm.expectRevert(abi.encodeWithSignature("OverMaxDailyTrades()"));
        applicationNFT.transferFrom(user2, user1, 2);
    }

    function testProtocol_RuleProcessorDiamond_DiamondCut_Replace() public endWithStopPrank ifDeploymentTestsEnabled{
        _facetCutSetUp();
        //switchToSuperAdmin();
        SampleFacet _sampleFacet2 = new SampleFacet();
        //build cut struct
        FacetCut[] memory cut = new FacetCut[](1);
        cut[0] = (FacetCut({facetAddress: address(_sampleFacet2), action: FacetCutAction.Replace, functionSelectors: generateSelectors("SampleFacet")}));
        // check event emission 
        vm.expectEmit(true, true, true, false);
        emit IDiamondCut.DiamondCut(cut, address(0x0), "");
        //upgrade diamond
        IDiamondCut(address(ruleProcessor)).diamondCut(cut, address(0x0), "");
    }

    function testProtocol_RuleProcessorDiamond_DiamondCut_Remove() public endWithStopPrank ifDeploymentTestsEnabled{
        _facetCutSetUp();
        //build cut struct
        FacetCut[] memory cut = new FacetCut[](1);
        cut[0] = (FacetCut({facetAddress: address(0), action: FacetCutAction.Remove, functionSelectors: generateSelectors("SampleFacet")}));
        // check event emission 
        vm.expectEmit(true, true, true, false);
        emit IDiamondCut.DiamondCut(cut, address(0x0), "");
        //upgrade diamond
        IDiamondCut(address(ruleProcessor)).diamondCut(cut, address(0x0), "");
    }
}
