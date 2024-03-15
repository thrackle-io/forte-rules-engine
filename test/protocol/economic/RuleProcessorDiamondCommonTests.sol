// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/util/TestCommonFoundry.sol";
import "test/util/RuleCreation.sol";
import "test/client/token/ERC721/util/ERC721Util.sol";

abstract contract RuleProcessorDiamondCommonTests is Test, TestCommonFoundry, ERC721Util {
    /// Test Diamond upgrade
    function testProtocol_RuleProcessorDiamond_UpgradeRuleProcessor() public endWithStopPrank() ifDeplomentTestsEnabled() {
        // must be the owner for upgrade
        switchToSuperAdmin();
        SampleFacet _sampleFacet = new SampleFacet();
        //build cut struct
        FacetCut[] memory cut = new FacetCut[](1);
        cut[0] = (FacetCut({facetAddress: address(_sampleFacet), action: FacetCutAction.Add, functionSelectors: generateSelectors("SampleFacet")}));
        //upgrade diamond
        IDiamondCut(address(ruleProcessor)).diamondCut(cut, address(0x0), "");
        console.log("ERC173Facet owner: ");
        console.log(ERC173Facet(address(ruleProcessor)).owner());

        // call a function
        assertEq("good", SampleFacet(address(ruleProcessor)).sampleFunction());

        /// test transfer ownership
        address newOwner = address(0xB00B);
        ERC173Facet(address(ruleProcessor)).transferOwnership(newOwner);
        address retrievedOwner = ERC173Facet(address(ruleProcessor)).owner();
        assertEq(retrievedOwner, newOwner);

        /// test that an onlyOwner function will fail when called by not the owner
        vm.expectRevert("UNAUTHORIZED");
        SampleFacet(address(ruleProcessor)).sampleFunction();

        SampleUpgradeFacet testFacet = new SampleUpgradeFacet();
        //build new cut struct
        console.log("before generate selectors");
        cut[0] = (FacetCut({facetAddress: address(testFacet), action: FacetCutAction.Add, functionSelectors: generateSelectors("SampleUpgradeFacet")}));
        console.log("after generate selectors");

        // test that account that isn't the owner cannot upgrade
        switchToSuperAdmin();
        //upgrade diamond
        vm.expectRevert("UNAUTHORIZED");
        IDiamondCut(address(ruleProcessor)).diamondCut(cut, address(0x0), "");

        //test that the newOwner can upgrade
        vm.stopPrank();
        vm.startPrank(newOwner);
        IDiamondCut(address(ruleProcessor)).diamondCut(cut, address(0x0), "");
        retrievedOwner = ERC173Facet(address(ruleProcessor)).owner();
        assertEq(retrievedOwner, newOwner);

        // call a function
        assertEq("good", SampleFacet(address(ruleProcessor)).sampleFunction());
    }

    /// Test Add Min TransactionSize Rule 
    function testProtocol_RuleProcessorDiamond_AddMinTransactionSizeRule() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint32 index = RuleDataFacet(address(ruleProcessor)).addTokenMinTxSize(address(applicationAppManager), 1000);
        assertEq(ERC20RuleProcessorFacet(address(ruleProcessor)).getTokenMinTxSize(index).minSize, 1000);
    }

    /// Test Diamond Versioning 
    function testProtocol_RuleProcessorDiamond_RuleProcessorVersion() public endWithStopPrank() ifDeplomentTestsEnabled() {
        vm.stopPrank();
        vm.startPrank(superAdmin);
        switchToSuperAdmin();
        // update version
        VersionFacet(address(ruleProcessor)).updateVersion("1,0,0"); // commas are used here to avoid upgrade_version-script replacements
        string memory version = VersionFacet(address(ruleProcessor)).version();
        console.log(version);
        assertEq(version, "1,0,0");
        // update version again
        VersionFacet(address(ruleProcessor)).updateVersion("1.1.0"); // upgrade_version script will replace this version
        version = VersionFacet(address(ruleProcessor)).version();
        console.log(version);
        assertEq(version, "1.1.0");
        // test that no other than the owner can update the version
        vm.stopPrank();
        if (vm.envAddress("DEPLOYMENT_OWNER") != address(0x0)) {
            vm.startPrank(user1);
        } else {
            switchToAppAdministrator();
        }
        vm.expectRevert("UNAUTHORIZED");
        VersionFacet(address(ruleProcessor)).updateVersion("6,6,6"); // this is done to avoid upgrade_version-script replace this version
        version = VersionFacet(address(ruleProcessor)).version();
        console.log(version);
        // make sure that the version didn't change
        assertEq(version, "1.1.0");
    }

    /*********************** AccountMaxBuySize *******************/
    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_AccountMaxBuySizeSettingStorage() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        vm.warp(Blocktime);
        bytes32[] memory accs = createBytes32Array("Oscar","Tayler","Shane");   
        uint256[] memory pAmounts = createUint256Array(1000, 2000, 3000);
        uint16[] memory pPeriods = createUint16Array(100, 101, 102);
        uint64 sTime = 16;
        vm.stopPrank();
        vm.startPrank(ruleAdmin);
        // uint32 _index = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxBuySize(address(applicationAppManager), accs, pAmounts, pPeriods, sTime);
        // assertEq(_index, 0);
        /// Uncomment lines after merge into internal

        // TaggedRules.AccountMaxBuySize memory rule = ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).getAccountMaxBuySize(_index, "Oscar");
        // assertEq(rule.maxSize, 1000);
        // assertEq(rule.period, 100);

        // accs[1] = bytes32("Tayler");
        // pAmounts[1] = uint192(20000000);
        // pPeriods[1] = uint16(2);
        // sTime[1] = uint8(23);

        // _index = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxBuySize(address(applicationAppManager), accs, pAmounts, pPeriods, sTime);
        // assertEq(_index, 1);
        // rule = TaggedRuleDataFacet(address(ruleProcessor)).getAccountMaxBuySize(_index, "Tayler");
        // assertEq(rule.maxSize, 20000000);
        // assertEq(rule.period, 2);

        /// test zero address check
        vm.expectRevert();
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxBuySize(address(0), accs, pAmounts, pPeriods, sTime);
    }

    /// Test only ruleAdministrators can add AccountMaxBuySize Rule
    function testProtocol_RuleProcessorDiamond_AccountMaxBuySizeSettingRuleWithoutAppAdministratorAccount() public endWithStopPrank() ifDeplomentTestsEnabled() {
        vm.warp(Blocktime);
        switchToRuleAdmin();
        bytes32[] memory accs = createBytes32Array("Oscar","Tayler","Shane");   
        uint256[] memory pAmounts = createUint256Array(1000, 2000, 3000);
        uint16[] memory pPeriods = createUint16Array(100, 101, 102);
        uint64 sTime = 16;
        // set user to the super admin
        vm.stopPrank();
        
        if (vm.envAddress("DEPLOYMENT_OWNER") != address(0x0)) {
            vm.startPrank(user1);
        } else {
            switchToSuperAdmin();
        }
        vm.expectRevert(0xd66c3008);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxBuySize(address(applicationAppManager), accs, pAmounts, pPeriods, sTime);
        vm.stopPrank(); //stop interacting as the super admin
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxBuySize(address(applicationAppManager), accs, pAmounts, pPeriods, sTime);
        switchToRuleAdmin(); //interact as the rule admin
        uint32 _index = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxBuySize(address(applicationAppManager), accs, pAmounts, pPeriods, sTime);
        assertEq(_index, 0);
    }

    /// Test mismatched arrays sizes
    function testProtocol_RuleProcessorDiamond_AccountMaxBuySizeSettingWithArraySizeMismatch() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        vm.warp(Blocktime);
        bytes32[] memory accs = createBytes32Array("Oscar","Tayler","Shane");   
        uint256[] memory pAmounts = createUint256Array(1000, 2000, 3000);
        uint16[] memory pPeriods = createUint16Array(100, 101);
        uint64 sTime = 16;
        vm.expectRevert(0x028a6c58);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxBuySize(address(applicationAppManager), accs, pAmounts, pPeriods, sTime);
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_AccountMaxBuySizeTotalRules() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        vm.warp(Blocktime);
        uint256[101] memory _indexes;
        bytes32[] memory accs = createBytes32Array("Oscar");   
        uint256[] memory pAmounts = createUint256Array(1000);
        uint16[] memory pPeriods = createUint16Array(100);
        uint64 sTime = 12;
        for (uint8 i = 0; i < _indexes.length; i++) {
            _indexes[i] = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxBuySize(address(applicationAppManager), accs, pAmounts, pPeriods, sTime);
        }
        /// TODO Uncomment line after merge to internal
        /// assertEq(TaggedRuleDataFacet(address(ruleProcessor)).getTotalAccountMaxBuySize(), _indexes.length);
    }

    /************************ AccountMaxSellSize *************************/
    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_AccountMaxSellSizeSetting() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        vm.warp(Blocktime);
        bytes32[] memory accs = createBytes32Array("Oscar","Tayler","Shane");   
        uint192[] memory sAmounts = createUint192Array(1000, 2000, 3000);
        uint16[] memory sPeriod = createUint16Array(24, 36, 48);
        uint64 sTime = Blocktime;
        uint32 _index = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxSellSize(address(applicationAppManager), accs, sAmounts, sPeriod, sTime);
        assertEq(_index, 0);

        ///Uncomment lines after merge to internal
        // TaggedRules.AccountMaxSellSize memory rule = TaggedRuleDataFacet(address(ruleProcessor)).getAccountMaxSellSizeByIndex(_index, "Oscar");
        // assertEq(rule.maxSize, 1000);
        // assertEq(rule.period, 24);
        // bytes32[] memory accs = createBytes32Array("Oscar","Tayler","Shane");   
        // uint192[] memory pAmounts = createUint192Array(100000000, 20000000, 3000000);
        // uint16[] memory pPeriods = createUint16Array(11, 22, 33);
        // _index = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxSellSize(address(applicationAppManager), accs, sAmounts, sPeriod, sTime);
        // assertEq(_index, 1);
        // rule = TaggedRuleDataFacet(address(ruleProcessor)).getAccountMaxSellSizeByIndex(_index, "Tayler");
        // assertEq(rule.maxSize, 20000000);
        // assertEq(rule.period, 22);
        vm.expectRevert();
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxSellSize(address(0), accs, sAmounts, sPeriod, sTime);
    }

    /// Test only ruleAdministrators can add AccountMaxSellSize Rule
    function testProtocol_RuleProcessorDiamond_AccountMaxSellSizeSettingWithoutAppAdministratorAccount() public endWithStopPrank() ifDeplomentTestsEnabled() {
        vm.warp(Blocktime);
        switchToRuleAdmin();
        bytes32[] memory accs = createBytes32Array("Oscar","Tayler","Shane");   
        uint192[] memory sAmounts = createUint192Array(1000, 2000, 3000);
        uint16[] memory sPeriod = createUint16Array(24, 36, 48);
        uint64 sTime = Blocktime;
        vm.stopPrank(); //stop interacting as the super admin
        vm.startPrank(address(0xDEAD)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxSellSize(address(applicationAppManager), accs, sAmounts, sPeriod, sTime);
        vm.stopPrank(); //stop interacting as the super admin
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxSellSize(address(applicationAppManager), accs, sAmounts, sPeriod, sTime);
        switchToRuleAdmin();
        uint32 _index = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxSellSize(address(applicationAppManager), accs, sAmounts, sPeriod, sTime);
        assertEq(_index, 0);
    }

    /// Test mismatched arrays sizes
    function testProtocol_RuleProcessorDiamond_AccountMaxSellSizeSettingWithArraySizeMismatch() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        vm.warp(Blocktime);
        bytes32[] memory accs = createBytes32Array("Oscar","Tayler");   
        uint192[] memory sAmounts = createUint192Array(1000, 2000, 3000);
        uint16[] memory sPeriod = createUint16Array(24, 36, 48);
        uint64 sTime = Blocktime;
        vm.expectRevert(0x028a6c58);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxSellSize(address(applicationAppManager), accs, sAmounts, sPeriod, sTime);
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_AccountMaxSellSizeTotalRules() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        vm.warp(Blocktime);
        uint256[101] memory _indexes;
        bytes32[] memory accs = createBytes32Array("Oscar");
        uint192[] memory sAmounts = createUint192Array(1000);
        uint16[] memory sPeriod = createUint16Array(24);
        uint64 sTime = Blocktime;
        for (uint8 i = 0; i < _indexes.length; i++) {
            _indexes[i] = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMaxSellSize(address(applicationAppManager), accs, sAmounts, sPeriod, sTime);
        }
        ///TODO Uncomment lines when merged into internal 
        // assertEq(TaggedRuleDataFacet(address(ruleProcessor)).getTotalAccountMaxSellSize(), _indexes.length);
    }

    /************************ PurchaseFeeByVolumeRule **********************/
    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_PurchaseFeeByVolumeRuleSetting() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addPurchaseFeeByVolumeRule(address(applicationAppManager), 5000000000000000000000000000000000, 100);
        assertEq(_index, 0);
        NonTaggedRules.TokenPurchaseFeeByVolume memory rule = RuleDataFacet(address(ruleProcessor)).getPurchaseFeeByVolumeRule(_index);
        assertEq(rule.rateIncreased, 100);

        _index = RuleDataFacet(address(ruleProcessor)).addPurchaseFeeByVolumeRule(address(applicationAppManager), 10000000000000000000000000000000000, 200);
        assertEq(_index, 1);
        ///TODO Uncomment lines when merged into internal 
        // rule = RuleDataFacet(address(ruleProcessor)).getPurchaseFeeByVolumeRule(_index);
        // assertEq(rule.volume, 10000000000000000000000000000000000);
        // assertEq(rule.rateIncreased, 200);
    }

    /// Test only ruleAdministrators can add PurchaseFeeByVolumeRule
    function testProtocol_RuleProcessorDiamond_PurchaseFeeByVolumeRuleSettingRuleWithoutAppAdministratorAccount() public endWithStopPrank() ifDeplomentTestsEnabled() {
        vm.startPrank(address(0xDEAD)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addPurchaseFeeByVolumeRule(address(applicationAppManager), 5000000000000000000000000000000000, 100);
        vm.stopPrank(); //stop interacting as the super admin
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addPurchaseFeeByVolumeRule(address(applicationAppManager), 5000000000000000000000000000000000, 100);
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addPurchaseFeeByVolumeRule(address(applicationAppManager), 5000000000000000000000000000000000, 100);
        assertEq(_index, 0);

        _index = RuleDataFacet(address(ruleProcessor)).addPurchaseFeeByVolumeRule(address(applicationAppManager), 5000000000000000000000000000000000, 100);
        assertEq(_index, 1);
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_TotalRulesOnPurchaseFeeByVolume() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint256[101] memory _indexes;
        for (uint8 i = 0; i < 101; i++) {
            _indexes[i] = RuleDataFacet(address(ruleProcessor)).addPurchaseFeeByVolumeRule(address(applicationAppManager), 500 + i, 1 + i);
        }
        assertEq(RuleDataFacet(address(ruleProcessor)).getTotalTokenPurchaseFeeByVolumeRules(), _indexes.length);
    }

    /*********************** TokenMaxPriceVolatility ************************/
    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_TokenMaxPriceVolatilitySetting() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addTokenMaxPriceVolatility(address(applicationAppManager), 5000, 60, 12, totalSupply);
        assertEq(_index, 0);
        NonTaggedRules.TokenMaxPriceVolatility memory rule = RuleDataFacet(address(ruleProcessor)).getTokenMaxPriceVolatility(_index);
        assertEq(rule.hoursFrozen, 12);

        _index = RuleDataFacet(address(ruleProcessor)).addTokenMaxPriceVolatility(address(applicationAppManager), 666, 100, 16, totalSupply);
        assertEq(_index, 1);
        rule = RuleDataFacet(address(ruleProcessor)).getTokenMaxPriceVolatility(_index);
        assertEq(rule.hoursFrozen, 16);
        assertEq(rule.max, 666);
        assertEq(rule.period, 100);
        vm.expectRevert();
        RuleDataFacet(address(ruleProcessor)).addTokenMaxPriceVolatility(address(0), 666, 100, 16, totalSupply);
    }

    /// Test only ruleAdministrators can add TokenMaxPriceVolatility Rule
    function testProtocol_RuleProcessorDiamond_TokenMaxPriceVolatilitySettingWithoutAppAdministratorAccount() public endWithStopPrank() ifDeplomentTestsEnabled() {
        vm.startPrank(address(0xDEAD)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addTokenMaxPriceVolatility(address(applicationAppManager), 5000, 60, 24, totalSupply);
        vm.stopPrank(); //stop interacting as the super admin
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addTokenMaxPriceVolatility(address(applicationAppManager), 5000, 60, 24, totalSupply);
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addTokenMaxPriceVolatility(address(applicationAppManager), 5000, 60, 24, totalSupply);
        assertEq(_index, 0);

        _index = RuleDataFacet(address(ruleProcessor)).addTokenMaxPriceVolatility(address(applicationAppManager), 5000, 60, 24, totalSupply);
        assertEq(_index, 1);
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_TokenMaxPriceVolatilityTotalRules() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint256[101] memory _indexes;
        for (uint8 i = 0; i < 101; i++) {
            _indexes[i] = RuleDataFacet(address(ruleProcessor)).addTokenMaxPriceVolatility(address(applicationAppManager), 5000 + i, 60 + i, 24 + i, totalSupply);
        }
        assertEq(RuleDataFacet(address(ruleProcessor)).getTotalTokenMaxPriceVolatility(), _indexes.length);
    }

    /*********************** MaxTradingVolume Rule ************************/
    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_TokenMaxTradingVolumeRuleSetting() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addTokenMaxTradingVolume(address(applicationAppManager), 1000, 2, Blocktime, 0);
        assertEq(_index, 0);
        NonTaggedRules.TokenMaxTradingVolume memory rule = ERC20RuleProcessorFacet(address(ruleProcessor)).getTokenMaxTradingVolume(_index);
        assertEq(rule.startTime, Blocktime);

        _index = RuleDataFacet(address(ruleProcessor)).addTokenMaxTradingVolume(address(applicationAppManager), 2000, 1, 12, 1_000_000_000_000_000 * 10 ** 18);
        assertEq(_index, 1);
        rule = ERC20RuleProcessorFacet(address(ruleProcessor)).getTokenMaxTradingVolume(_index);
        assertEq(rule.max, 2000);
        assertEq(rule.period, 1);
        assertEq(rule.startTime, 12);
        assertEq(rule.totalSupply, 1_000_000_000_000_000 * 10 ** 18);
        vm.expectRevert();
        RuleDataFacet(address(ruleProcessor)).addTokenMaxTradingVolume(address(0), 2000, 1, 12, 1_000_000_000_000_000 * 10 ** 18);
    }

    /// Test only ruleAdministrators can add Max Trading Volume Rule 
    function testProtocol_RuleProcessorDiamond_TokenMaxTradingVolumeRuleSettingWithoutappAdministratorAccount() public endWithStopPrank() ifDeplomentTestsEnabled() {
        vm.startPrank(address(0xDEAD)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addTokenMaxTradingVolume(address(applicationAppManager), 4000, 2, 23, 0);
        vm.stopPrank(); //stop interacting as the super admin
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addTokenMaxTradingVolume(address(applicationAppManager), 4000, 2, 23, 0);
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addTokenMaxTradingVolume(address(applicationAppManager), 4000, 2, 23, 0);
        assertEq(_index, 0);

        _index = RuleDataFacet(address(ruleProcessor)).addTokenMaxTradingVolume(address(applicationAppManager), 4000, 2, 23, 0);
        assertEq(_index, 1);
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_TokenMaxTradingVolumeRuleTotalRules() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint256[101] memory _indexes;
        for (uint8 i = 0; i < 101; i++) {
            _indexes[i] = RuleDataFacet(address(ruleProcessor)).addTokenMaxTradingVolume(address(applicationAppManager), 5000 + i, 60 + i, Blocktime, 0);
        }
        assertEq(ERC20RuleProcessorFacet(address(ruleProcessor)).getTotalTokenMaxTradingVolume(), _indexes.length);
    }

    /*********************** TokenMinTransactionSize ************************/
    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_TokenMinTransactionSizeSetting() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addTokenMinTxSize(address(applicationAppManager), 500000000000000);
        assertEq(_index, 0);
        NonTaggedRules.TokenMinTxSize memory rule = ERC20RuleProcessorFacet(address(ruleProcessor)).getTokenMinTxSize(_index);
        assertEq(rule.minSize, 500000000000000);

        _index = RuleDataFacet(address(ruleProcessor)).addTokenMinTxSize(address(applicationAppManager), 300000000000000);
        assertEq(_index, 1);
        rule = ERC20RuleProcessorFacet(address(ruleProcessor)).getTokenMinTxSize(_index);
        assertEq(rule.minSize, 300000000000000);
    }

    /// Test only ruleAdministrators can add TokenMinTransactionSize Rule
    function testProtocol_RuleProcessorDiamond_TokenMinTransactionSizeSettingRuleWithoutAppAdministratorAccount() public endWithStopPrank() ifDeplomentTestsEnabled() {
        vm.startPrank(address(0xDEAD)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addTokenMinTxSize(address(applicationAppManager), 500000000000000);
        vm.stopPrank(); //stop interacting as the super admin
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addTokenMinTxSize(address(applicationAppManager), 500000000000000);
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addTokenMinTxSize(address(applicationAppManager), 500000000000000);
        assertEq(_index, 0);
        _index = RuleDataFacet(address(ruleProcessor)).addTokenMinTxSize(address(applicationAppManager), 500000000000000);
        assertEq(_index, 1);
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_TokenMinTransactionSizeTotalRules() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint256[101] memory _indexes;
        for (uint8 i = 0; i < 101; i++) {
            _indexes[i] = RuleDataFacet(address(ruleProcessor)).addTokenMinTxSize(address(applicationAppManager), 5000 + i);
        }
        assertEq(ERC20RuleProcessorFacet(address(ruleProcessor)).getTotalTokenMinTxSize(), _indexes.length);
    }

    /*********************** AccountMinMaxTokenBalance *******************/
    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceSetting() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        bytes32[] memory accs = createBytes32Array("Oscar","Tayler","Shane");
        uint256[] memory min = createUint256Array(1000, 2000, 3000);
        uint256[] memory max = createUint256Array(
            10000000000000000000000000000000000000, 
            100000000000000000000000000000000000000000, 
            100000000000000000000000000000000000000000000000000000000000000000000000000
            );
        uint16[] memory empty;
        uint32 _index = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        assertEq(_index, 0);
        TaggedRules.AccountMinMaxTokenBalance memory rule = ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).getAccountMinMaxTokenBalance(_index, "Oscar");
        assertEq(rule.min, 1000);
        assertEq(rule.max, 10000000000000000000000000000000000000);

        bytes32[] memory accs2 = createBytes32Array("Oscar","Tayler","Shane");
        uint256[] memory min2 = createUint256Array(100000000, 20000000, 3000000);
        uint256[] memory max2 = createUint256Array(
            100000000000000000000000000000000000000000000000000000000000000000000000000, 
            20000000000000000000000000000000000000, 
            900000000000000000000000000000000000000000000000000000000000000000000000000
            );
        uint16[] memory empty2;
        _index = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs2, min2, max2, empty2, uint64(Blocktime));
        assertEq(_index, 1);
        rule = ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).getAccountMinMaxTokenBalance(_index, "Tayler");
        assertEq(rule.min, 20000000);
        assertEq(rule.max, 20000000000000000000000000000000000000);
        vm.expectRevert();
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(0), accs, min, max, empty, uint64(Blocktime));
    }

    /// Test only ruleAdministrators can add Min Max Token Balance Rule
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceSettingWithoutAppAdministratorAccount() public endWithStopPrank() ifDeplomentTestsEnabled() {
        bytes32[] memory accs = createBytes32Array("Oscar","Tayler","Shane");
        uint256[] memory min = createUint256Array(1000, 2000, 3000);
        uint256[] memory max = createUint256Array(
            10000000000000000000000000000000000000, 
            100000000000000000000000000000000000000000, 
            100000000000000000000000000000000000000000000000000000000000000000000000000
            );
        uint16[] memory empty;
        vm.stopPrank(); //stop interacting as the super admin
        vm.startPrank(address(0xDEAD)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        vm.stopPrank(); //stop interacting as the super admin
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        switchToRuleAdmin();
        uint32 _index = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        assertEq(_index, 0);
        _index = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        assertEq(_index, 1);
    }

    /// Test mismatched arrays sizes
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceSettingWithArraySizeMismatch() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        bytes32[] memory accs = createBytes32Array("Oscar","Tayler","Shane");
        uint256[] memory min = createUint256Array(1000, 2000);
        uint256[] memory max = createUint256Array(
            10000000000000000000000000000000000000, 
            100000000000000000000000000000000000000000, 
            100000000000000000000000000000000000000000000000000000000000000000000000000
            );
        uint16[] memory empty;
        vm.expectRevert(0x028a6c58);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
    }

    /// Test inverted limits
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceAddWithInvertedLimits() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        bytes32[] memory accs = createBytes32Array("Oscar");
        uint256[] memory min = createUint256Array(999999000000000000000000000000000000000000000000000000000000000000000000000);
        uint256[] memory max = createUint256Array(100);
        uint16[] memory empty;
        vm.expectRevert(0xeeb9d4f7);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
    }

    /// Test mixing Periodic and Non-Periodic cases
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceAddMixedPeriodicAndNonPeriodic() public endWithStopPrank() ifDeplomentTestsEnabled() {
        // set user to the rule admin
        vm.startPrank(ruleAdmin);
        bytes32[] memory accs = createBytes32Array("Oscar", "Shane");
        uint256[] memory min = createUint256Array(10, 20);
        uint256[] memory max = createUint256Array(
            999999000000000000000000000000000000000000000000000000000000000000000000000, 
            999999000000000000000000000000000000000000000000000000000000000000000000000
            );
        uint16[] memory periods = createUint16Array(10, 0);
        vm.expectRevert(0xb75194a4);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, periods, uint64(Blocktime));
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceTotalRules() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint256[101] memory _indexes;
        bytes32[] memory accs = createBytes32Array("Oscar");
        uint256[] memory max = createUint256Array(999999000000000000000000000000000000000000000000000000000000000000000000000);
        uint256[] memory min = createUint256Array(100);
        uint16[] memory empty;
        for (uint8 i = 0; i < _indexes.length; i++) {
            _indexes[i] = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        }
        assertEq(ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).getTotalAccountMinMaxTokenBalances(), _indexes.length);
    }

    /// With Hold Periods

    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceSettingWithPeriod() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        vm.warp(Blocktime);
        bytes32[] memory accs = createBytes32Array("Oscar","Tayler","Shane");
        uint256[] memory minAmounts = createUint256Array(1000, 2000, 3000);
        uint256[] memory maxAmounts = createUint256Array(
            999999000000000000000000000000000000000000000000000000000000000000000000000,
            999990000000000000000000000000000000000000000000000000000000000000000000000,
            999990000000000000000000000000000000000000000000000000000000000000000000000
        );
        uint16[] memory periods = createUint16Array(100, 101, 102);
        uint32 _index = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, minAmounts, maxAmounts, periods, uint64(Blocktime));
        assertEq(_index, 0);
        TaggedRules.AccountMinMaxTokenBalance memory rule = ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).getAccountMinMaxTokenBalance(_index, "Oscar");
        assertEq(rule.min, 1000);
        assertEq(rule.period, 100);
        bytes32[] memory accs2 = createBytes32Array("Oscar","Tayler","Shane");
        uint256[] memory minAmounts2 = createUint256Array(1000, 20000000, 3000);
        uint256[] memory maxAmounts2 = createUint256Array(
            999999000000000000000000000000000000000000000000000000000000000000000000000,
            999990000000000000000000000000000000000000000000000000000000000000000000000,
            999990000000000000000000000000000000000000000000000000000000000000000000000
        );
        uint16[] memory periods2 = createUint16Array(100, 2, 102);

        _index = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs2, minAmounts2, maxAmounts2, periods2, uint64(Blocktime));
        assertEq(_index, 1);
        rule = ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).getAccountMinMaxTokenBalance(_index, "Tayler");
        assertEq(rule.min, 20000000);
        assertEq(rule.period, 2);
    }

    /// Test Account Min Max Token Balance while not admin 
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceSettingNotAdmin() public endWithStopPrank() ifDeplomentTestsEnabled() {
        vm.warp(Blocktime);
        vm.startPrank(address(0xDEAD));
        bytes32[] memory accs = createBytes32Array("Oscar","Tayler","Shane");
        uint256[] memory minAmounts = createUint256Array(1000, 2000, 3000);
        uint256[] memory maxAmounts = createUint256Array(
            999999000000000000000000000000000000000000000000000000000000000000000000000,
            999990000000000000000000000000000000000000000000000000000000000000000000000,
            999990000000000000000000000000000000000000000000000000000000000000000000000
        );
        uint16[] memory periods = createUint16Array(100, 101, 102);
        vm.expectRevert(0xd66c3008);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, minAmounts, maxAmounts, periods, uint64(Blocktime));
    }

    /// Test for proper array size mismatch error
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceSettingSizeMismatch() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        vm.warp(Blocktime);
        bytes32[] memory accs = createBytes32Array("Oscar","Tayler","Shane");
        uint256[] memory minAmounts = createUint256Array(1000, 2000, 3000);
        uint256[] memory maxAmounts = createUint256Array(
            999999000000000000000000000000000000000000000000000000000000000000000000000,
            999990000000000000000000000000000000000000000000000000000000000000000000000,
            999990000000000000000000000000000000000000000000000000000000000000000000000
        );
        uint16[] memory periods = createUint16Array(100, 101);
        vm.expectRevert();
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, minAmounts, maxAmounts, periods, uint64(Blocktime));
    }

    /*********************** TokenMaxSupplyVolatility ************************/
    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_TokenMaxSupplyVolatilitySetting() public endWithStopPrank() ifDeplomentTestsEnabled() {
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
    function testProtocol_RuleProcessorDiamond_TokenMaxSupplyVolatilitySettingRuleWithoutAppAdministratorAccount() public endWithStopPrank() ifDeplomentTestsEnabled() {
        vm.startPrank(address(0xDEAD)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addTokenMaxSupplyVolatility(address(applicationAppManager), 6500, 24, Blocktime, totalSupply);
        vm.stopPrank(); //stop interacting as the super admin
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addTokenMaxSupplyVolatility(address(applicationAppManager), 6500, 24, Blocktime, totalSupply);
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addTokenMaxSupplyVolatility(address(applicationAppManager), 6500, 24, Blocktime, totalSupply);
        assertEq(_index, 0);
        _index = RuleDataFacet(address(ruleProcessor)).addTokenMaxSupplyVolatility(address(applicationAppManager), 6500, 24, Blocktime, totalSupply);
        assertEq(_index, 1);
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_TokenMaxSupplyVolatilityTotalRules() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint256[101] memory _indexes;
        for (uint8 i = 0; i < 101; i++) {
            _indexes[i] = RuleDataFacet(address(ruleProcessor)).addTokenMaxSupplyVolatility(address(applicationAppManager), 6500 + i, 24 + i, 12, totalSupply);
        }
        assertEq(ERC20RuleProcessorFacet(address(ruleProcessor)).getTotalTokenMaxSupplyVolatility(), _indexes.length);
    }

    /*********************** AccountApproveDenyOracle ************************/
    /// Simple setting and getting
    function testProtocol_RuleProcessorDiamond_AccountApproveDenyOracle() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 0, address(69));
        assertEq(_index, 0);
        NonTaggedRules.AccountApproveDenyOracle memory rule = ERC20RuleProcessorFacet(address(ruleProcessor)).getAccountApproveDenyOracle(_index);
        assertEq(rule.oracleType, 0);
        assertEq(rule.oracleAddress, address(69));
        _index = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 1, address(79));
        assertEq(_index, 1);
        rule = ERC20RuleProcessorFacet(address(ruleProcessor)).getAccountApproveDenyOracle(_index);
        assertEq(rule.oracleType, 1);
    }

    /// Test only ruleAdministrators can add AccountApproveDenyOracle Rule
    function testProtocol_RuleProcessorDiamond_AccountApproveDenyOracleSettingWithoutAppAdministratorAccount() public endWithStopPrank() ifDeplomentTestsEnabled() {
        vm.startPrank(address(0xDEAD)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 0, address(69));
        vm.stopPrank(); //stop interacting as the super admin
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 0, address(69));
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 0, address(69));
        assertEq(_index, 0);

        _index = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 1, address(79));
        assertEq(_index, 1);
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_AccountApproveDenyOracleTotalRules() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint256[101] memory _indexes;
        for (uint8 i = 0; i < 101; i++) {
            _indexes[i] = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 0, address(69));
        }
        assertEq(ERC20RuleProcessorFacet(address(ruleProcessor)).getTotalAccountApproveDenyOracle(), _indexes.length);
    }

    /*********************** TokenMaxDailyTrades ************************/
    function testProtocol_RuleProcessorDiamond_TokenMaxDailyTrades() public endWithStopPrank() ifDeplomentTestsEnabled() {
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
    function testProtocol_RuleProcessorDiamond_TokenMaxDailyTradesSettingRuleWithoutAppAdministratorAccount() public endWithStopPrank() ifDeplomentTestsEnabled() {
        bytes32[] memory nftTags = createBytes32Array("BoredGrape", "DiscoPunk"); 
        uint8[] memory tradesAllowed = createUint8Array(1, 5);
        vm.startPrank(address(0xDEAD)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        TaggedRuleDataFacet(address(ruleProcessor)).addTokenMaxDailyTrades(address(applicationAppManager), nftTags, tradesAllowed, Blocktime);
        vm.stopPrank(); //stop interacting as the super admin
        vm.startPrank(address(0xC0FFEE)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        TaggedRuleDataFacet(address(ruleProcessor)).addTokenMaxDailyTrades(address(applicationAppManager), nftTags, tradesAllowed, Blocktime);
        switchToRuleAdmin();
        uint32 _index = TaggedRuleDataFacet(address(ruleProcessor)).addTokenMaxDailyTrades(address(applicationAppManager), nftTags, tradesAllowed, Blocktime);
        assertEq(_index, 0);
        _index = TaggedRuleDataFacet(address(ruleProcessor)).addTokenMaxDailyTrades(address(applicationAppManager), nftTags, tradesAllowed, Blocktime);
        assertEq(_index, 1);
    }

    /// Test Token Max Daily Trades Rule with Blank Tags
    function testProtocol_RuleProcessorDiamond_TokenMaxDailyTradesRulesBlankTag_Positive() public endWithStopPrank() ifDeplomentTestsEnabled() {
        // set user to the rule admin
        vm.startPrank(ruleAdmin);
        bytes32[] memory nftTags = createBytes32Array(""); 
        uint8[] memory tradesAllowed = createUint8Array(1);
        uint32 _index = TaggedRuleDataFacet(address(ruleProcessor)).addTokenMaxDailyTrades(address(applicationAppManager), nftTags, tradesAllowed, Blocktime);
        assertEq(_index, 0);
        TaggedRules.TokenMaxDailyTrades memory rule = ERC721TaggedRuleProcessorFacet(address(ruleProcessor)).getTokenMaxDailyTrades(_index, nftTags[0]);
        assertEq(rule.tradesAllowedPerDay, 1);
    }

    /// Test Token Max Daily Trades Rule with negative case
    function testProtocol_RuleProcessorDiamond_TokenMaxDailyTradesRulesBlankTag_Negative() public endWithStopPrank() ifDeplomentTestsEnabled() {
        // set user to the rule admin
        vm.startPrank(ruleAdmin);
        bytes32[] memory nftTags = createBytes32Array("","BoredGrape"); 
        uint8[] memory tradesAllowed = createUint8Array(1,5);
        vm.expectRevert(0x6bb35a99);
        TaggedRuleDataFacet(address(ruleProcessor)).addTokenMaxDailyTrades(address(applicationAppManager), nftTags, tradesAllowed, Blocktime);
    }

    /// Test total rules
    function testProtocol_RuleProcessorDiamond_TokenMaxDailyTradesTotalRules() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        bytes32[] memory nftTags = createBytes32Array("BoredGrape", "DiscoPunk"); 
        uint8[] memory tradesAllowed = createUint8Array(1, 5);
        uint256[101] memory _indexes;
        for (uint8 i = 0; i < 101; i++) {
            _indexes[i] = TaggedRuleDataFacet(address(ruleProcessor)).addTokenMaxDailyTrades(address(applicationAppManager), nftTags, tradesAllowed, Blocktime);
        }
    }

    /**************** Account Max Value by Access Level Rule  ****************/

    /// Test Adding AccountMaxValueByAccessLevel
    function testProtocol_RuleProcessorDiamond_AccountMaxValueByAccessLevelRuleAdd() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint48[] memory balanceAmounts = createUint48Array(10, 100, 500, 1000, 1000);
        uint32 _index = AppRuleDataFacet(address(ruleProcessor)).addAccountMaxValueByAccessLevel(address(applicationAppManager), balanceAmounts);
        /// account for already deployed contract that has AccessLevelBalanceRule added
        uint256 testBalance = ApplicationAccessLevelProcessorFacet(address(ruleProcessor)).getAccountMaxValueByAccessLevel(_index, 2);
        assertEq(testBalance, 500);
    }

    /// Test Adding AccountMaxValueByAccessLevel while not admin 
    function testProtocol_RuleProcessorDiamond_AccountMaxValueByAccessLevelAddNotAdmin() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint48[] memory balanceAmounts;
        vm.stopPrank(); //stop interacting as the super admin
        vm.startPrank(address(0xDEAD)); //interact as a different user
        vm.expectRevert(0xd66c3008);
        AppRuleDataFacet(address(ruleProcessor)).addAccountMaxValueByAccessLevel(address(applicationAppManager), balanceAmounts);
    }

    /// Test AccountMaxValueByAccessLevel total Rules
    function testProtocol_RuleProcessorDiamond_AccountMaxValueByAccessLevelTotalRules() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint256[101] memory _indexes;
        uint48[] memory balanceAmounts = createUint48Array(10, 100, 500, 1000, 1000);
        for (uint8 i = 0; i < _indexes.length; i++) {
            _indexes[i] = AppRuleDataFacet(address(ruleProcessor)).addAccountMaxValueByAccessLevel(address(applicationAppManager), balanceAmounts);
        }

        uint256 result = ApplicationAccessLevelProcessorFacet(address(ruleProcessor)).getTotalAccountMaxValueByAccessLevel();
        assertEq(result, _indexes.length);
    }

    /**************** AdminMinTokenBalance Rule Testing  ****************/

    /// Test Adding AdminMinTokenBalance Rule endTime: block.timestamp + 10000
    function testProtocol_RuleProcessorDiamond_AddAdminMinTokenBalanceStorage_Positive() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToSuperAdmin();
        applicationAppManager.addAppAdministrator(address(22));
        switchToRuleAdmin();
        assertEq(applicationAppManager.isAppAdministrator(address(22)), true);
        uint32 _index = TaggedRuleDataFacet(address(ruleProcessor)).addAdminMinTokenBalance(address(applicationAppManager), 5000, block.timestamp + 10000);
        TaggedRules.AdminMinTokenBalance memory rule = ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).getAdminMinTokenBalance(_index);
        assertEq(rule.amount, 5000);
        assertEq(rule.endTime, block.timestamp + 10000);
    }

    /// Test Adding AdminMinTokenBalance Rule while not admin 
    function testProtocol_RuleProcessorDiamond_AdminMinTokenBalanceNotPassingNotAdmin() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToUser();
        vm.expectRevert(0xd66c3008);
        TaggedRuleDataFacet(address(ruleProcessor)).addAdminMinTokenBalance(address(applicationAppManager), 6500, 1669748600);
    }

    /// Test Get Total Admin Withdrawal Rules
    function testProtocol_RuleProcessorDiamond_AdminMinTokenBalanceTotal() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint256[101] memory _indexes;
        uint256 amount = 1000;
        uint256 endTime = block.timestamp + 10000;
        for (uint8 i = 0; i < _indexes.length; i++) {
            _indexes[i] = TaggedRuleDataFacet(address(ruleProcessor)).addAdminMinTokenBalance(address(applicationAppManager), amount, endTime);
        }
        uint256 result;
        result = ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).getTotalAdminMinTokenBalance();
        assertEq(result, _indexes.length);
    }

    /***************** RULE PROCESSING *****************/

    /// Test Token Min Transaction Size while not admin 
    function testProtocol_RuleProcessorDiamond_TokenMinTransactionSizeNotPassingByNonAdmin() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToUser();
        vm.expectRevert(0xd66c3008);
        RuleDataFacet(address(ruleProcessor)).addTokenMinTxSize(address(applicationAppManager), 1000);
    }

    /// Test Token Min Transaction Size
    function testProtocol_RuleProcessorDiamond_TokenMinTransactionSize() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint32 index = RuleDataFacet(address(ruleProcessor)).addTokenMinTxSize(address(applicationAppManager), 2222);
        switchToUser();
        ERC20RuleProcessorFacet(address(ruleProcessor)).checkTokenMinTxSize(index, 2222);
    }

    /// Test Token Min Transaction Size fail scenario
    function testProtocol_RuleProcessorDiamond_TokenMinTransactionSizeNotPassing() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        uint32 index = RuleDataFacet(address(ruleProcessor)).addTokenMinTxSize(address(applicationAppManager), 420);
        vm.expectRevert(0x7a78c901);
        ERC20RuleProcessorFacet(address(ruleProcessor)).checkTokenMinTxSize(index, 400);
    }

    /// Test Account Min Max Token Balance Rule 
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceCheck() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        bytes32[] memory accs = createBytes32Array("Oscar","Tayler","Shane");
        uint256[] memory min = createUint256Array(10, 20, 30);
        uint256[] memory max = createUint256Array(10000000000000000000000000, 10000000000000000000000000000, 1000000000000000000000000000000);
        uint16[] memory empty;
        // add rule at ruleId 0
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        vm.stopPrank();
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
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceCheck_Negative() public endWithStopPrank() ifDeplomentTestsEnabled() {
        bytes32[] memory accs = createBytes32Array("Oscar","Tayler","Shane");
        uint256[] memory min = createUint256Array(10, 20, 30);
        uint256[] memory max = createUint256Array(10000000000000000000000000, 10000000000000000000000000000, 1000000000000000000000000000000);
        uint16[] memory empty;
        // add rule at ruleId 0
        switchToRuleAdmin();
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        vm.stopPrank();
        switchToAppAdministrator();
        applicationAppManager.addTag(user1, "Oscar"); //add tag
        assertTrue(applicationAppManager.hasTag(user1, "Oscar"));
        switchToSuperAdmin();
        applicationCoin.mint(user1, 10000000000000000000000);
        uint256 amount = 10000000000000000000000;
        assertEq(applicationCoin.balanceOf(user1), 10000000000000000000000);
        bytes32[] memory tags = applicationAppManager.getAllTags(user1);
        uint256 balance = applicationCoin.balanceOf(user1);
        switchToUser();
        vm.expectRevert(0x3e237976);
        ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).checkAccountMinTokenBalance(balance, tags, amount, ruleId);
    }

    /// Test Max Tag Enforcement Through Account Min Max Token Balance Rule 
    function testProtocol_RuleProcessorDiamond_MaxTagEnforcementThroughAccountMinMaxTokenBalance() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        bytes32[] memory accs = createBytes32Array("Oscar","Tayler","Shane");
        uint256[] memory min = createUint256Array(10, 20, 30);
        uint256[] memory max = createUint256Array(10000000000000000000000000, 10000000000000000000000000000, 1000000000000000000000000000000);
        uint16[] memory empty;
        // add rule at ruleId 0
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        vm.stopPrank();
        switchToAppAdministrator();
        for (uint i = 1; i < 11; i++) {
            applicationAppManager.addTag(user1, bytes32(i)); //add tag
        }
        vm.expectRevert(0xa3afb2e2);
        applicationAppManager.addTag(user1, "xtra tag"); //add tag should fail

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
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceBlankTagCheck_Negative() public endWithStopPrank() ifDeplomentTestsEnabled() {
        applicationCoin.mint(superAdmin, totalSupply);
        vm.startPrank(ruleAdmin);
        // add rule at ruleId 0
        bytes32[] memory accs = createBytes32Array("");
        uint256[] memory min = createUint256Array(10);
        uint256[] memory max = createUint256Array(10000);
        uint16[] memory empty;

        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        switchToAppAdministrator();
        applicationAppManager.addTag(superAdmin, "Oscar"); //add tag
        assertTrue(applicationAppManager.hasTag(superAdmin, "Oscar"));
        switchToSuperAdmin();
        uint256 amount = 10000000000000000000000000;
        assertEq(applicationCoin.balanceOf(superAdmin), 100000000000);
        bytes32[] memory tags = applicationAppManager.getAllTags(superAdmin);
        uint256 balance = applicationCoin.balanceOf(superAdmin);
        vm.expectRevert(0x1da56a44);
        ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).checkAccountMaxTokenBalance(balance, tags, amount, ruleId);
    }


    /// Test Account Min Max Token Balance Rule with Blank Tags 
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceBlankTagProcessCheck() public endWithStopPrank() ifDeplomentTestsEnabled() {
        applicationCoin.mint(superAdmin, totalSupply);
        vm.startPrank(ruleAdmin);
        bytes32[] memory accs = createBytes32Array("");
        uint256[] memory min = createUint256Array(10);
        uint256[] memory max = createUint256Array(10000000000000000000000000);
        uint16[] memory empty;

        // add rule at ruleId 0
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        vm.stopPrank();
        switchToAppAdministrator();
        applicationAppManager.addTag(superAdmin, "Oscar"); //add tag
        assertTrue(applicationAppManager.hasTag(superAdmin, "Oscar"));
        vm.stopPrank();
        switchToSuperAdmin();
        uint256 amount = 1;
        assertEq(applicationCoin.balanceOf(superAdmin), totalSupply);
        bytes32[] memory tags = applicationAppManager.getAllTags(superAdmin);
        ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).checkAccountMinTokenBalance(applicationCoin.balanceOf(superAdmin), tags, amount, ruleId);
    }

    /// Test Account Min Max Token Balance Rule with Blank Tags negative case 
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceBlankTagCreationCheck_Negative() public endWithStopPrank() ifDeplomentTestsEnabled() {
        applicationCoin.mint(superAdmin, totalSupply);
        vm.startPrank(ruleAdmin);
        bytes32[] memory accs = createBytes32Array("", "Shane");
        uint256[] memory min = createUint256Array(10,100);
        uint256[] memory max = createUint256Array(10000000000000000000000000, 10000000000000000000000000);
        uint16[] memory empty;
        // Can't add a blank and specific tag together
        vm.expectRevert(0x6bb35a99);
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
    }

    /// Test Adding Account Min Max Token Balance Rule with Blank Tags 
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceBlankTagCreationCheck_Positive() public endWithStopPrank() ifDeplomentTestsEnabled() {
        applicationCoin.mint(superAdmin, totalSupply);
        vm.startPrank(ruleAdmin);
        bytes32[] memory accs = createBytes32Array("Oscar", "Shane");
        uint256[] memory min = createUint256Array(10,100);
        uint256[] memory max = createUint256Array(10000000000000000000000000, 10000000000000000000000000);
        uint16[] memory empty;
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
    }

    /// Test Account Min Max Token Balance Rule Fail Scenario 
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceCheck_UnderMinBalance() public endWithStopPrank() ifDeplomentTestsEnabled() {
        applicationCoin.mint(superAdmin, totalSupply);
        vm.startPrank(ruleAdmin);
        // add rule at ruleId 0
        bytes32[] memory accs = createBytes32Array("Oscar","Tayler","Shane");
        uint256[] memory min = createUint256Array(10, 20, 30);
        uint256[] memory max = createUint256Array(10000000000000000000000000, 10000000000000000000000000000, 1000000000000000000000000000000);
        uint16[] memory empty;
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        switchToAppAdministrator();
        applicationAppManager.addTag(superAdmin, "Oscar"); //add tag
        assertTrue(applicationAppManager.hasTag(superAdmin, "Oscar"));
        switchToSuperAdmin();
        uint256 balance = applicationCoin.balanceOf(superAdmin);
        uint256 amount = balance - 5; // we try to only leave 5 weis to trigger the rule
        assertEq(applicationCoin.balanceOf(superAdmin), totalSupply);
        bytes32[] memory tags = applicationAppManager.getAllTags(superAdmin);

        vm.expectRevert(abi.encodeWithSignature("UnderMinBalance()"));
        ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).checkAccountMinTokenBalance(balance, tags, amount, ruleId);
    }

    /// Test Account Min Max Balance Rule With Blank Tags 
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceBlankTagProcessChecks() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToRuleAdmin();
        applicationCoin.mint(superAdmin, totalSupply);
        
        // add rule at ruleId 0
        bytes32[] memory accs = createBytes32Array("");
        uint256[] memory min = createUint256Array(10);
        uint256[] memory max = createUint256Array(1000000000000000000000000000000);
        uint16[] memory empty;

        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        switchToAppAdministrator();
        applicationAppManager.addTag(superAdmin, "Oscar"); //add tag
        assertTrue(applicationAppManager.hasTag(superAdmin, "Oscar"));
        switchToSuperAdmin();
        uint256 amount = 999;
        assertEq(applicationCoin.balanceOf(superAdmin), totalSupply);
        bytes32[] memory tags = applicationAppManager.getAllTags(superAdmin);

        ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).checkAccountMaxTokenBalance(applicationCoin.balanceOf(superAdmin), tags, amount, ruleId);
    }

    /// Test Account Min Max Balance Check Fail Scenario 
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceChecks_OverMaxBalance() public endWithStopPrank() ifDeplomentTestsEnabled() {
        applicationCoin.mint(superAdmin, totalSupply);
        vm.startPrank(ruleAdmin);
        // add rule at ruleId 0
        bytes32[] memory accs = createBytes32Array("Oscar","Tayler","Shane");
        uint256[] memory min = createUint256Array(10, 20, 30);
        uint256[] memory max = createUint256Array(10000000000000000000000000, 10000000000000000000000000000, 1000000000000000000000000000000);
        uint16[] memory empty;
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        switchToAppAdministrator();
        applicationAppManager.addTag(superAdmin, "Oscar"); //add tag
        assertTrue(applicationAppManager.hasTag(superAdmin, "Oscar"));
        switchToSuperAdmin();
        uint256 balance = applicationCoin.balanceOf(superAdmin);
        uint256 amount = max[0] + 1;
        bytes32[] memory tags = applicationAppManager.getAllTags(superAdmin);

        vm.expectRevert(abi.encodeWithSignature("OverMaxBalance()"));
        ERC20TaggedRuleProcessorFacet(address(ruleProcessor)).checkAccountMaxTokenBalance(balance, tags, amount, ruleId);
    }


    /// Test Account Min Max Token Balance Rule NFT 
    function testProtocol_RuleProcessorDiamond_AccountMinMaxTokenBalanceRuleNFT() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToAppAdministrator();
        /// mint 6 NFTs to appAdministrator for transfer
        applicationNFT.safeMint(appAdministrator);
        applicationNFT.safeMint(appAdministrator);
        applicationNFT.safeMint(appAdministrator);
        applicationNFT.safeMint(appAdministrator);
        applicationNFT.safeMint(appAdministrator);
        applicationNFT.safeMint(appAdministrator);

        bytes32[] memory accs = createBytes32Array("Oscar");
        uint256[] memory min = createUint256Array(1);
        uint256[] memory max = createUint256Array(6);
        uint16[] memory empty;

        /// set up a non admin user with tokens
        switchToAppAdministrator();
        ///transfer tokenId 1 and 2 to rich_user
        applicationNFT.transferFrom(appAdministrator, rich_user, 0);
        applicationNFT.transferFrom(appAdministrator, rich_user, 1);
        assertEq(applicationNFT.balanceOf(rich_user), 2);

        ///transfer tokenId 3 and 4 to user1
        applicationNFT.transferFrom(appAdministrator, user1, 3);
        applicationNFT.transferFrom(appAdministrator, user1, 4);
        assertEq(applicationNFT.balanceOf(user1), 2);

        switchToRuleAdmin();
        TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        // add the actual rule
        uint32 ruleId = TaggedRuleDataFacet(address(ruleProcessor)).addAccountMinMaxTokenBalance(address(applicationAppManager), accs, min, max, empty, uint64(Blocktime));
        switchToAppAdministrator();
        ///Add Tag to account
        applicationAppManager.addTag(user1, "Oscar"); ///add tag
        assertTrue(applicationAppManager.hasTag(user1, "Oscar"));
        applicationAppManager.addTag(user2, "Oscar"); ///add tag
        assertTrue(applicationAppManager.hasTag(user2, "Oscar"));
        applicationAppManager.addTag(user3, "Oscar"); ///add tag
        assertTrue(applicationAppManager.hasTag(user3, "Oscar"));
        ///perform transfer that checks rule
        vm.stopPrank();
        vm.startPrank(user1);
        applicationNFT.transferFrom(user1, user2, 3);
        assertEq(applicationNFT.balanceOf(user2), 1);
        assertEq(applicationNFT.balanceOf(user1), 1);
        switchToRuleAdmin();
        ///update ruleId in application NFT handler
        ActionTypes[] memory actionTypes = new ActionTypes[](3);
        actionTypes[0] = ActionTypes.P2P_TRANSFER;
        actionTypes[1] = ActionTypes.MINT;
        actionTypes[2] = ActionTypes.BURN;
        ERC721TaggedRuleFacet(address(applicationNFTHandler)).setAccountMinMaxTokenBalanceId(actionTypes, ruleId);
        /// make sure the minimum rules fail results in revert
        vm.stopPrank();
        vm.startPrank(user1);
        vm.expectRevert(0x3e237976);
        applicationNFT.transferFrom(user1, user3, 4);

        ///make sure the maximum rule fail results in revert
        vm.stopPrank();
        switchToAppAdministrator();
        // user1 mints to 6 total (limit)
        applicationNFT.safeMint(user1); /// Id 6
        applicationNFT.safeMint(user1); /// Id 7
        applicationNFT.safeMint(user1); /// Id 8
        applicationNFT.safeMint(user1); /// Id 9
        applicationNFT.safeMint(user1); /// Id 10

        vm.stopPrank();
        switchToAppAdministrator();
        applicationNFT.safeMint(user2);
        // transfer to user1 to exceed limit
        vm.stopPrank();
        vm.startPrank(user2);
        vm.expectRevert(0x1da56a44);
        applicationNFT.transferFrom(user2, user1, 3);

        /// test that burn works with rule
        applicationNFT.burn(3);
        vm.expectRevert(0x3e237976);
        applicationNFT.burn(11);
    }

    /// Test Account Approve Deny Oracle NFT 
    function testProtocol_RuleProcessorDiamond_AccountApproveDenyOracleNFT() public endWithStopPrank() ifDeplomentTestsEnabled() {
        switchToAppAdministrator();
        /// set up a non admin user an nft
        applicationNFT.safeMint(user1);
        applicationNFT.safeMint(user1);
        applicationNFT.safeMint(user1);
        applicationNFT.safeMint(user1);
        applicationNFT.safeMint(user1);

        assertEq(applicationNFT.balanceOf(user1), 5);

        // add the rule.
        switchToRuleAdmin();
        uint32 _index = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 0, address(oracleDenied));
        assertEq(_index, 0);
        NonTaggedRules.AccountApproveDenyOracle memory rule = ERC20RuleProcessorFacet(address(ruleProcessor)).getAccountApproveDenyOracle(_index);
        assertEq(rule.oracleType, 0);
        assertEq(rule.oracleAddress, address(oracleDenied));
        // add a blocked address
        switchToAppAdministrator();
        badBoys.push(address(69));
        oracleDenied.addToDeniedList(badBoys);
        /// connect the rule to this handler
        switchToRuleAdmin();
        ActionTypes[] memory actionTypes = new ActionTypes[](3);
        actionTypes[0] = ActionTypes.P2P_TRANSFER;
        actionTypes[1] = ActionTypes.MINT;
        actionTypes[2] = ActionTypes.BURN;
        ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).setAccountApproveDenyOracleId(actionTypes, _index);
        // test that the oracle works
        // This one should pass
        ///perform transfer that checks rule
        vm.stopPrank();
        vm.startPrank(user1);
        applicationNFT.transferFrom(user1, user2, 0);
        assertEq(applicationNFT.balanceOf(user2), 1);
        ///perform transfer that checks rule
        // This one should fail
        vm.expectRevert(0x2767bda4);
        applicationNFT.transferFrom(user1, address(69), 1);
        assertEq(applicationNFT.balanceOf(address(69)), 0);
        // check the allowed list type
        switchToRuleAdmin();
        _index = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 1, address(oracleApproved));
        /// connect the rule to this handler
        ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).setAccountApproveDenyOracleId(actionTypes, _index);
        // add an allowed address
        switchToAppAdministrator();
        goodBoys.push(address(59));
        oracleApproved.addToApprovedList(goodBoys);
        vm.stopPrank();
        vm.startPrank(user1);
        // This one should pass
        applicationNFT.transferFrom(user1, address(59), 2);
        // This one should fail
        vm.expectRevert(0xcafd3316);
        applicationNFT.transferFrom(user1, address(88), 3);

        // Finally, check the invalid type
        switchToRuleAdmin();
        bytes4 selector = bytes4(keccak256("InvalidOracleType(uint8)"));
        vm.expectRevert(abi.encodeWithSelector(selector, 2));
        _index = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 2, address(oracleApproved));

        /// set oracle back to allow and attempt to burn token
        _index = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 1, address(oracleApproved));
        ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).setAccountApproveDenyOracleId(actionTypes, _index);
        /// swap to user and burn
        vm.stopPrank();
        vm.startPrank(user1);
        applicationNFT.burn(4);
        /// set oracle to deny and add address(0) to list to deny burns
        switchToRuleAdmin();
        _index = RuleDataFacet(address(ruleProcessor)).addAccountApproveDenyOracle(address(applicationAppManager), 0, address(oracleDenied));
        ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).setAccountApproveDenyOracleId(actionTypes, _index);
        switchToAppAdministrator();
        badBoys.push(address(0));
        oracleDenied.addToDeniedList(badBoys);
        /// user attempts burn
        vm.stopPrank();
        vm.startPrank(user1);
        vm.expectRevert(0x2767bda4);
        applicationNFT.burn(3);
    }

    function testProtocol_RuleProcessorDiamond_TokenMaxDailyTradesRuleInNFT() public endWithStopPrank() ifDeplomentTestsEnabled() {
        vm.warp(Blocktime);
        switchToAppAdministrator();
        /// set up a non admin user an nft
        applicationNFT.safeMint(user1); // tokenId = 0
        applicationNFT.safeMint(user1); // tokenId = 1
        applicationNFT.safeMint(user1); // tokenId = 2
        applicationNFT.safeMint(user1); // tokenId = 3
        applicationNFT.safeMint(user1); // tokenId = 4

        assertEq(applicationNFT.balanceOf(user1), 5);

        // add the rule.
        bytes32[] memory nftTags = createBytes32Array("BoredGrape", "DiscoPunk"); 
        uint8[] memory tradesAllowed = createUint8Array(1, 5);
        switchToRuleAdmin();
        uint32 _index = TaggedRuleDataFacet(address(ruleProcessor)).addTokenMaxDailyTrades(address(applicationAppManager), nftTags, tradesAllowed, Blocktime);
        assertEq(_index, 0);
        TaggedRules.TokenMaxDailyTrades memory rule = ERC721TaggedRuleProcessorFacet(address(ruleProcessor)).getTokenMaxDailyTrades(_index, nftTags[0]);
        assertEq(rule.tradesAllowedPerDay, 1);
        // apply the rule to the ApplicationERC721Handler
        ERC721NonTaggedRuleFacet(address(applicationNFTHandler)).setTokenMaxDailyTradesId(_createActionsArray(), _index);
        // tag the NFT collection
        switchToAppAdministrator();
        applicationAppManager.addTag(address(applicationNFT), "DiscoPunk"); ///add tag

        // ensure standard transfer works by transferring 1 to user2 and back(2 trades)
        ///perform transfer that checks rule
        vm.stopPrank();
        vm.startPrank(user1);
        applicationNFT.transferFrom(user1, user2, 0);
        assertEq(applicationNFT.balanceOf(user2), 1);
        vm.stopPrank();
        vm.startPrank(user2);
        applicationNFT.transferFrom(user2, user1, 0);
        assertEq(applicationNFT.balanceOf(user2), 0);

        // set to a tag that only allows 1 transfer
        switchToAppAdministrator();
        applicationAppManager.removeTag(address(applicationNFT), "DiscoPunk"); ///add tag
        applicationAppManager.addTag(address(applicationNFT), "BoredGrape"); ///add tag
        // perform 1 transfer
        vm.stopPrank();
        vm.startPrank(user1);
        applicationNFT.transferFrom(user1, user2, 1);
        assertEq(applicationNFT.balanceOf(user2), 1);
        vm.stopPrank();
        vm.startPrank(user2);
        // this one should fail because it is more than 1 in 24 hours
        vm.expectRevert(0x09a92f2d);
        applicationNFT.transferFrom(user2, user1, 1);
        assertEq(applicationNFT.balanceOf(user2), 1);
        // add a day to the time and it should pass
        vm.warp(block.timestamp + 1 days);
        applicationNFT.transferFrom(user2, user1, 1);
        assertEq(applicationNFT.balanceOf(user2), 0);

        // add the other tag and check to make sure that it still only allows 1 trade
        switchToAppAdministrator();
        applicationAppManager.addTag(address(applicationNFT), "DiscoPunk"); ///add tag
        vm.stopPrank();
        vm.startPrank(user1);
        // first one should pass
        applicationNFT.transferFrom(user1, user2, 2);
        vm.stopPrank();
        vm.startPrank(user2);
        // this one should fail because it is more than 1 in 24 hours
        vm.expectRevert(0x09a92f2d);
        applicationNFT.transferFrom(user2, user1, 2);
    }
}