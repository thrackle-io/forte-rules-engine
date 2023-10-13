// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "src/data/GeneralTags.sol";
import "src/data/PauseRules.sol";
import "src/data/AccessLevels.sol";
import "src/data/RiskScores.sol";
import "src/data/Accounts.sol";
import "src/data/IDataModule.sol";
import "test/helpers/TestCommonFoundry.sol";

contract AppManagerBaseTest is TestCommonFoundry {
    bytes32 public constant SUPER_ADMIN_ROLE = keccak256("SUPER_ADMIN_ROLE");
    bytes32 public constant USER_ROLE = keccak256("USER");
    bytes32 public constant APP_ADMIN_ROLE = keccak256("APP_ADMIN_ROLE");
    bytes32 public constant ACCESS_TIER_ADMIN_ROLE = keccak256("ACCESS_TIER_ADMIN_ROLE");
    bytes32 public constant RISK_ADMIN_ROLE = keccak256("RISK_ADMIN_ROLE");
    uint256 public constant TEST_DATE = 1666706998;

    function setUp() public {
        vm.startPrank(superAdmin); //set up as the default admin
        setUpProtocolAndAppManager();
        switchToAppAdministrator();
        vm.warp(TEST_DATE); // set block.timestamp
    }

    ///---------------DEFAULT ADMIN--------------------
    /// Test the Default Admin roles
    function testIsSuperAdmin() public {
        assertEq(applicationAppManager.isSuperAdmin(superAdmin), true);
        assertEq(applicationAppManager.isSuperAdmin(appAdministrator), false);
    }

    /// Test the Application Administrators roles
    function testIsAppAdministrator() public {
        assertEq(applicationAppManager.isAppAdministrator(superAdmin), true);
    }

    function testRenounceSuperAdmin() public {
        switchToSuperAdmin();
        applicationAppManager.renounceRole(SUPER_ADMIN_ROLE, superAdmin);
    }

    ///---------------APP ADMIN--------------------
    // Test the Application Administrators roles(only DEFAULT_ADMIN can add app administrator)
    function testAddAppAdministratorAppManager() public {
        vm.stopPrank();
        vm.startPrank(superAdmin);
        applicationAppManager.addAppAdministrator(appAdministrator);
        assertEq(applicationAppManager.isAppAdministrator(appAdministrator), true);
        assertEq(applicationAppManager.isAppAdministrator(user), false);

        switchToAppAdministrator();
        vm.expectRevert();
        applicationAppManager.addAppAdministrator(address(77));
        assertFalse(applicationAppManager.isAppAdministrator(address(77)));
    }

    /// Test revoke Application Administrators role
    function testRevokeAppAdministrator() public {
        switchToSuperAdmin();
        applicationAppManager.addAppAdministrator(appAdministrator); //set a app administrator
        assertEq(applicationAppManager.isAppAdministrator(appAdministrator), true);
        assertEq(applicationAppManager.hasRole(APP_ADMIN_ROLE, appAdministrator), true); // verify it was added as a app administrator

        applicationAppManager.revokeRole(APP_ADMIN_ROLE, appAdministrator);
        assertEq(applicationAppManager.isAppAdministrator(appAdministrator), false);
    }

    /// Test failed revoke Application Administrators role
    function testFailRevokeAppAdministrator() public {
        switchToSuperAdmin();
        applicationAppManager.addAppAdministrator(appAdministrator); //set a app administrator
        assertEq(applicationAppManager.isAppAdministrator(appAdministrator), true);
        assertEq(applicationAppManager.hasRole(APP_ADMIN_ROLE, appAdministrator), true); // verify it was added as a app administrator

        applicationAppManager.addAppAdministrator(address(77)); //set an additional app administrator
        assertEq(applicationAppManager.isAppAdministrator(address(77)), true);
        assertEq(applicationAppManager.hasRole(APP_ADMIN_ROLE, address(77)), true); // verify it was added as a app administrator

        vm.stopPrank(); //stop interacting as the default admin
        vm.startPrank(user); //interact as a normal user

        applicationAppManager.revokeRole(APP_ADMIN_ROLE, address(77)); // try to revoke other app administrator
    }

    /// Test renounce Application Administrators role
    function testRenounceAppAdministrator() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.
        applicationAppManager.renounceAppAdministrator();
    }

    ///---------------Risk ADMIN--------------------
    // Test adding the Risk Admin roles
    function testAddRiskAdmin() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.

        applicationAppManager.addRiskAdmin(riskAdmin); //add risk admin
        assertEq(applicationAppManager.isRiskAdmin(riskAdmin), true);
        assertEq(applicationAppManager.isRiskAdmin(address(88)), false);
    }

    // Test non app administrator attempt to add the Risk Admin roles
    function testFailAddRiskAdmin() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.

        applicationAppManager.addRiskAdmin(riskAdmin); //add Risk admin
        assertEq(applicationAppManager.isRiskAdmin(riskAdmin), true);
        assertEq(applicationAppManager.isRiskAdmin(address(88)), false);

        vm.stopPrank(); //stop interacting as the app administrator
        vm.startPrank(address(77)); //interact as a non app administrator

        applicationAppManager.addRiskAdmin(address(88)); //add risk admin
    }

    /// Test renounce risk Admin role
    function testRenounceRiskAdmin() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.
        applicationAppManager.addRiskAdmin(riskAdmin); //add risk admin
        assertEq(applicationAppManager.isRiskAdmin(riskAdmin), true);
        assertEq(applicationAppManager.isRiskAdmin(address(88)), false);
        vm.stopPrank(); //stop interacting as the app administrator
        vm.startPrank(riskAdmin); //interact as the created risk admin
        applicationAppManager.renounceRiskAdmin();
    }

    /// Test revoke risk Admin role
    function testRevokeRiskAdmin() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.
        applicationAppManager.addRiskAdmin(riskAdmin); //add risk admin
        assertEq(applicationAppManager.isRiskAdmin(riskAdmin), true);
        assertEq(applicationAppManager.isRiskAdmin(address(88)), false);

        applicationAppManager.revokeRole(RISK_ADMIN_ROLE, riskAdmin);
        assertEq(applicationAppManager.isRiskAdmin(riskAdmin), false);
    }

    /// Test attempt to revoke risk Admin role from non app administrator
    function testFailRevokeRiskAdmin() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.
        applicationAppManager.addRiskAdmin(riskAdmin); //add risk admin
        assertEq(applicationAppManager.isRiskAdmin(riskAdmin), true);
        assertEq(applicationAppManager.isRiskAdmin(address(88)), false);

        vm.stopPrank(); //stop interacting as the app administrator
        vm.startPrank(address(77)); //interact as a different user

        applicationAppManager.revokeRole(RISK_ADMIN_ROLE, riskAdmin);
    }

    ///---------------ACCESS TIER--------------------
    // Test adding the Access Tier roles
    function testAddaccessLevelAdmin() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.
        switchToSuperAdmin(); // create a app administrator and make it the sender.

        applicationAppManager.addAccessTier(accessLevelAdmin); //add AccessLevel admin
        assertEq(applicationAppManager.isAccessTier(accessLevelAdmin), true);
        assertEq(applicationAppManager.isAccessTier(address(88)), false);
    }

    // Test non app administrator attempt to add the Access Tier roles
    function testFailAddaccessLevelAdmin() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.

        applicationAppManager.addAccessTier(accessLevelAdmin); //add AccessLevel admin
        assertEq(applicationAppManager.isAccessTier(accessLevelAdmin), true);
        assertEq(applicationAppManager.isAccessTier(address(88)), false);

        vm.stopPrank(); //stop interacting as the app administrator
        vm.startPrank(address(77)); //interact as a non app administrator

        applicationAppManager.addAccessTier(address(88)); //add AccessLevel admin
    }

    /// Test renounce Access Tier role
    function testRenounceAccessLevelAdmin() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.
        applicationAppManager.addAccessTier(accessLevelAdmin); //add AccessLevel admin
        assertEq(applicationAppManager.isAccessTier(accessLevelAdmin), true);
        assertEq(applicationAppManager.isAccessTier(address(88)), false);
        vm.stopPrank(); //stop interacting as the app administrator
        vm.startPrank(accessLevelAdmin); //interact as the created AccessLevel admin
        applicationAppManager.renounceAccessTier();
    }

    /// Test revoke Access Tier role
    function testRevokeAccessLevelAdmin() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.
        applicationAppManager.addAccessTier(accessLevelAdmin); //add AccessLevel admin
        assertEq(applicationAppManager.isAccessTier(accessLevelAdmin), true);
        assertEq(applicationAppManager.isAccessTier(address(88)), false);

        applicationAppManager.revokeRole(ACCESS_TIER_ADMIN_ROLE, accessLevelAdmin);
        assertEq(applicationAppManager.isAccessTier(accessLevelAdmin), false);
    }

    /// Test attempt to revoke Access Tier role from non app administrator
    function testFailRevokeAccessLevelAdmin() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.
        applicationAppManager.addAccessTier(accessLevelAdmin); //add AccessLevel admin
        assertEq(applicationAppManager.isAccessTier(accessLevelAdmin), true);
        assertEq(applicationAppManager.isAccessTier(address(88)), false);

        vm.stopPrank(); //stop interacting as the app administrator
        vm.startPrank(address(77)); //interact as a different user

        applicationAppManager.revokeRole(ACCESS_TIER_ADMIN_ROLE, accessLevelAdmin);
    }

    ///---------------AccessLevel LEVEL MAINTENANCE--------------------
    function testAddAccessLevel() public {
        switchToAccessLevelAdmin();
        console.log("Access Tier Address");
        console.log(accessLevelAdmin);
        applicationAppManager.addAccessLevel(user, 4);
        uint8 retLevel = applicationAppManager.getAccessLevel(user);
        assertEq(retLevel, 4);
    }

    function testFailAddAccessLevel() public {
        switchToUser(); // create a user and make it the sender.
        applicationAppManager.addAccessLevel(user, 4);
        uint8 retLevel = applicationAppManager.getAccessLevel(user);
        assertEq(retLevel, 4);
    }

    function testUpdateAccessLevel() public {
        switchToAccessLevelAdmin(); // create a access tier and make it the sender.
        applicationAppManager.addAccessLevel(user, 4);
        uint8 retLevel = applicationAppManager.getAccessLevel(user);
        assertEq(retLevel, 4);

        applicationAppManager.addAccessLevel(user, 1);
        retLevel = applicationAppManager.getAccessLevel(user);
        assertEq(retLevel, 1);
    }

    ///---------------RISK SCORE MAINTENANCE--------------------
    function testAddRiskScore() public {
        switchToRiskAdmin(); // create a risk admin and make it the sender.
        applicationAppManager.addRiskScore(user, 75);
        assertEq(75, applicationAppManager.getRiskScore(user));
    }

    function testGetRiskScore() public {
        switchToRiskAdmin(); // create a risk admin and make it the sender.
        applicationAppManager.addRiskScore(user, 75);
        assertEq(75, applicationAppManager.getRiskScore(user));
    }

    function testFailAddRiskScore() public {
        switchToUser(); // create a user and make it the sender.
        applicationAppManager.addRiskScore(user, 44);
        assertEq(44, applicationAppManager.getRiskScore(user));
    }

    function testUpdateRiskScore() public {
        switchToRiskAdmin(); // create a risk admin and make it the sender.
        applicationAppManager.addRiskScore(user, 75);
        assertEq(75, applicationAppManager.getRiskScore(user));
        // update the score
        applicationAppManager.addRiskScore(user, 55);
        assertEq(55, applicationAppManager.getRiskScore(user));
    }

    ///---------------GENERAL TAGS--------------------
    // Test adding the general tags
    function testAddGeneralTag() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.
        applicationAppManager.addGeneralTag(user, "TAG1"); //add tag
        assertTrue(applicationAppManager.hasTag(user, "TAG1"));
    }

    // Test when tag is invalid
    function testFailAddGeneralTag() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.
        applicationAppManager.addGeneralTag(user, ""); //add blank tag
    }

    // Test scenarios for checking specific tags.
    function testHasGeneralTag() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.
        applicationAppManager.addGeneralTag(user, "TAG1"); //add tag
        applicationAppManager.addGeneralTag(user, "TAG3"); //add tag
        assertTrue(applicationAppManager.hasTag(user, "TAG1"));
        assertFalse(applicationAppManager.hasTag(user, "TAG2"));
        assertTrue(applicationAppManager.hasTag(user, "TAG3"));
    }

    // Test removal of the tag
    function testRemoveGeneralTag() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.
        applicationAppManager.addGeneralTag(user, "TAG1"); //add tag
        assertTrue(applicationAppManager.hasTag(user, "TAG1"));
        applicationAppManager.removeGeneralTag(user, "TAG1");
        assertFalse(applicationAppManager.hasTag(user, "TAG1"));
    }

    ///---------------PAUSE RULES----------------
    // Test setting/listing/removing pause rules
    function testAddPauseRule() public {
        switchToRuleAdmin();
        applicationAppManager.addPauseRule(1769924800, 1769984800);
        PauseRule[] memory test = applicationAppManager.getPauseRules();
        PauseRule[] memory noRule = applicationAppManager.getPauseRules();
        assertTrue(test.length == 1);
        assertTrue(noRule.length == 1);
    }

    function testRemovePauseRule() public {
        switchToRuleAdmin();
        applicationAppManager.addPauseRule(1769924800, 1769984800);
        PauseRule[] memory test = applicationAppManager.getPauseRules();
        assertTrue(test.length == 1);
        applicationAppManager.removePauseRule(1769924800, 1769984800);
        PauseRule[] memory removeTest = applicationAppManager.getPauseRules();
        assertTrue(removeTest.length == 0);
    }

    function testAutoCleaningRules() public {
        vm.warp(TEST_DATE);

        switchToRuleAdmin();
        applicationAppManager.addPauseRule(TEST_DATE + 100, TEST_DATE + 200);
        PauseRule[] memory test = applicationAppManager.getPauseRules();
        PauseRule[] memory noRule = applicationAppManager.getPauseRules();
        assertTrue(test.length == 1);
        assertTrue(noRule.length == 1);

        vm.warp(TEST_DATE + 201);
        console.log("block's timestamp", block.timestamp);
        assertEq(block.timestamp, TEST_DATE + 201);
        applicationAppManager.addPauseRule(TEST_DATE + 300, TEST_DATE + 400);
        test = applicationAppManager.getPauseRules();
        console.log("test2 length", test.length);
        noRule = applicationAppManager.getPauseRules();
        console.log("noRule2 length", noRule.length);
        assertTrue(test.length == 1);
        assertTrue(noRule.length == 1);
        vm.warp(TEST_DATE);
    }

    function testRuleSizeLimit() public {
        switchToRuleAdmin();
        vm.warp(TEST_DATE);
        for (uint8 i; i < 15; i++) {
            applicationAppManager.addPauseRule(TEST_DATE + (i + 1) * 10, TEST_DATE + (i + 2) * 10);
        }
        PauseRule[] memory test = applicationAppManager.getPauseRules();
        assertTrue(test.length == 15);
        vm.expectRevert(0xd30bd9c5);
        applicationAppManager.addPauseRule(TEST_DATE + 150, TEST_DATE + 160);
        vm.warp(TEST_DATE);
    }

    function testManualCleaning() public {
        switchToRuleAdmin();
        vm.warp(TEST_DATE);
        for (uint8 i; i < 15; i++) {
            applicationAppManager.addPauseRule(TEST_DATE + (i + 1) * 10, TEST_DATE + (i + 2) * 10);
        }
        PauseRule[] memory test = applicationAppManager.getPauseRules();
        assertTrue(test.length == 15);
        vm.warp(TEST_DATE + 200);
        applicationAppManager.cleanOutdatedRules();
        test = applicationAppManager.getPauseRules();
        assertTrue(test.length == 0);
        vm.warp(TEST_DATE);
    }

    function testAnotherManualCleaning() public {
        switchToRuleAdmin();
        vm.warp(TEST_DATE);
        applicationAppManager.addPauseRule(TEST_DATE + 1000, TEST_DATE + 1010);
        applicationAppManager.addPauseRule(TEST_DATE + 1020, TEST_DATE + 1030);
        applicationAppManager.addPauseRule(TEST_DATE + 40, TEST_DATE + 45);
        applicationAppManager.addPauseRule(TEST_DATE + 1060, TEST_DATE + 1070);
        applicationAppManager.addPauseRule(TEST_DATE + 1080, TEST_DATE + 1090);
        applicationAppManager.addPauseRule(TEST_DATE + 10, TEST_DATE + 20);
        applicationAppManager.addPauseRule(TEST_DATE + 2000, TEST_DATE + 2010);
        applicationAppManager.addPauseRule(TEST_DATE + 2020, TEST_DATE + 2030);
        applicationAppManager.addPauseRule(TEST_DATE + 55, TEST_DATE + 66);
        applicationAppManager.addPauseRule(TEST_DATE + 2060, TEST_DATE + 2070);
        applicationAppManager.addPauseRule(TEST_DATE + 2080, TEST_DATE + 2090);
        PauseRule[] memory test = applicationAppManager.getPauseRules();
        assertTrue(test.length == 11);
        vm.warp(TEST_DATE + 150);
        applicationAppManager.cleanOutdatedRules();
        test = applicationAppManager.getPauseRules();
        assertTrue(test.length == 8);
        vm.warp(TEST_DATE);
    }

    ///--------------- PROVIDER UPGRADES ---------------

    // Test setting General Tag provider contract address
    function testSetNewGeneralTagProvider() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.
        GeneralTags dataMod = new GeneralTags(address(applicationAppManager));
        applicationAppManager.proposeGeneralTagsProvider(address(dataMod));
        dataMod.confirmDataProvider(IDataModule.ProviderType.GENERAL_TAG);
        assertEq(address(dataMod), applicationAppManager.getGeneralTagProvider());
    }

    // Test setting access level provider contract address
    function testSetNewAccessLevelProvider() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.
        AccessLevels dataMod = new AccessLevels(address(applicationAppManager));
        applicationAppManager.proposeAccessLevelsProvider(address(dataMod));
        dataMod.confirmDataProvider(IDataModule.ProviderType.ACCESS_LEVEL);
        assertEq(address(dataMod), applicationAppManager.getAccessLevelProvider());
    }

    // Test setting account  provider contract address
    function testSetNewAccountProvider() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.
        Accounts dataMod = new Accounts(address(applicationAppManager));
        applicationAppManager.proposeAccountsProvider(address(dataMod));
        dataMod.confirmDataProvider(IDataModule.ProviderType.ACCOUNT);
        assertEq(address(dataMod), applicationAppManager.getAccountProvider());
    }

    // Test setting risk provider contract address
    function testSetNewRiskScoreProvider() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.
        RiskScores dataMod = new RiskScores(address(applicationAppManager));
        applicationAppManager.proposeRiskScoresProvider(address(dataMod));
        dataMod.confirmDataProvider(IDataModule.ProviderType.RISK_SCORE);
        assertEq(address(dataMod), applicationAppManager.getRiskScoresProvider());
    }

    // Test setting pause provider contract address
    function testSetNewPauseRulesProvider() public {
        switchToAppAdministrator(); // create a app administrator and make it the sender.
        PauseRules dataMod = new PauseRules(address(applicationAppManager));
        applicationAppManager.proposePauseRulesProvider(address(dataMod));
        dataMod.confirmDataProvider(IDataModule.ProviderType.PAUSE_RULE);
        assertEq(address(dataMod), applicationAppManager.getPauseRulesProvider());
    }

    ///---------------UPGRADEABILITY---------------
    /**
     * @dev This function ensures that a app manager can be upgraded without losing its data
     */
    function testUpgradeAppManagerBaseAppManager() public {
        /// create user addresses
        address upgradeUser1 = address(100);
        address upgradeUser2 = address(101);
        /// put data in the old app manager
        /// AccessLevel
        switchToAccessLevelAdmin();
        applicationAppManager.addAccessLevel(upgradeUser1, 4);
        assertEq(applicationAppManager.getAccessLevel(upgradeUser1), 4);
        applicationAppManager.addAccessLevel(upgradeUser2, 3);
        assertEq(applicationAppManager.getAccessLevel(upgradeUser2), 3);
        /// Risk Data
        switchToRiskAdmin(); // create a access tier and make it the sender.
        applicationAppManager.addRiskScore(upgradeUser1, 75);
        assertEq(75, applicationAppManager.getRiskScore(upgradeUser1));
        applicationAppManager.addRiskScore(upgradeUser2, 65);
        assertEq(65, applicationAppManager.getRiskScore(upgradeUser2));
        /// Account Data
        switchToAppAdministrator(); // create a app administrator and make it the sender.
        /// General Tags Data
        applicationAppManager.addGeneralTag(upgradeUser1, "TAG1"); //add tag
        assertTrue(applicationAppManager.hasTag(upgradeUser1, "TAG1"));
        applicationAppManager.addGeneralTag(upgradeUser2, "TAG2"); //add tag
        assertTrue(applicationAppManager.hasTag(upgradeUser2, "TAG2"));
        /// Pause Rule Data
        switchToRuleAdmin();
        applicationAppManager.addPauseRule(1769924800, 1769984800);
        PauseRule[] memory test = applicationAppManager.getPauseRules();
        assertTrue(test.length == 1);

        /// create new app manager
        vm.stopPrank();
        vm.startPrank(superAdmin);
        AppManager appManagerNew = new AppManager(superAdmin, "Castlevania", false);
        /// migrate data contracts to new app manager
        /// set a app administrator in the new app manager
        appManagerNew.addAppAdministrator(appAdministrator);
        switchToAppAdministrator(); // create a app admin and make it the sender.
        applicationAppManager.proposeDataContractMigration(address(appManagerNew));
        appManagerNew.confirmDataContractMigration(address(applicationAppManager));
        vm.stopPrank();
        vm.startPrank(appAdministrator);
        /// test that the data is accessible only from the new app manager
        assertEq(appManagerNew.getAccessLevel(upgradeUser1), 4);
        assertEq(appManagerNew.getAccessLevel(upgradeUser2), 3);
        assertEq(75, appManagerNew.getRiskScore(upgradeUser1));
        assertEq(65, appManagerNew.getRiskScore(upgradeUser2));
        assertTrue(appManagerNew.hasTag(upgradeUser1, "TAG1"));
        assertTrue(appManagerNew.hasTag(upgradeUser2, "TAG2"));
        test = appManagerNew.getPauseRules();
        assertTrue(test.length == 1);
    }
}
