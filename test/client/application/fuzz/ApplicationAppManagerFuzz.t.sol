// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/util/TestCommonFoundry.sol";

contract ApplicationAppManagerFuzzTest is TestCommonFoundry {

    function setUp() public {
        setUpProtocolAndAppManager();            
        vm.warp(Blocktime); // set block.timestamp
    }

    function testApplication_ApplicationAppManagerFuzz_RenounceAppAdmin(uint8 addressIndex) public endWithStopPrank() {
        address sender = ADDRESSES[addressIndex % ADDRESSES.length];
        vm.startPrank(sender);
        applicationAppManager.renounceRole(APP_ADMIN_ROLE, sender);
        if (sender == superAdmin) assertFalse(applicationAppManager.isAppAdministrator(sender));
    }

    function testApplication_ApplicationAppManagerFuzz_AddAppAdministrator(uint8 addressIndexA, uint8 addressIndexB) public endWithStopPrank() {
        address sender = ADDRESSES[addressIndexA % ADDRESSES.length];
        address admin = ADDRESSES[addressIndexB % ADDRESSES.length];
        vm.startPrank(sender);
        if (sender != superAdmin) vm.expectRevert();
        applicationAppManager.addAppAdministrator(admin);
        if (sender == superAdmin) {
            assertTrue(applicationAppManager.isAppAdministrator(admin));
            assertFalse(applicationAppManager.isAppAdministrator(address(0xBABE)));
        }
    }

    function testApplication_ApplicationAppManagerFuzz_AddMultipleAppAdministrator(uint8 addressIndexA) public endWithStopPrank() {
        vm.stopPrank();
        address sender = ADDRESSES[addressIndexA % ADDRESSES.length];
        vm.startPrank(sender);
        if (sender != superAdmin) vm.expectRevert();
        applicationAppManager.addMultipleAppAdministrator(ADDRESSES);
        if (sender == superAdmin) {
            assertTrue(applicationAppManager.isAppAdministrator(appAdministrator));
            assertFalse(applicationAppManager.isAppAdministrator(address(0xFF77)));
        }
    }

    function testApplication_ApplicationAppManagerFuzz_RevokeAppAdministrator(uint8 addressIndexA, uint8 addressIndexB, uint8 addressIndexC) public endWithStopPrank() {
        address sender = ADDRESSES[addressIndexA % ADDRESSES.length];
        address admin = ADDRESSES[addressIndexB % ADDRESSES.length];
        address random = ADDRESSES[addressIndexC % ADDRESSES.length];
        vm.startPrank(sender);
        if (sender != superAdmin) vm.expectRevert();
        applicationAppManager.addAppAdministrator(admin); //set a app administrator
        if (sender == superAdmin) {
            assertTrue(applicationAppManager.isAppAdministrator(admin));
            assertTrue(applicationAppManager.hasRole(APP_ADMIN_ROLE, admin)); // verify it was added as a app administrator
            vm.stopPrank();
            vm.startPrank(random);
            if (random != superAdmin) vm.expectRevert();
            applicationAppManager.revokeRole(APP_ADMIN_ROLE, admin);
            if (random == superAdmin) assertFalse(applicationAppManager.isAppAdministrator(admin));
        }
    }

    function testApplication_ApplicationAppManagerFuzz_RenounceAppAdministrator(uint8 addressIndexA, uint8 addressIndexB) public endWithStopPrank() {
        address sender = ADDRESSES[addressIndexA % ADDRESSES.length];
        address admin = ADDRESSES[addressIndexB % ADDRESSES.length];
        vm.startPrank(sender);
        if (sender != superAdmin) vm.expectRevert();
        applicationAppManager.addAppAdministrator(admin);
        if (sender == superAdmin) {
            assertTrue(applicationAppManager.isAppAdministrator(admin));
            assertTrue(applicationAppManager.hasRole(APP_ADMIN_ROLE, admin)); // verify it was added as a app administrator
            vm.stopPrank();
            vm.startPrank(admin);
            applicationAppManager.renounceAppAdministrator();
            assertFalse(applicationAppManager.isAppAdministrator(admin));
        }
    }

    ///---------------Risk ADMIN--------------------
    function testApplication_ApplicationAppManagerFuzz_AddRiskAdmin(uint8 addressIndexA, uint8 addressIndexB, uint8 addressIndexC) public endWithStopPrank() {
        address sender = ADDRESSES[addressIndexA % ADDRESSES.length];
        address admin = ADDRESSES[addressIndexB % ADDRESSES.length];
        address random = ADDRESSES[addressIndexC % ADDRESSES.length];
        vm.startPrank(sender);
        if (sender != superAdmin) vm.expectRevert();
        applicationAppManager.addAppAdministrator(admin);
        if (sender == superAdmin) {
            vm.stopPrank();
            vm.startPrank(admin);
            applicationAppManager.addRiskAdmin(random); //add risk admin
            assertTrue(applicationAppManager.isRiskAdmin(random));
            assertFalse(applicationAppManager.isRiskAdmin(address(88)));
            vm.stopPrank();
            vm.startPrank(random);
            if (random != superAdmin && random != admin) vm.expectRevert();
            applicationAppManager.addRiskAdmin(random); //add risk admin
        }
    }

    function testApplication_ApplicationAppManagerFuzz_AddMultipleRiskAdmins(uint8 addressIndexA, uint8 addressIndexB, uint8 addressIndexC) public endWithStopPrank() {
        address sender = ADDRESSES[addressIndexA % ADDRESSES.length];
        address admin = ADDRESSES[addressIndexB % ADDRESSES.length];
        address random = ADDRESSES[addressIndexC % ADDRESSES.length];
        vm.startPrank(sender);
        if (sender != superAdmin) vm.expectRevert();
        applicationAppManager.addAppAdministrator(admin);
        if (sender == superAdmin) {
            vm.stopPrank();
            vm.startPrank(admin);
            applicationAppManager.addMultipleRiskAdmin(ADDRESSES); //add risk admins
            assertTrue(applicationAppManager.isRiskAdmin(random));
            assertTrue(applicationAppManager.isRiskAdmin(address(0xF00D)));
            assertTrue(applicationAppManager.isRiskAdmin(address(0xBEEF)));
            assertTrue(applicationAppManager.isRiskAdmin(address(0xC0FFEE)));
            assertFalse(applicationAppManager.isRiskAdmin(address(88)));
        }
    }

    function testApplication_ApplicationAppManagerFuzz_RenounceRiskAdmin(uint8 addressIndexA, uint8 addressIndexB, uint8 addressIndexC) public endWithStopPrank() {
        address sender = ADDRESSES[addressIndexA % ADDRESSES.length];
        address admin = ADDRESSES[addressIndexB % ADDRESSES.length];
        address random = ADDRESSES[addressIndexC % ADDRESSES.length];
        vm.startPrank(sender);
        if (sender != superAdmin) vm.expectRevert();
        applicationAppManager.addAppAdministrator(admin);
        if (sender == superAdmin) {
            vm.stopPrank();
            vm.startPrank(admin);
            applicationAppManager.addRiskAdmin(random); //add risk admin
            assertTrue(applicationAppManager.isRiskAdmin(random));
            assertFalse(applicationAppManager.isRiskAdmin(address(88)));

            vm.stopPrank(); //stop interacting as the app administrator
            vm.startPrank(random); //interact as the created risk admin
            applicationAppManager.renounceRiskAdmin();
            assertFalse(applicationAppManager.isRiskAdmin(random));
        }
    }

    function testApplication_ApplicationAppManagerFuzz_RevokeRiskAdmin(uint8 addressIndexA, uint8 addressIndexB, uint8 addressIndexC) public endWithStopPrank() {
        address sender = ADDRESSES[addressIndexA % ADDRESSES.length];
        address admin = ADDRESSES[addressIndexB % ADDRESSES.length];
        address random = ADDRESSES[addressIndexC % ADDRESSES.length];
        vm.startPrank(sender);
        if (sender != superAdmin) vm.expectRevert();
        applicationAppManager.addAppAdministrator(admin);
        if (sender == superAdmin) {
            vm.stopPrank();
            vm.startPrank(admin);
            applicationAppManager.addRiskAdmin(random); //add risk admin
            assertTrue(applicationAppManager.isRiskAdmin(random));
            assertFalse(applicationAppManager.isRiskAdmin(address(88)));
            vm.stopPrank();
            vm.startPrank(random);
            if (random != superAdmin && random != admin) vm.expectRevert();
            applicationAppManager.revokeRole(RISK_ADMIN_ROLE, admin);
            if (random == superAdmin || random == admin) assertFalse(applicationAppManager.isRiskAdmin(admin));
        }
    }

    ///---------------ACCESS LEVEL--------------------
    function testApplication_ApplicationAppManagerFuzz_AddAccessLevel(uint8 addressIndexA, uint8 addressIndexB, uint8 addressIndexC) public endWithStopPrank() {
        address sender = ADDRESSES[addressIndexA % ADDRESSES.length];
        address admin = ADDRESSES[addressIndexB % ADDRESSES.length];
        address random = ADDRESSES[addressIndexC % ADDRESSES.length];
        vm.startPrank(sender);
        if (sender != superAdmin) vm.expectRevert();
        applicationAppManager.addAppAdministrator(admin);
        if (sender == superAdmin) {
            vm.stopPrank();
            vm.startPrank(admin);
            applicationAppManager.addAccessLevelAdmin(random); //add AccessLevel admin
            assertTrue(applicationAppManager.isAccessLevelAdmin(random));
            assertFalse(applicationAppManager.isAccessLevelAdmin(address(88)));
            vm.stopPrank();
            vm.startPrank(random);
            if (random != superAdmin && random != admin) vm.expectRevert();
            applicationAppManager.addAccessLevelAdmin(address(0xBABE)); //add AccessLevel
        }
    }

    function testApplication_ApplicationAppManagerFuzz_MultipleAddAccessLevel(uint8 addressIndexA, uint8 addressIndexB, uint8 addressIndexC) public endWithStopPrank() {
        address sender = ADDRESSES[addressIndexA % ADDRESSES.length];
        address admin = ADDRESSES[addressIndexB % ADDRESSES.length];
        address random = ADDRESSES[addressIndexC % ADDRESSES.length];
        vm.startPrank(sender);
        if (sender != superAdmin) vm.expectRevert();
        applicationAppManager.addAppAdministrator(admin);
        if (sender == superAdmin) {
            vm.stopPrank();
            vm.startPrank(admin);
            applicationAppManager.addMultipleAccessLevelAdmins(ADDRESSES); //add AccessLevel admins
            assertTrue(applicationAppManager.isAccessLevelAdmin(random));
            assertTrue(applicationAppManager.isAccessLevelAdmin(address(0xF00D)));
            assertTrue(applicationAppManager.isAccessLevelAdmin(address(0xBEEF)));
            assertTrue(applicationAppManager.isAccessLevelAdmin(address(0xC0FFEE)));
            assertFalse(applicationAppManager.isAccessLevelAdmin(address(88)));
        }
    }

    function testApplication_ApplicationAppManagerFuzz_RenounceAccessLevel(uint8 addressIndexA, uint8 addressIndexB, uint8 addressIndexC) public endWithStopPrank() {
        address sender = ADDRESSES[addressIndexA % ADDRESSES.length];
        address admin = ADDRESSES[addressIndexB % ADDRESSES.length];
        address random = ADDRESSES[addressIndexC % ADDRESSES.length];
        vm.startPrank(sender);
        if (sender != superAdmin) vm.expectRevert();
        applicationAppManager.addAppAdministrator(admin);
        if (sender == superAdmin) {
            vm.stopPrank();
            vm.startPrank(admin);
            applicationAppManager.addAccessLevelAdmin(random); //add AccessLevel admin
            assertTrue(applicationAppManager.isAccessLevelAdmin(random));
            assertFalse(applicationAppManager.isAccessLevelAdmin(address(88)));

            vm.stopPrank(); //stop interacting as the app administrator
            vm.startPrank(random); //interact as the created risk admin
            applicationAppManager.renounceAccessLevelAdmin();
            assertFalse(applicationAppManager.isAccessLevelAdmin(random));
        }
    }

    function testApplication_ApplicationAppManagerFuzz_RevokeAccessLevel(uint8 addressIndexA, uint8 addressIndexB, uint8 addressIndexC) public endWithStopPrank() {
        address sender = ADDRESSES[addressIndexA % ADDRESSES.length];
        address admin = ADDRESSES[addressIndexB % ADDRESSES.length];
        address random = ADDRESSES[addressIndexC % ADDRESSES.length];
        vm.startPrank(sender);
        if (sender != superAdmin) vm.expectRevert();
        applicationAppManager.addAppAdministrator(admin);
        if (sender == superAdmin) {
            vm.stopPrank();
            vm.startPrank(admin);
            applicationAppManager.addAccessLevelAdmin(random); //add AccessLevel admin
            assertTrue(applicationAppManager.isAccessLevelAdmin(random));
            assertFalse(applicationAppManager.isAccessLevelAdmin(address(88)));
            vm.stopPrank();
            vm.startPrank(random);
            if (random != superAdmin && random != admin) vm.expectRevert();
            applicationAppManager.revokeRole(ACCESS_LEVEL_ADMIN_ROLE, admin);
            if (random == superAdmin || random == admin) assertFalse(applicationAppManager.isRiskAdmin(admin));
        }
    }

    ///---------------AccessLevel MAINTENANCE--------------------
    function testApplication_ApplicationAppManagerFuzz_AddAccessLevel(uint8 addressIndexA, uint8 addressIndexB, uint8 addressIndexC, uint8 AccessLevel) public endWithStopPrank() {
        address sender = ADDRESSES[addressIndexA % ADDRESSES.length];
        address admin = ADDRESSES[addressIndexB % ADDRESSES.length];
        address random = ADDRESSES[addressIndexC % ADDRESSES.length];
        vm.startPrank(sender);
        if (sender != superAdmin) vm.expectRevert();
        applicationAppManager.addAccessLevelAdmin(admin);
        if (sender == superAdmin) {
            assertTrue(applicationAppManager.isAccessLevelAdmin(admin));
            vm.stopPrank();
            vm.startPrank(random);
            if (random != admin || (AccessLevel > 4)) vm.expectRevert();
            applicationAppManager.addAccessLevel(address(0xBABE), AccessLevel);
            if (random == admin && (AccessLevel < 4)) {
                assertEq(applicationAppManager.getAccessLevel(address(0xBABE)), AccessLevel);
                /// testing update
                applicationAppManager.addAccessLevel(address(0xBABE), 1);
                assertEq(applicationAppManager.getAccessLevel(address(0xBABE)), 1);
            }
        }
    }

    ///---------------RISK SCORE MAINTENANCE--------------------
    function testApplication_ApplicationAppManagerFuzz_AddRiskScore(uint8 addressIndexA, uint8 addressIndexB, uint8 addressIndexC, uint8 riskScore) public endWithStopPrank() {
        address sender = ADDRESSES[addressIndexA % ADDRESSES.length];
        address admin = ADDRESSES[addressIndexB % ADDRESSES.length];
        address random = ADDRESSES[addressIndexC % ADDRESSES.length];
        vm.startPrank(sender);
        if (sender != superAdmin) vm.expectRevert();
        applicationAppManager.addRiskAdmin(admin);
        if (sender == superAdmin) {
            assertTrue(applicationAppManager.isRiskAdmin(admin));
            vm.stopPrank();
            vm.startPrank(random);
            if (random != admin || riskScore > 100) vm.expectRevert();
            applicationAppManager.addRiskScore(address(0xBABE), riskScore);
            if (random == admin && riskScore <= 100) {
                assertEq(applicationAppManager.getRiskScore(address(0xBABE)), riskScore);
                /// testing update
                applicationAppManager.addRiskScore(address(0xBABE), 1);
                assertEq(applicationAppManager.getRiskScore(address(0xBABE)), 1);
            }
        }
    }

    ///---------------TAGS--------------------
    function testApplication_ApplicationAppManagerFuzz_AddTag(uint8 addressIndexA, uint8 addressIndexB, uint8 addressIndexC, bytes32 Tag1, bytes32 Tag2) public endWithStopPrank() {
        vm.assume(Tag1 != Tag2 && Tag2 != Tag1);
        address sender = ADDRESSES[addressIndexA % ADDRESSES.length];
        address admin = ADDRESSES[addressIndexB % ADDRESSES.length];
        address random = ADDRESSES[addressIndexC % ADDRESSES.length];
        vm.startPrank(sender);
        if (sender != superAdmin) vm.expectRevert();
        applicationAppManager.addAppAdministrator(admin);
        if (sender == superAdmin) {
            vm.stopPrank();
            vm.startPrank(admin);
            if (Tag1 == "") vm.expectRevert();
            applicationAppManager.addTag(address(0xBABE), Tag1); //add tag
            if (Tag1 != "") assertTrue(applicationAppManager.hasTag(address(0xBABE), Tag1));
            vm.stopPrank();
            vm.startPrank(random);
            if ((random != admin && random != superAdmin) || Tag2 == "") vm.expectRevert();
            applicationAppManager.addTag(address(0xBABE), Tag2);
            if ((random == admin || random == superAdmin) && Tag2 != "") assertTrue(applicationAppManager.hasTag(address(0xBABE), Tag2));
        }
    }

    function testApplication_ApplicationAppManagerFuzz_AddMultipleGenTagsToMulitpleAccounts(uint8 addressIndexA, uint8 addressIndexB, bytes32 Tag1, bytes32 Tag2, bytes32 Tag3, bytes32 Tag4) public endWithStopPrank() {
        vm.assume(Tag1 != Tag2 && Tag2 != Tag3 && Tag3 != Tag4 && Tag4 != Tag1 && Tag4 != Tag2 && Tag3 != Tag1);
        vm.assume(Tag1 != "" && Tag2 != "" && Tag3 != "" && Tag4 != "");
        address sender = ADDRESSES[addressIndexA % ADDRESSES.length];
        address admin = ADDRESSES[addressIndexB % ADDRESSES.length];

        bytes32[] memory genTags = createBytes32Array(Tag1, Tag1, Tag2, Tag2, Tag3, Tag3, Tag4, Tag4);

        vm.startPrank(sender);
        if (sender != superAdmin) vm.expectRevert();
        applicationAppManager.addAppAdministrator(admin);
        ///Test to ensure non admins cannot call function
        if (sender == superAdmin) {
            vm.stopPrank();
            vm.startPrank(admin);
            applicationAppManager.addMultipleTagToMultipleAccounts(ADDRESSES, genTags);
            /// Test to prove addresses in array are tagged by index matched to second array of tags
            assertTrue(applicationAppManager.hasTag(user, Tag3));
            assertTrue(applicationAppManager.hasTag(address(0xBEEF), Tag3));
            assertTrue(applicationAppManager.hasTag(address(0xC0FFEE), Tag4));
            assertTrue(applicationAppManager.hasTag(address(0xF00D), Tag4));
        }
    }

    function testApplication_ApplicationAppManagerFuzz_RemoveTag(uint8 addressIndexA, bytes32 Tag1, bytes32 Tag2, bytes32 Tag3, bytes32 Tag4) public endWithStopPrank() {
        vm.assume(Tag1 != Tag2 && Tag2 != Tag3 && Tag3 != Tag4 && Tag4 != Tag1 && Tag4 != Tag2 && Tag3 != Tag1);

        address sender = ADDRESSES[addressIndexA % ADDRESSES.length];
        switchToAppAdministrator();
        /// add first tag
        if (Tag1 == "") vm.expectRevert();
        applicationAppManager.addTag(address(0xBABE), Tag1); //add tag
        if (Tag1 != "") {
            assertTrue(applicationAppManager.hasTag(address(0xBABE), Tag1));
            assertFalse(applicationAppManager.hasTag(address(0xBABE), Tag2));
        }
        /// add second tag
        if (Tag2 == "") vm.expectRevert();
        applicationAppManager.addTag(address(0xBABE), Tag2); //add tag
        if (Tag2 != "") {
            assertTrue(applicationAppManager.hasTag(address(0xBABE), Tag2));
            assertFalse(applicationAppManager.hasTag(address(0xBABE), Tag3));
        }
        /// add a third tag
        if (Tag3 == "") vm.expectRevert();
        applicationAppManager.addTag(address(0xBABE), Tag3); //add tag
        if (Tag3 != "") {
            assertTrue(applicationAppManager.hasTag(address(0xBABE), Tag3));
            assertFalse(applicationAppManager.hasTag(address(0xBABE), Tag4));
        }
        /// remove tags
        vm.stopPrank();
        vm.startPrank(sender);
        if ((sender != appAdministrator)) vm.expectRevert();
        applicationAppManager.removeTag(address(0xBABE), Tag3);
        if ((sender == appAdministrator)) assertFalse(applicationAppManager.hasTag(address(0xBABE), Tag3));
        if ((sender != appAdministrator)) vm.expectRevert();
        applicationAppManager.removeTag(address(0xBABE), Tag2);
        if ((sender == appAdministrator)) assertFalse(applicationAppManager.hasTag(address(0xBABE), Tag2));
        if ((sender != appAdministrator)) vm.expectRevert();
        applicationAppManager.removeTag(address(0xBABE), Tag1);
        if ((sender == appAdministrator)) {
            assertFalse(applicationAppManager.hasTag(address(0xBABE), Tag1));
        }
    }

    ///---------------PAUSE RULES----------------
    function testApplication_ApplicationAppManagerFuzz_AddPauseRuleFuzz(uint8 addressIndexA, uint8 addressIndexB, uint8 addressIndexC, uint64 start, uint64 end) public endWithStopPrank() {
        address sender = ADDRESSES[addressIndexA % ADDRESSES.length];
        address admin = ADDRESSES[addressIndexB % ADDRESSES.length];
        address random = ADDRESSES[addressIndexC % ADDRESSES.length];
        vm.startPrank(sender);
        if (sender != superAdmin) vm.expectRevert();
        applicationAppManager.addAppAdministrator(admin);
        if (sender == superAdmin) {
            vm.stopPrank();
            vm.startPrank(admin);
            /// we are adding a repeated rule to test the resiliency of the
            /// contract to this scenario
            if (start >= end || start <= block.timestamp) vm.expectRevert();
            applicationAppManager.addPauseRule(start, end);
            if (start >= end || start <= block.timestamp) vm.expectRevert();
            applicationAppManager.addPauseRule(start, end);
            if (start < end && start > block.timestamp) {
                PauseRule[] memory test = applicationAppManager.getPauseRules();
                assertTrue(test.length == 2);
                assertTrue(applicationHandler.isPauseRuleActive() == true);

                /// test if not-an-admin can set a rule
                vm.stopPrank();
                vm.startPrank(random);
                /// testing onlyAppAdministrator
                if (random != admin && random != superAdmin) vm.expectRevert();
                applicationAppManager.addPauseRule(1769924800, 1769984800);
                if (random == admin || random == superAdmin) {
                    test = applicationAppManager.getPauseRules();
                    assertTrue(test.length == 3);
                }
                PauseRule[] memory total = applicationAppManager.getPauseRules();
                vm.stopPrank();
                vm.startPrank(admin);
                applicationAppManager.removePauseRule(start, end);
                test = applicationAppManager.getPauseRules();
                assertTrue(test.length == total.length - 2);
            }
        }
    }
}
