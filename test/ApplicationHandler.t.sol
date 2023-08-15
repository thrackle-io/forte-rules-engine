// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.17;

import "../src/example/application/ApplicationHandler.sol";
import "../src/application/AppManager.sol";
import "./DiamondTestUtil.sol";
import "./RuleProcessorDiamondTestUtil.sol";

contract ApplicationHandlerTest is DiamondTestUtil, RuleProcessorDiamondTestUtil {
    ApplicationHandler public applicationHandler;
    AppManager appManager;

    RuleProcessorDiamond ruleProcessor;
    RuleStorageDiamond ruleStorageDiamond;

    string tokenId = "FEUD";

    function setUp() public {
        vm.startPrank(superAdmin);
        ruleProcessorDiamond = getApplicationProcessorDiamond();
        // Deploy the Rule Storage Diamond.
        ruleStorageDiamond = getRuleStorageDiamond();
        // Deploy the token rule processor diamond
        ruleProcessor = getRuleProcessorDiamond();
        // Connect the ruleProcessor into the ruleStorageDiamond
        ruleProcessor.setRuleDataDiamond(address(ruleStorageDiamond));

        appManager = new AppManager(superAdmin, "Castlevania", false);

        // for simplicity, set up default as all admins. This is fine because this role logic is
        // test thoroughly in AppManager.t.sol
        appManager.addAppAdministrator(superAdmin);
        appManager.addAccessTier(superAdmin);
        appManager.addRiskAdmin(superAdmin);
        applicationHandler = new ApplicationHandler(address(ruleProcessor), address(appManager));
        appManager.setNewApplicationHandlerAddress(address(applicationHandler));
    }

    /// Test the checkAction. This tests all application compliance
    function testCheckActionApplicationHandler() public {
        // check if standard user can inquire
        //assertTrue(applicationHandler.checkAction(ActionTypes.INQUIRE, address(appManager), user));
        //appManager.checkApplicationRules(_action, _from, _to, balanceValuation, transferValuation);
        appManager.checkApplicationRules(ActionTypes.INQUIRE, user, user, 0, 0);
    }

    ///-----------------------PAUSE ACTIONS-----------------------------///
    /// Test the checkAction. This tests all AccessLevel application compliance
    function testCheckActionForPause() public {
        // check if users can use system when not paused
        appManager.checkApplicationRules(ActionTypes.INQUIRE, user, user, 0, 0);

        // check if users can not use system when paused
        appManager.addPauseRule(1769924800, 1769984800);
        vm.warp(1769924800); // set block.timestamp
        vm.expectRevert();
        appManager.checkApplicationRules(ActionTypes.INQUIRE, user, user, 0, 0);

        // check if users can use system after the pause rule expires
        vm.warp(1769984801); // set block.timestamp
        appManager.checkApplicationRules(ActionTypes.INQUIRE, user, user, 0, 0);

        // check if users can use system when in pause block but the pause has been deleted
        appManager.removePauseRule(1769924800, 1769984800);
        PauseRule[] memory removeTest = appManager.getPauseRules();
        assertTrue(removeTest.length == 0);
        vm.warp(1769924800); // set block.timestamp
        appManager.checkApplicationRules(ActionTypes.INQUIRE, user, user, 0, 0);
    }
}
