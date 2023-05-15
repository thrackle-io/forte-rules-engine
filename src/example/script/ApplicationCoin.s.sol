// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.17;

import "forge-std/Script.sol";
import "src/example/ApplicationERC20.sol";
import "src/application/IAppManager.sol";

/**
 * @title This is the deployment script for the Application Coin ERC20.
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett
 * @dev This contract deploys the Application Coin ERC20.
 */

contract ApplicationERC20Script is Script {
    function setUp() public {}

    /**
     * @dev This function runs the script
     */
    function run() public {
        vm.startBroadcast(vm.envUint("QUORRA_PRIVATE_KEY"));

        new ApplicationERC20("Frankenstein Coin", "FRANK", vm.envAddress("APPLICATION_APP_MANAGER"), vm.envAddress("APPLICATION_ERC20_HANDLER_ADDRESS"));
        // Register the token with the application's app manager
        IAppManager(vm.envAddress("APPLICATION_APP_MANAGER")).registerToken("Frankenstein Coin", address(this));
        vm.stopBroadcast();
    }
}
