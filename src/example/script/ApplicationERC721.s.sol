// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.17;

import "forge-std/Script.sol";
import "src/example/ApplicationERC721.sol";
import "src/application/IAppManager.sol";

/**
 * @title This is the deployment script for the Application NFT.
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett
 * @dev This contract deploys the Application NFT ERC721. It will also register the token with the application's app manager
 */

contract ApplicationERC721Script is Script {
    function setUp() public {}

    /**
     * @dev This function runs the script
     */
    function run() public {
        vm.startBroadcast(vm.envUint("QUORRA_PRIVATE_KEY"));

        new ApplicationERC721("Frankenstein", "FRANK", vm.envAddress("APPLICATION_APP_MANAGER"), vm.envAddress("APPLICATION_ERC20_HANDLER_ADDRESS"), vm.envString("APPLICATION_ERC721_URI_1"));
        // Register the token with the application's app manager
        IAppManager(vm.envAddress("APPLICATION_APP_MANAGER")).registerToken("Frankenstein", address(this));
        vm.stopBroadcast();
    }
}
