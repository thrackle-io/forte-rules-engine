// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "src/example/application/ApplicationHandler.sol";
import {ApplicationERC721AdminOrOwnerMint} from "src/example/ERC721/ApplicationERC721AdminOrOwnerMint.sol";
import "src/example/ERC721/upgradeable/ApplicationERC721UProxy.sol";
import {ApplicationAppManager} from "src/example/application/ApplicationAppManager.sol";
import "./DeployBase.s.sol";

/**
 * @title Application Deploy 04 Application Non-Fungible Token Upgradeable Script
 * @author @VoR0220, @ShaneDuncan, @TJEverett, @GordanPalmer
 * @dev This script will deploy an ERC721 non-fungible token and Handler.
 * @notice Deploys an application ERC721 non-fungible token and Handler..
 * ** Requires .env variables to be set with correct addresses and Protocol Diamond addresses **
 * Deploy Scripts:
 * forge script example/script/Application_Deploy_01_AppManager.s.sol --ffi --rpc-url $RPC_URL --broadcast -vvvv
 * forge script example/script/Application_Deploy_02_ApplicationFT1.s.sol --ffi --rpc-url $RPC_URL --broadcast -vvvv
 * forge script example/script/Application_Deploy_03_ApplicationFT2.s.sol --ffi --rpc-url $RPC_URL --broadcast -vvvv
 * forge script example/script/Application_Deploy_04_ApplicationNFT.s.sol --ffi --rpc-url $RPC_URL --broadcast -vvvv
 * forge script example/script/Application_Deploy_05_Oracle.s.sol --ffi --rpc-url $RPC_URL --broadcast -vvvv
 * forge script example/script/Application_Deploy_06_Pricing.s.sol --ffi --rpc-url $RPC_URL --broadcast -vvvv
 * forge script example/script/Application_Deploy_07_ApplicationAdminRoles.s.sol --ffi --rpc-url $RPC_URL --broadcast -vvvv
 * <<<OPTIONAL>>>
 * forge script example/script/Application_Deploy_08_UpgradeTesting.s.sol --ffi --rpc-url $RPC_URL --broadcast -vvvv
 */

contract ApplicationDeployNFTScript is Script, DeployBase {
    HandlerDiamond applicationNFTHandlerDiamond;
    uint256 privateKey;
    address ownerAddress;
    uint256 appAdminKey;
    address appAdminAddress;

    function setUp() public {}

    function run() public {
        appAdminKey = vm.envUint("APP_ADMIN_PRIVATE_KEY");
        appAdminAddress = vm.envAddress("APP_ADMIN");
        vm.startBroadcast(appAdminKey);
        /// Retrieve the App Manager from previous script
        ApplicationAppManager applicationAppManager = ApplicationAppManager(vm.envAddress("APPLICATION_APP_MANAGER"));
        ApplicationERC721AdminOrOwnerMint nftupgradeable = ApplicationERC721AdminOrOwnerMint(vm.envAddress("APPLICATION_ERC721U_ADDRESS"));
        applicationNFTHandlerDiamond = HandlerDiamond(payable(vm.envAddress("APPLICATION_ERC721U_HANDLER")));
        /// Create NFT Handler
        createERC721HandlerDiamondPt2("Jekyll&Hyde", address(applicationNFTHandlerDiamond));
        ERC721HandlerMainFacet(address(applicationNFTHandlerDiamond)).initialize(vm.envAddress("RULE_PROCESSOR_DIAMOND"), address(applicationAppManager), address(nftupgradeable));
        vm.stopBroadcast();

        /// super admin adds a second app administrator for configuration to bypass peculiarities with initialization and handler connection
        vm.startBroadcast(vm.envUint("DEPLOYMENT_OWNER_KEY"));
        applicationAppManager.addAppAdministrator(vm.envAddress("CONFIG_APP_ADMIN"));
        vm.stopBroadcast();

        /// Connect handler to token 

        /// switch to the config admin
        vm.startBroadcast(vm.envUint("CONFIG_APP_ADMIN_KEY"));
        /// then connect
        nftupgradeable.connectHandlerToToken(address(applicationNFTHandlerDiamond));
        /// Register the tokens with the application's app manager
        applicationAppManager.registerToken("Jekyll&Hyde", address(nftupgradeable));

        vm.stopBroadcast();
    }
}