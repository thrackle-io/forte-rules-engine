// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "../../liquidity/ProtocolAMMHandler.sol";

/**
 * @title Example ApplicationAMMHandler Contract
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett
 * @dev This contract performs all the rule checks related to the the AMM that implements it.
 * @notice Any rule checks may be updated by modifying this contract and redeploying.
 */

contract ApplicationAMMHandler is ProtocolAMMHandler {
    /**
     * @dev Constructor sets the App Manager and token rule router Address
     * @param _appManagerAddress App Manager Address
     * @param _ruleProcessorProxyAddress Rule Router Proxy Address
     * @param _assetAddress address of the congtrolling address
     */ constructor(address _appManagerAddress, address _ruleProcessorProxyAddress,address _assetAddress) ProtocolAMMHandler(_appManagerAddress, _ruleProcessorProxyAddress,_assetAddress) {}
}