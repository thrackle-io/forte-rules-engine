// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "../common/HandlerUtils.sol";
import "../ruleContracts/HandlerBase.sol";
import "../ruleContracts/HandlerAdminMinTokenBalance.sol";
import "./ERC20TaggedRuleFacet.sol";
import "./ERC20NonTaggedRuleFacet.sol";
import "../../../application/IAppManager.sol";
import {ICommonApplicationHandlerEvents} from "../../../../common/IEvents.sol";
import {ERC165Lib} from "diamond-std/implementations/ERC165/ERC165Lib.sol";
import {IHandlerDiamondErrors} from "../../../../common/IErrors.sol";
import "diamond-std/implementations/ERC173/ERC173.sol";

contract ERC20HandlerMainFacet is HandlerBase, HandlerAdminMinTokenBalance, HandlerUtils, ICommonApplicationHandlerEvents, IHandlerDiamondErrors, ERC173 {

    /**
     * @dev Initializer params
     * @param _ruleProcessorProxyAddress of the protocol's Rule Processor contract.
     * @param _appManagerAddress address of the application AppManager.
     * @param _assetAddress address of the controlling asset.
     */
    function initialize(address _ruleProcessorProxyAddress, address _appManagerAddress, address _assetAddress) external onlyOwner {
        InitializedS storage ini = lib.initializedStorage();
        if(ini.initialized) revert AlreadyInitialized();
        HandlerBaseS storage data = lib.handlerBaseStorage();
        if (_appManagerAddress == address(0) || _ruleProcessorProxyAddress == address(0) || _assetAddress == address(0)) 
            revert ZeroAddress();
        data.appManager = _appManagerAddress;
        data.ruleProcessor = _ruleProcessorProxyAddress;
        data.assetAddress = _assetAddress;
        ERC165Lib.setSupportedInterface(type(IAdminMinTokenBalanceCapable).interfaceId, true);
        ini.initialized = true;
        callAnotherFacet(0xf2fde38b, abi.encodeWithSignature("transferOwnership(address)",_assetAddress));
    }

    /**
     * @dev This function is the one called from the contract that implements this handler. It's the entry point.
     * @param balanceFrom token balance of sender address
     * @param balanceTo token balance of recipient address
     * @param _from sender address
     * @param _to recipient address
     * @param _sender the address triggering the contract action
     * @param _amount number of tokens transferred
     * @return true if all checks pass
     */
    function checkAllRules(uint256 balanceFrom, uint256 balanceTo, address _from, address _to, address _sender, uint256 _amount) external onlyOwner returns (bool) {
        HandlerBaseS storage handlerBaseStorage = lib.handlerBaseStorage();
        bool isFromBypassAccount = IAppManager(handlerBaseStorage.appManager).isRuleBypassAccount(_from);
        bool isToBypassAccount = IAppManager(handlerBaseStorage.appManager).isRuleBypassAccount(_to);
        ActionTypes action = determineTransferAction(_from, _to, _sender);
        // All transfers to treasury account are allowed
        if (!IAppManager(handlerBaseStorage.appManager).isTreasury(_to)) {
            /// standard rules do not apply when either to or from is an admin
            if (!isFromBypassAccount && !isToBypassAccount) {
                IAppManager(handlerBaseStorage.appManager).checkApplicationRules(address(msg.sender), _from, _to, _amount,  0, 0, action, HandlerTypes.ERC20HANDLER); 
                callAnotherFacet(
                    0x36bd6ea7, 
                    abi.encodeWithSignature(
                        "checkTaggedAndTradingRules(uint256,uint256,address,address,uint256,uint8)",
                        balanceFrom, 
                        balanceTo, 
                        _from, 
                        _to, 
                        _amount, 
                        action
                    )
                );
                callAnotherFacet(
                    0x6f43d91d, 
                    abi.encodeWithSignature(
                        "checkNonTaggedRules(address,address,uint256,uint8)",
                        _from, 
                        _to, 
                        _amount, 
                        action
                    )
                );
            } else if (lib.adminMinTokenBalanceStorage().adminMinTokenBalance[action].active && isFromBypassAccount) {
                IRuleProcessor(lib.handlerBaseStorage().ruleProcessor).checkAdminMinTokenBalance(lib.adminMinTokenBalanceStorage().adminMinTokenBalance[action].ruleId, balanceFrom, _amount);
                emit RulesBypassedViaRuleBypassAccount(address(msg.sender), lib.handlerBaseStorage().appManager); 
            }
            
       }
        return true;
    }

    

    
}