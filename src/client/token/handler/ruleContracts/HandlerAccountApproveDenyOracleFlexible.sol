// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/client/token/handler/ruleContracts/HandlerRuleContractsCommonImports.sol";
import {IAssetHandlerErrors} from "src/common/IErrors.sol";

uint8 constant MAX_ORACLE_FLEXIBLE_RULES = 10;

/**
 * @title Handler Account Approve Deny Oracle Flexible
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev Setters and getters for the rule in the handler. Meant to be inherited by a handler
 * facet to easily support the rule.
 */

contract HandlerAccountApproveDenyOracleFlexible is RuleAdministratorOnly, ActionTypesArray, ITokenHandlerEvents, IAssetHandlerErrors {
    /// Rule Setters and Getters

    /**
     * @dev Set the AccountApproveDenyOracleFlexible. Restricted to rule administrators only.
     * @notice that setting a rule will automatically activate it.
     * @param _actions the action types
     * @param _ruleId Rule Id to set
     */
    function setAccountApproveDenyOracleFlexibleId(ActionTypes[] calldata _actions, uint32 _ruleId) external ruleAdministratorOnly(lib.handlerBaseStorage().appManager) {
        IRuleProcessor(lib.handlerBaseStorage().ruleProcessor).validateAccountApproveDenyOracleFlexible(_actions, _ruleId);
        for (uint i; i < _actions.length; ++i) {
            setAccountApproveDenyOracleFlexibleIdUpdate(_actions[i], _ruleId);
            emit AD1467_ApplicationHandlerActionApplied(ACCOUNT_APPROVE_DENY_ORACLE_FLEXIBLE, _actions[i], _ruleId);
        }
    }

    /**
     * @dev Set the AccountApproveDenyOracleFlexible suite. This function works differently since the rule allows multiples per action. The actions are repeated to account for multiple oracle rules per action. Restricted to rule administrators only.
     * @notice that setting a rule will automatically activate it.
     * @notice This function does not check that the array length is greater than zero to allow for clearing out of the action types data
     * @param _actions actions to have the rule applied to
     * @param _ruleIds Rule Id corresponding to the actions
     */
    function setAccountApproveDenyOracleFlexibleIdFull(ActionTypes[] calldata _actions, uint32[] calldata _ruleIds) external ruleAdministratorOnly(lib.handlerBaseStorage().appManager) {
        if (_actions.length != _ruleIds.length) revert InputArraysMustHaveSameLength();
        clearAccountApproveDenyOracleFlexible();
        for (uint i; i < _actions.length; ++i) {
            // slither-disable-next-line calls-loop
            IRuleProcessor(lib.handlerBaseStorage().ruleProcessor).validateAccountApproveDenyOracleFlexible(createActionTypesArray(_actions[i]), _ruleIds[i]);
            setAccountApproveDenyOracleFlexibleIdUpdate(_actions[i], _ruleIds[i]);
        }
        emit AD1467_ApplicationHandlerActionAppliedFull(ACCOUNT_APPROVE_DENY_ORACLE_FLEXIBLE, _actions, _ruleIds);
    }

    /**
     * @dev Clear the rule data structure
     */
    function clearAccountApproveDenyOracleFlexible() internal {
        AccountApproveDenyOracleFlexibleS storage data = lib.accountApproveDenyOracleFlexibleStorage();
        for (uint i; i <= lib.handlerBaseStorage().lastPossibleAction;) {
            delete data.accountApproveDenyOracleFlexible[ActionTypes(i)];
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @dev Set the AccountApproveDenyOracleFlexible.
     * @notice that setting a rule will automatically activate it.
     * @param _action the action type to set the rule
     * @param _ruleId Rule Id to set
     */
    // slither-disable-next-line calls-loop
    function setAccountApproveDenyOracleFlexibleIdUpdate(ActionTypes _action, uint32 _ruleId) internal {
        AccountApproveDenyOracleFlexibleS storage data = lib.accountApproveDenyOracleFlexibleStorage();
        if (data.accountApproveDenyOracleFlexible[_action].length >= MAX_ORACLE_FLEXIBLE_RULES) {
            revert AccountApproveDenyOraclesPerAssetLimitReached();
        }
        Rule memory newOracleRule = Rule(_ruleId, true);
        // check to see if the oracle rule is already in the array
        (uint256 index, bool found) = _doesAccountApproveDenyOracleFlexibleIdExist(_action, _ruleId);
        if (found) {
            // replace the existing rule
            data.accountApproveDenyOracleFlexible[_action][index] = newOracleRule;
        } else {
            // append the new rule
            data.accountApproveDenyOracleFlexible[_action].push(newOracleRule);
        }
    }

    /**
     * @dev Check to see if the oracle rule already exists in the array. If it does, return the index
     * @param _action the corresponding action
     * @param _ruleId the rule's identifier
     * @return _index the index of the found oracle rule
     * @return _found true if found
     */
    function _doesAccountApproveDenyOracleFlexibleIdExist(ActionTypes _action, uint32 _ruleId) internal view returns (uint256 _index, bool _found) {
        AccountApproveDenyOracleFlexibleS storage data = lib.accountApproveDenyOracleFlexibleStorage();
        for (uint i; i < data.accountApproveDenyOracleFlexible[_action].length; ++i) {
            if (data.accountApproveDenyOracleFlexible[_action][i].ruleId == _ruleId) {
                _index = i;
                _found = true;
                break;
            }
        }
        return (_index, _found);
    }

    /**
     * @dev enable/disable rule. Disabling a rule will save gas on transfer transactions.
     * @param _actions the action types
     * @param _on boolean representing if a rule must be checked or not.
     * @param ruleId the id of the rule to activate/deactivate
     */

    function activateAccountApproveDenyOracleFlexible(ActionTypes[] calldata _actions, bool _on, uint32 ruleId) external ruleAdministratorOnly(lib.handlerBaseStorage().appManager) {
        for (uint i; i < _actions.length; ++i) {
            mapping(ActionTypes => Rule[]) storage accountApproveDenyOracleFlexible = lib.accountApproveDenyOracleFlexibleStorage().accountApproveDenyOracleFlexible;
            for (uint256 ruleIndex; ruleIndex < accountApproveDenyOracleFlexible[_actions[i]].length; ++ruleIndex) {
                if (accountApproveDenyOracleFlexible[_actions[i]][ruleIndex].ruleId == ruleId) {
                    accountApproveDenyOracleFlexible[_actions[i]][ruleIndex].active = _on;
                }
            }
        }

        if (_on) {
            emit AD1467_ApplicationHandlerActionActivated(ACCOUNT_APPROVE_DENY_ORACLE_FLEXIBLE, _actions, ruleId);
        } else {
            emit AD1467_ApplicationHandlerActionDeactivated(ACCOUNT_APPROVE_DENY_ORACLE_FLEXIBLE, _actions, ruleId);
        }
    }

    /**
     * @dev Retrieve the account approve deny oracle flexible rule id
     * @param _action the action type
     * @return oracleRuleId
     */
    function getAccountApproveDenyOracleFlexibleIds(ActionTypes _action) external view returns (uint32[] memory) {
        mapping(ActionTypes => Rule[]) storage accountApproveDenyOracleFlexible = lib.accountApproveDenyOracleFlexibleStorage().accountApproveDenyOracleFlexible;
        uint32[] memory ruleIds = new uint32[](accountApproveDenyOracleFlexible[_action].length);
        for (uint256 ruleIndex; ruleIndex < accountApproveDenyOracleFlexible[_action].length; ++ruleIndex) {
            ruleIds[ruleIndex] = accountApproveDenyOracleFlexible[_action][ruleIndex].ruleId;
        }
        return ruleIds;
    }

    /**
     * @dev Tells you if the Accont Approve Deny Oracle Flexible Rule is active or not.
     * @param _action the action type
     * @param ruleId the id of the rule to check
     * @return boolean representing if the rule is active
     */
    function isAccountApproveDenyOracleFlexibleActive(ActionTypes _action, uint32 ruleId) external view returns (bool) {
        mapping(ActionTypes => Rule[]) storage accountApproveDenyOracleFlexible = lib.accountApproveDenyOracleFlexibleStorage().accountApproveDenyOracleFlexible;
        for (uint256 ruleIndex; ruleIndex < accountApproveDenyOracleFlexible[_action].length; ++ruleIndex) {
            if (accountApproveDenyOracleFlexible[_action][ruleIndex].ruleId == ruleId) {
                return accountApproveDenyOracleFlexible[_action][ruleIndex].active;
            }
        }
        return false;
    }

    /**
     * @dev Removes an account approve deny oracle flexible rule from the list.
     * @param _actions the action types
     * @param ruleId the id of the rule to remove
     */
    function removeAccountApproveDenyOracleFlexible(ActionTypes[] calldata _actions, uint32 ruleId) external ruleAdministratorOnly(lib.handlerBaseStorage().appManager) {
        mapping(ActionTypes => Rule[]) storage accountApproveDenyOracleFlexible = lib.accountApproveDenyOracleFlexibleStorage().accountApproveDenyOracleFlexible;
        for (uint i; i < _actions.length; ++i) {
            Rule memory lastId = accountApproveDenyOracleFlexible[_actions[i]][accountApproveDenyOracleFlexible[_actions[i]].length - 1];
            if (ruleId != lastId.ruleId) {
                uint index = 0;
                for (uint256 ruleIndex; ruleIndex < accountApproveDenyOracleFlexible[_actions[i]].length; ++ruleIndex) {
                    if (accountApproveDenyOracleFlexible[_actions[i]][ruleIndex].ruleId == ruleId) {
                        index = ruleIndex;
                        break;
                    }
                }
                accountApproveDenyOracleFlexible[_actions[i]][index] = lastId;
            }

            accountApproveDenyOracleFlexible[_actions[i]].pop();
        }
    }
}
