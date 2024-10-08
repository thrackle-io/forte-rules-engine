// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/client/token/handler/ruleContracts/HandlerRuleContractsCommonImports.sol";
import {IAssetHandlerErrors} from "src/common/IErrors.sol";

uint8 constant MAX_ORACLE_RULES = 10;

/**
 * @title Handler Account Approve Deny Oracle
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev Setters and getters for the rule in the handler. Meant to be inherited by a handler
 * facet to easily support the rule.
 */

contract HandlerAccountApproveDenyOracle is RuleAdministratorOnly, ActionTypesArray, ITokenHandlerEvents, IAssetHandlerErrors {
    /// Rule Setters and Getters

    /**
     * @dev Set the AccountApproveDenyOracle. Restricted to rule administrators only.
     * @notice that setting a rule will automatically activate it.
     * @param _actions the action types
     * @param _ruleId Rule Id to set
     */
    function setAccountApproveDenyOracleId(ActionTypes[] calldata _actions, uint32 _ruleId) external ruleAdministratorOnly(lib.handlerBaseStorage().appManager) {
        IRuleProcessor(lib.handlerBaseStorage().ruleProcessor).validateAccountApproveDenyOracle(_actions, _ruleId);
        for (uint i; i < _actions.length; ++i) {
            setAccountApproveDenyOracleIdUpdate(_actions[i], _ruleId);
            emit AD1467_ApplicationHandlerActionApplied(ACCOUNT_APPROVE_DENY_ORACLE, _actions[i], _ruleId);
        }
    }

    /**
     * @dev Set the AccountApproveDenyOracle suite. This function works differently since the rule allows multiples per action. The actions are repeated to account for multiple oracle rules per action. Restricted to rule administrators only.
     * @notice that setting a rule will automatically activate it.
     * @notice This function does not check that the array length is greater than zero to allow for clearing out of the action types data
     * @param _actions actions to have the rule applied to
     * @param _ruleIds Rule Id corresponding to the actions
     */
    function setAccountApproveDenyOracleIdFull(ActionTypes[] calldata _actions, uint32[] calldata _ruleIds) external ruleAdministratorOnly(lib.handlerBaseStorage().appManager) {
        if (_actions.length != _ruleIds.length) revert InputArraysMustHaveSameLength();
        clearAccountApproveDenyOracle();
        for (uint i; i < _actions.length; ++i) {
            // slither-disable-next-line calls-loop
            IRuleProcessor(lib.handlerBaseStorage().ruleProcessor).validateAccountApproveDenyOracle(createActionTypesArray(_actions[i]), _ruleIds[i]);
            setAccountApproveDenyOracleIdUpdate(_actions[i], _ruleIds[i]);
        }
        emit AD1467_ApplicationHandlerActionAppliedFull(ACCOUNT_APPROVE_DENY_ORACLE, _actions, _ruleIds);
    }

    /**
     * @dev Clear the rule data structure
     */
    function clearAccountApproveDenyOracle() internal {
        AccountApproveDenyOracleS storage data = lib.accountApproveDenyOracleStorage();
        for (uint i; i <= lib.handlerBaseStorage().lastPossibleAction;) {
            delete data.accountApproveDenyOracle[ActionTypes(i)];
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @dev Set the AccountApproveDenyOracle.
     * @notice that setting a rule will automatically activate it.
     * @param _action the action type to set the rule
     * @param _ruleId Rule Id to set
     */
    // slither-disable-next-line calls-loop
    function setAccountApproveDenyOracleIdUpdate(ActionTypes _action, uint32 _ruleId) internal {
        AccountApproveDenyOracleS storage data = lib.accountApproveDenyOracleStorage();
        if (data.accountApproveDenyOracle[_action].length >= MAX_ORACLE_RULES) {
            revert AccountApproveDenyOraclesPerAssetLimitReached();
        }
        Rule memory newOracleRule = Rule(_ruleId, true);
        // check to see if the oracle rule is already in the array
        (uint256 index, bool found) = _doesAccountApproveDenyOracleIdExist(_action, _ruleId);
        if (found) {
            // replace the existing rule
            data.accountApproveDenyOracle[_action][index] = newOracleRule;
        } else {
            // append the new rule
            data.accountApproveDenyOracle[_action].push(newOracleRule);
        }
    }

    /**
     * @dev Check to see if the oracle rule already exists in the array. If it does, return the index
     * @param _action the corresponding action
     * @param _ruleId the rule's identifier
     * @return _index the index of the found oracle rule
     * @return _found true if found
     */
    function _doesAccountApproveDenyOracleIdExist(ActionTypes _action, uint32 _ruleId) internal view returns (uint256 _index, bool _found) {
        AccountApproveDenyOracleS storage data = lib.accountApproveDenyOracleStorage();
        for (uint i; i < data.accountApproveDenyOracle[_action].length; ++i) {
            if (data.accountApproveDenyOracle[_action][i].ruleId == _ruleId) {
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

    function activateAccountApproveDenyOracle(ActionTypes[] calldata _actions, bool _on, uint32 ruleId) external ruleAdministratorOnly(lib.handlerBaseStorage().appManager) {
        for (uint i; i < _actions.length; ++i) {
            mapping(ActionTypes => Rule[]) storage accountApproveDenyOracle = lib.accountApproveDenyOracleStorage().accountApproveDenyOracle;
            for (uint256 ruleIndex; ruleIndex < accountApproveDenyOracle[_actions[i]].length; ++ruleIndex) {
                if (accountApproveDenyOracle[_actions[i]][ruleIndex].ruleId == ruleId) {
                    accountApproveDenyOracle[_actions[i]][ruleIndex].active = _on;
                }
            }
        }

        if (_on) {
            emit AD1467_ApplicationHandlerActionActivated(ACCOUNT_APPROVE_DENY_ORACLE, _actions, ruleId);
        } else {
            emit AD1467_ApplicationHandlerActionDeactivated(ACCOUNT_APPROVE_DENY_ORACLE, _actions, ruleId);
        }
    }

    /**
     * @dev Retrieve the account approve deny oracle rule id
     * @param _action the action type
     * @return oracleRuleId
     */
    function getAccountApproveDenyOracleIds(ActionTypes _action) external view returns (uint32[] memory) {
        mapping(ActionTypes => Rule[]) storage accountApproveDenyOracle = lib.accountApproveDenyOracleStorage().accountApproveDenyOracle;
        uint32[] memory ruleIds = new uint32[](accountApproveDenyOracle[_action].length);
        for (uint256 ruleIndex; ruleIndex < accountApproveDenyOracle[_action].length; ++ruleIndex) {
            ruleIds[ruleIndex] = accountApproveDenyOracle[_action][ruleIndex].ruleId;
        }
        return ruleIds;
    }

    /**
     * @dev Tells you if the Accont Approve Deny Oracle Rule is active or not.
     * @param _action the action type
     * @param ruleId the id of the rule to check
     * @return boolean representing if the rule is active
     */
    function isAccountApproveDenyOracleActive(ActionTypes _action, uint32 ruleId) external view returns (bool) {
        mapping(ActionTypes => Rule[]) storage accountApproveDenyOracle = lib.accountApproveDenyOracleStorage().accountApproveDenyOracle;
        for (uint256 ruleIndex; ruleIndex < accountApproveDenyOracle[_action].length; ++ruleIndex) {
            if (accountApproveDenyOracle[_action][ruleIndex].ruleId == ruleId) {
                return accountApproveDenyOracle[_action][ruleIndex].active;
            }
        }
        return false;
    }

    /**
     * @dev Removes an account approve deny oracle rule from the list.
     * @param _actions the action types
     * @param ruleId the id of the rule to remove
     */
    function removeAccountApproveDenyOracle(ActionTypes[] calldata _actions, uint32 ruleId) external ruleAdministratorOnly(lib.handlerBaseStorage().appManager) {
        mapping(ActionTypes => Rule[]) storage accountApproveDenyOracle = lib.accountApproveDenyOracleStorage().accountApproveDenyOracle;
        for (uint i; i < _actions.length; ++i) {
            Rule memory lastId = accountApproveDenyOracle[_actions[i]][accountApproveDenyOracle[_actions[i]].length - 1];
            if (ruleId != lastId.ruleId) {
                uint index = 0;
                for (uint256 ruleIndex; ruleIndex < accountApproveDenyOracle[_actions[i]].length; ++ruleIndex) {
                    if (accountApproveDenyOracle[_actions[i]][ruleIndex].ruleId == ruleId) {
                        index = ruleIndex;
                        break;
                    }
                }
                accountApproveDenyOracle[_actions[i]][index] = lastId;
            }

            accountApproveDenyOracle[_actions[i]].pop();
        }
    }
}
