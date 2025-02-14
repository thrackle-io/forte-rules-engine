// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetCommonImports.sol";
import "src/engine/facets/RulesEngineAdminRolesFacet.sol";

/**
 * @title Rules Engine Data Facet
 * @author @ShaneDuncan602 
 * @dev This contract serves as the primary data facet for the rules engine. It is responsible for mutating and serving all the policy data.
 * @notice Data facet for the Rules Engine
 */
contract RulesEngineDataFacet2 is FacetCommonImports {

    function getRule(uint256 _policyId, uint256 _ruleId) public view returns (RuleStorageSet memory) {
        return lib.getRuleStorage().ruleStorageSets[_ruleId];
    }
}