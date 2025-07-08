// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {RulesEngineStoragePositionLib as lib} from "src/engine/RulesEngineStoragePositionLib.sol";
import "src/engine/AccessModifiers.sol";
import "src/engine/RulesEngineStorageStructure.sol";
import "src/engine/facets/FacetUtils.sol";
import "src/engine/RulesEngineEvents.sol";
import "src/engine/RulesEngineErrors.sol";

/**
 * @title Facet Common Imports
 * @dev This abstract contract consolidates common imports and dependencies for facets in the Rules Engine.
 *      It ensures consistent access to shared libraries, modifiers, storage structures, utilities, events, and errors.
 * @notice This contract is intended to be inherited by other facet contracts to streamline their implementation.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
abstract contract FacetCommonImports is AccessModifiers {
    uint256 constant MAX_LOOP = 10_000;
}
