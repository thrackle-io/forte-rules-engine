// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {RulesEngineStoragePositionLib as lib} from "src/engine/RulesEngineStoragePositionLib.sol";
import "src/engine/AccessModifiers.sol";
import "src/engine/RulesEngineStorageStructure.sol";
import "src/engine/facets/FacetUtils.sol";
import "src/engine/RulesEngineEvents.sol";


abstract contract FacetCommonImports is AccessModifiers {}
