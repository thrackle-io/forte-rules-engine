// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {DiamondLoupeFacet} from "diamond-std/core/DiamondLoupe/DiamondLoupeFacet.sol";
import {ERC173Facet} from "diamond-std/implementations/ERC173/ERC173Facet.sol";

/**
 * @title NativeFacet
 * @dev This contract integrates core functionalities for managing and interacting with a diamond contract.
 *      It includes implementations for diamond cutting, diamond loupe, and ownership management.
 *      The code is based on Nick Mudge's sample contracts and is tailored for use in the Rules Engine.
 * @notice This contract is intended to be used as a foundational facet for diamond contracts.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract NativeFacet is DiamondLoupeFacet, ERC173Facet {}