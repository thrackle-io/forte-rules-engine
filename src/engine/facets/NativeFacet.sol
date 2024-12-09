// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "diamond-std/core/DiamondCut/DiamondCutFacet.sol";
import {DiamondLoupeFacet} from "diamond-std/core/DiamondLoupe/DiamondLoupeFacet.sol";
import {ERC165Facet} from "diamond-std/implementations/ERC165/ERC165Facet.sol";
import {ERC173Facet} from "diamond-std/implementations/ERC173/ERC173Facet.sol";

/**
 * @title NativeFacet
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 * @dev The code for this comes from Nick Mudge's sample contracts. This contains all the implementations to be applied to each diamond.
 */
contract NativeFacet is DiamondCutFacet, DiamondLoupeFacet, ERC165Facet, ERC173Facet {

}
