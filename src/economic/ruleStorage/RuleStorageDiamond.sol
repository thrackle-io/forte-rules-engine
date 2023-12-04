// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {RuleStorageDiamondLib as DiamondLib, DiamondCutStorage, FacetCut} from "./RuleStorageDiamondLib.sol";
import {IRuleStorageDiamondEvents} from "../../interfaces/IEvents.sol";
// When no function exists for function called
error FunctionNotFound(bytes4 _functionSelector);

// This is used in diamond constructor
// more arguments are added to this struct
// this avoids stack too deep errors
struct RuleStorageDiamondArgs {
    address init;
    bytes initCalldata;
}

/**
 *@title Rule Storage Diamond
 * @author @oscarsernarosero, built on top of Nick Mudge implementation.
 * @dev main contract of the Rule diamond pattern. Mainly responsible
 * for storing the diamnond-pattern logic and binding together the different facets.
 */
contract RuleStorageDiamond is IRuleStorageDiamondEvents {
    /**
     * @dev constructor creates facets for the diamond at deployment
     * @param diamondCut Array of Facets to be created at deployment
     * @param args Arguments for the Facets Position and Addresses
     */
    constructor(FacetCut[] memory diamondCut, RuleStorageDiamondArgs memory args) payable {
        DiamondLib.diamondCut(diamondCut, args.init, args.initCalldata);
        emit RuleStorageDiamondDeployed(address(this));
    }

    /**
     * @dev Function finds facet for function that is called and execute the function if a facet is found and return any value.
     */
    fallback() external payable {
        DiamondCutStorage storage ds;
        bytes32 position = DiamondLib.DIAMOND_CUT_STORAGE_POSITION;
        // get diamond storage
        assembly {
            ds.slot := position
        }

        /// get facet from function selector
        address facet = ds.facetAddressAndSelectorPosition[msg.sig].facetAddress;
        if (facet == address(0)) {
            revert FunctionNotFound(msg.sig);
        }

        // Execute external function from facet using delegatecall and return any value.
        assembly {
            /// copy function selector and any arguments
            calldatacopy(0, 0, calldatasize())

            /// execute function call using the facet
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)

            // get any return value
            returndatacopy(0, 0, returndatasize())

            /// return any return value or error back to the caller
            switch result
            case 0 {
                revert(0, returndatasize())
            }
            default {
                return(0, returndatasize())
            }
        }
    }

    /**
     *@dev Function for empty calldata
     */
    receive() external payable {}
}