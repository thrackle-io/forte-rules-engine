// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {RulesEngineDiamondLib as DiamondLib, RulesEngineDiamondStorage, FacetCut} from "src/engine/RulesEngineDiamondLib.sol";
import {ERC173} from "diamond-std/implementations/ERC173/ERC173.sol";

/// When no function exists for function called
error FunctionNotFound(bytes4 _functionSelector);
error FacetHasNoCodeOrHasBeenDestroyed();

/**
 * This is used in diamond constructor
 * more arguments are added to this struct
 * this avoids stack too deep errors
 */
struct RulesEngineDiamondArgs {
    address init;
    bytes initCalldata;
}

/**
 * @title Asset Handler Diamond Contract
 * @author @ShaneDuncan602
 * @dev The proxy contract of the diamond pattern. Responsible for handling 
 * the token rule configuration and communication with the application and protocol.
 * @notice The diamond inherits ERC173 for ownership management.
 */
contract RulesEngineDiamond is ERC173 {
    event EngineDeployed();
    
    /**
     * @dev constructor creates facets for the diamond at deployment
     * @param diamondCut Array of Facets to be created at deployment
     * @param args Arguments for the Facets Position and Addresses
     */
    constructor(FacetCut[] memory diamondCut, RulesEngineDiamondArgs memory args) payable {
        DiamondLib.diamondCut(diamondCut, args.init, args.initCalldata);
        emit EngineDeployed();
    }

    /**
     * @dev Function finds facet for function that is called and execute the function if a facet is found and return any value.
     */
    fallback() external payable {
        RulesEngineDiamondStorage storage ds;
        bytes32 position = DiamondLib.DIAMOND_CUT_STORAGE;
        // get diamond storage
        assembly {
            ds.slot := position
        }

        // get facet from function selector
        address facet = ds.facetAddressAndSelectorPosition[msg.sig].facetAddress;
        if (facet == address(0)) {
            revert FunctionNotFound(msg.sig);
        }

        if (facet.code.length == 0) revert FacetHasNoCodeOrHasBeenDestroyed();

        // Execute external function from facet using delegatecall and return any value.
        assembly {
            // copy function selector and any arguments
            calldatacopy(0, 0, calldatasize())

            // execute function call using the facet
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)

            // get any return value
            returndatacopy(0, 0, returndatasize())

            // return any return value or error back to the caller
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
