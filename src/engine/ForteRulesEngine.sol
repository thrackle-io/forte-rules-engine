// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {RulesEngineDiamondLib as DiamondLib, RulesEngineDiamondStorage, FacetCut} from "src/engine/RulesEngineDiamondLib.sol";
import {ERC173} from "diamond-std/implementations/ERC173/ERC173.sol";

/// When no function exists for function called
error FunctionNotFound(bytes4 _functionSelector);
error FacetHasNoCodeOrHasBeenDestroyed();
error BatchError(bytes innerError);

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
 * @title Rules Engine Diamond Contract
 * @dev This contract implements the diamond proxy pattern for the Rules Engine. It is responsible for managing facets,
 *      handling token rule configurations, and facilitating communication between the application and protocol.
 * @notice The diamond inherits ERC173 for ownership management and supports batch operations for efficiency.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220, @Palmerg4
 */
contract ForteRulesEngine is ERC173 {
    event EngineDeployed();

    /**
     * @notice Constructor for the Rules Engine Diamond.
     * @dev Initializes the diamond by performing a diamond cut operation to set up facets.
     * @param diamondCut Array of facets to be created at deployment.
     * @param args Arguments for the facets' initialization, including the initializer address and calldata.
     */
    constructor(FacetCut[] memory diamondCut, RulesEngineDiamondArgs memory args) payable {
        DiamondLib.diamondCut(diamondCut, args.init, args.initCalldata);
        emit EngineDeployed();
    }

    /**
     * @notice Fallback function to handle calls to functions not explicitly defined in the diamond.
     * @dev Finds the appropriate facet for the function selector and delegates the call to it.
     */
    fallback() external payable {
        _callDiamond();
    }

    /// @notice Allows batched call to self (this contract). Taken from BoringSolidity's Boring Batchable and modified to not be payable.
    /// @param calls An array of inputs for each call.
    /// @param revertOnFail If True then reverts after a failed call and stops doing further calls.
    // F1: External is ok here because this is the batch function, adding it to a batch makes no sense
    // F2: Calls in the batch may be payable, delegatecall operates in the same context, so each call in the batch has access to msg.value
    // C3: The length of the loop is fully under user control, so can't be exploited
    // C7: Delegatecall is only used on the same contract, so it's safe
    /**
     * @notice Allows batched calls to the diamond contract. Taken from BoringSolidity's Boring Batchable and modified to not be payable.
     * @dev Executes multiple calls in a single transaction. If `revertOnFail` is true, the batch stops on the first failure.
     * @param calls An array of calldata for each call.
     * @param revertOnFail If true, reverts the transaction on the first failed call.
     * F1: External is ok here because this is the batch function, adding it to a batch makes no sense
     * F2: Calls in the batch may be payable, delegatecall operates in the same context, so each call in the batch has access to msg.value
     * C3: The length of the loop is fully under user control, so can't be exploited
     * C7: Delegatecall is only used on the same contract, so it's safe
     */
    function batch(bytes[] calldata calls, bool revertOnFail) external {
        for (uint256 i = 0; i < calls.length; i++) {
            (bool success, bytes memory result) = address(this).delegatecall(calls[i]);
            if (!success && revertOnFail) {
                _getRevertMsg(result);
            }
        }
    }

    /**
     * @notice Internal function to handle fallback calls.
     * @dev Finds the facet for the function selector and delegates the call to it. Reverts if no facet is found or the facet has no code.
     */
    function _callDiamond() internal {
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
     * @notice Helper function to extract a revert message from a failed call.
     * @dev If the returned data is malformed or not correctly ABI-encoded, this function reverts with a `BatchError`.
     * @param _returnData The returned data from the failed call.
     */
    function _getRevertMsg(bytes memory _returnData) internal pure {
        // If the _res length is less than 68, then
        // the transaction failed with custom error or silently (without a revert message)
        if (_returnData.length < 68) revert BatchError(_returnData);

        assembly {
            // Slice the sighash.
            _returnData := add(_returnData, 0x04)
        }
        revert(abi.decode(_returnData, (string))); // All that remains is the revert string
    }

    /**
     * @notice Fallback function for empty calldata.
     * @dev Allows the contract to receive Ether.
     */
    receive() external payable {}
}
