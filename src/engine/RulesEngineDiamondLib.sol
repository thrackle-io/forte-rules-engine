// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "diamond-std/core/DiamondCut/FacetCut.sol";

error NoSelectorsGivenToAdd();
error NotContractOwner(address _user, address _contractOwner);
error NoSelectorsProvidedForFacetForCut(address _facetAddress);
error CannotAddSelectorsToZeroAddress(bytes4[] _selectors);
error NoBytecodeAtAddress(address _contractAddress, string _message);
error IncorrectFacetCutAction(uint8 _action);
error CannotAddFunctionToDiamondThatAlreadyExists(bytes4 _selector);
error CannotReplaceFunctionsFromFacetWithZeroAddress(bytes4[] _selectors);
error CannotReplaceImmutableFunction(bytes4 _selector);
error CannotReplaceFunctionWithTheSameFunctionFromTheSameFacet(bytes4 _selector);
error CannotReplaceFunctionThatDoesNotExists(bytes4 _selector);
error RemoveFacetAddressMustBeZeroAddress(address _facetAddress);
error CannotRemoveFunctionThatDoesNotExist(bytes4 _selector);
error CannotRemoveImmutableFunction(bytes4 _selector);
error InitializationFunctionReverted(address initializationContractAddress, bytes data);

struct FacetAddressAndSelectorPosition {
    address facetAddress;
    uint16 selectorPosition;
}

struct RulesEngineDiamondStorage {
    /// function selector => facet address and selector position in selectors array
    mapping(bytes4 => FacetAddressAndSelectorPosition) facetAddressAndSelectorPosition;
    bytes4[] selectors;
}

/**
 * @title Rules Engine Diamond Library
 * @dev This library implements the core functionality for managing facets in the diamond proxy pattern. It provides 
 *      functions for adding, replacing, and removing facets, as well as initializing diamond cuts. The library also 
 *      enforces rules for facet management and ensures that only valid operations are performed.
 * @notice This library is a critical component of the Rules Engine, enabling dynamic and modular functionality through 
 *         the diamond proxy pattern.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
library RulesEngineDiamondLib {
    bytes32 constant DIAMOND_CUT_STORAGE = bytes32(uint256(keccak256("diamond-cut.storage")) - 1);

    /**
     * @dev Function for position of rules. Every rule has its own storage.
     * @return ds Data storage for Rule Processor Storage
     */
    function s() internal pure returns (RulesEngineDiamondStorage storage ds) {
        bytes32 position = DIAMOND_CUT_STORAGE;
        assembly {
            ds.slot := position
        }
    }

    event DiamondCut(FacetCut[] _diamondCut, address init, bytes data);

    /**
     * @dev Internal function version of _diamondCut
     * @param _diamondCut Facets Array
     * @param init Address of the contract or facet to execute "data"
     * @param data A function call, including function selector and arguments
     *             calldata is executed with delegatecall on "init"
     */
    function diamondCut(FacetCut[] memory _diamondCut, address init, bytes memory data) internal {
        for (uint256 facetIndex; facetIndex < _diamondCut.length; ++facetIndex) {
            bytes4[] memory functionSelectors = _diamondCut[facetIndex].functionSelectors;
            address facetAddress = _diamondCut[facetIndex].facetAddress;

            if (functionSelectors.length == 0) {
                revert NoSelectorsProvidedForFacetForCut(facetAddress);
            }

            FacetCutAction action = _diamondCut[facetIndex].action;
            if (action == FacetCutAction.Add) {
                addFunctions(facetAddress, functionSelectors);
            } else if (action == FacetCutAction.Replace) {
                replaceFunctions(facetAddress, functionSelectors);
            } else if (action == FacetCutAction.Remove) {
                removeFunctions(facetAddress, functionSelectors);
            } else {
                revert IncorrectFacetCutAction(uint8(action));
            }
        }
        emit DiamondCut(_diamondCut, init, data);
        initializeDiamondCut(init, data);
    }

    /**
     * @dev Add Function to Diamond
     * @param _facetAddress Address of Facet
     * @param _functionSelectors Signature array of function selectors
     */
    function addFunctions(address _facetAddress, bytes4[] memory _functionSelectors) internal {
        if (_facetAddress == address(0)) {
            revert CannotAddSelectorsToZeroAddress(_functionSelectors);
        }

        RulesEngineDiamondStorage storage ds = s();
        uint16 selectorCount = uint16(ds.selectors.length);
        enforceHasContractCode(_facetAddress, "DiamondCutLib: Add facet has no code");

        for (uint256 selectorIndex; selectorIndex < _functionSelectors.length; ++selectorIndex) {
            bytes4 selector = _functionSelectors[selectorIndex];
            address oldFacetAddress = ds.facetAddressAndSelectorPosition[selector].facetAddress;
            if (oldFacetAddress != address(0)) {
                revert CannotAddFunctionToDiamondThatAlreadyExists(selector);
            }
            ds.facetAddressAndSelectorPosition[selector] = FacetAddressAndSelectorPosition(_facetAddress, selectorCount);
            ds.selectors.push(selector);
            ++selectorCount;
        }
    }

    /**
     * @dev Replace Function from Diamond
     * @param _facetAddress Address of Facet
     * @param _functionSelectors Signature array of function selectors
     */
    function replaceFunctions(address _facetAddress, bytes4[] memory _functionSelectors) internal {
        RulesEngineDiamondStorage storage ds = s();
        if (_facetAddress == address(0)) {
            revert CannotReplaceFunctionsFromFacetWithZeroAddress(_functionSelectors);
        }
        enforceHasContractCode(_facetAddress, "DiamondCutLib: Replace facet has no code");
        for (uint256 selectorIndex; selectorIndex < _functionSelectors.length; ++selectorIndex) {
            bytes4 selector = _functionSelectors[selectorIndex];
            address oldFacetAddress = ds.facetAddressAndSelectorPosition[selector].facetAddress;
            /// can't replace immutable functions -- functions defined directly in the diamond in this case
            if (oldFacetAddress == address(this)) {
                revert CannotReplaceImmutableFunction(selector);
            }
            if (oldFacetAddress == _facetAddress) {
                revert CannotReplaceFunctionWithTheSameFunctionFromTheSameFacet(selector);
            }
            if (oldFacetAddress == address(0)) {
                revert CannotReplaceFunctionThatDoesNotExists(selector);
            }
            /// replace old facet address
            ds.facetAddressAndSelectorPosition[selector].facetAddress = _facetAddress;
        }
    }

    /**
     * @dev Remove Function from Diamond
     * @param _facetAddress Address of Facet
     * @param _functionSelectors Signature array of function selectors
     */
    function removeFunctions(address _facetAddress, bytes4[] memory _functionSelectors) internal {
        RulesEngineDiamondStorage storage ds = s();
        uint256 selectorCount = ds.selectors.length;
        if (_facetAddress != address(0)) {
            revert RemoveFacetAddressMustBeZeroAddress(_facetAddress);
        }
        for (uint256 selectorIndex; selectorIndex < _functionSelectors.length; ++selectorIndex) {
            bytes4 selector = _functionSelectors[selectorIndex];
            FacetAddressAndSelectorPosition memory oldFacetAddressAndSelectorPosition = ds.facetAddressAndSelectorPosition[selector];
            if (oldFacetAddressAndSelectorPosition.facetAddress == address(0)) {
                revert CannotRemoveFunctionThatDoesNotExist(selector);
            }

            /// can't remove immutable functions -- functions defined directly in the diamond
            if (oldFacetAddressAndSelectorPosition.facetAddress == address(this)) {
                revert CannotRemoveImmutableFunction(selector);
            }
            /// replace selector with last selector
            selectorCount--;
            if (oldFacetAddressAndSelectorPosition.selectorPosition != selectorCount) {
                bytes4 lastSelector = ds.selectors[selectorCount];
                ds.selectors[oldFacetAddressAndSelectorPosition.selectorPosition] = lastSelector;
                ds.facetAddressAndSelectorPosition[lastSelector].selectorPosition = oldFacetAddressAndSelectorPosition.selectorPosition;
            }
            /// delete last selector
            ds.selectors.pop();
            delete ds.facetAddressAndSelectorPosition[selector];
        }
    }

    /**
     * @dev Initialize Diamond Cut of new Facet
     * @param init The address of the contract or facet to execute "data"
     * @param data A function call, including function selector and arguments
     *             calldata is executed with delegatecall on "init"
     */
    function initializeDiamondCut(address init, bytes memory data) internal {
        if (init == address(0)) {
            return;
        }
        enforceHasContractCode(init, "DiamondCutLib: init address has no code");
        (bool success, bytes memory error) = init.delegatecall(data);
        if (!success) {
            if (error.length > 0) {
                // bubble up error
                /// @solidity memory-safe-assembly
                assembly {
                    let returndata_size := mload(error)
                    revert(add(32, error), returndata_size)
                }
            } else {
                revert InitializationFunctionReverted(init, data);
            }
        }
    }

    /**
     * @dev Internal function to enforce contract has code
     * @param _contract The address of the contract be checked or enforced
     * @param _errorMessage Error for contract with non matching co
     */
    function enforceHasContractCode(address _contract, string memory _errorMessage) internal view {
        uint256 contractSize;
        assembly {
            contractSize := extcodesize(_contract)
        }
        if (contractSize == 0) {
            revert NoBytecodeAtAddress(_contract, _errorMessage);
        }
    }
}
