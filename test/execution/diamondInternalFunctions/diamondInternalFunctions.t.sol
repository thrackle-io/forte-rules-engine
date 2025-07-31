/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "lib/diamond-std/core/DiamondLoupe/IDiamondLoupe.sol";
import "lib/diamond-std/core/DiamondCut/IDiamondCut.sol";

abstract contract diamondInternalFunctions is RulesEngineCommon {
    /**
     *
     *
     * Execution tests for the diamond internal functions
     *
     *
     */
    address diamondOwner = address(0xB0b);
    IDiamondLoupe.Facet[] originalFacets;
    mapping(address => bytes4[]) facetToSelectors;
    address newfacetAddress = address(0xaaaaa);

    modifier recordDiamondBeforeTest() {
        assertEq(ERC173Facet(address(red)).owner(), diamondOwner, "Rules Engine Diamond address mismatch");
        IDiamondLoupe.Facet[] memory facets = IDiamondLoupe(address(red)).facets();
        for (uint facet; facet < facets.length; facet++) {
            originalFacets.push(facets[facet]);
            bytes4[] memory functionSelectors = IDiamondLoupe(address(red)).facetFunctionSelectors(facets[facet].facetAddress);
            for (uint selector; selector < functionSelectors.length; selector++) {
                facetToSelectors[facets[facet].facetAddress].push(functionSelectors[selector]);
            }
        }
        _;
    }

    function test_diamond_cannotAdd() public ifDeploymentTestsEnabled recordDiamondBeforeTest {
        _testDiamondCannotModify(FacetCutAction.Add);
    }

    function test_diamond_cannotRemove() public ifDeploymentTestsEnabled recordDiamondBeforeTest {
        _testDiamondCannotModify(FacetCutAction.Remove);
    }

    function test_diamond_cannotReplace() public ifDeploymentTestsEnabled recordDiamondBeforeTest {
        _testDiamondCannotModify(FacetCutAction.Replace);
    }

    function _testDiamondCannotModify(FacetCutAction _action) public {
        FacetCut memory newFacet;
        newFacet.facetAddress = newfacetAddress;
        newFacet.action = _action;
        bytes4[] memory newFacetSelectors = new bytes4[](3);
        newFacetSelectors[0] = bytes4(keccak256("newFunction1()"));
        newFacetSelectors[0] = bytes4(keccak256("newFunction2()"));
        newFacetSelectors[0] = bytes4(keccak256("newFunction3()"));
        newFacet.functionSelectors = newFacetSelectors;
        FacetCut[] memory newFacetCut = new FacetCut[](1);
        newFacetCut[0] = newFacet;
        // the diamond doesn't expose diamondCut function: diamondCut((address,uint8,bytes4[])[],address,bytes)
        // since it doesn't add a facet that makes the internal funtion in the DiamondCutLib public
        address diamondCutFacetAddress = IDiamondLoupe(address(red)).facetAddress(bytes4(0x1f931c1c));
        // we make sure the diamond is not aware of such function by checking that the facet is address(0)
        assertEq(address(0), diamondCutFacetAddress);
        // we go a step further and try to call the diamondCut function and expect a specific revert message
        vm.expectRevert("FunctionNotFound(0x1f931c1c)");
        IDiamondCut(address(red)).diamondCut(newFacetCut, address(0), "");
        // we confirm that diamond hasn't changed at all
        checkDiamondImmutability();
    }
    function test_diamond_initialize_onlyOnce_negative() public ifDeploymentTestsEnabled recordDiamondBeforeTest {
        vm.expectRevert("Already initialized");
        RulesEngineInitialFacet(address(red)).initialize(address(this));
        // we confirm that the owner is still the original owner and the diamond is still the same
        checkDiamondImmutability();
    }

    function checkDiamondImmutability() public {
        assertEq(ERC173Facet(address(red)).owner(), diamondOwner, "Rules Engine Diamond address mismatch");
        IDiamondLoupe.Facet[] memory facets = IDiamondLoupe(address(red)).facets();
        for (uint facet; facet < facets.length; facet++) {
            if (originalFacets[facet].facetAddress != facets[facet].facetAddress) revert("facet addresses don't match");
            bytes4[] memory functionSelectors = IDiamondLoupe(address(red)).facetFunctionSelectors(facets[facet].facetAddress);
            for (uint selector; selector < functionSelectors.length; selector++) {
                if (facetToSelectors[facets[facet].facetAddress][selector] != functionSelectors[selector])
                    revert("facet selectors don't match");
            }
        }
    }
}
