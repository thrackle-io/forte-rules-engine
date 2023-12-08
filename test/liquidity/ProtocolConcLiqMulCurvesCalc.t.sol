// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "test/helpers/TestCommonFoundry.sol";
import {LinearInput, LinearFractionB, ConstantRatio} from "../../src/liquidity/calculators/dataStructures/CurveDataStructures.sol";
import "src/liquidity/calculators/ProtocolAMMCalcConcLiqMulCurves.sol";

/**
 * @title Test all AMM Calculator Factory related functions
 * @notice This tests every function related to the AMM Calculator Factory including the different types of calculators
 * @dev A substantial amount of set up work is needed for each test.
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 */
contract ProtocolNFTAMMFactoryTest is TestCommonFoundry {

    uint256 constant M_PRECISION_DECIMALS = 8;
    uint256 constant B_PRECISION_DECIMALS = 18;
    uint256 constant Y_MAX = 100_000 * 10 ** 18;
    uint256 constant M_MAX = 100 * 10 ** 8;

    LinearInput linearA = LinearInput(1 * 10 ** (M_PRECISION_DECIMALS - 1), 50 * (10 ** B_PRECISION_DECIMALS)); //m=0.1; b=50.0
    LinearInput linearB = LinearInput(1 * 10 ** (M_PRECISION_DECIMALS - 2), 100 * (10 ** B_PRECISION_DECIMALS)); //m=0.01; b=100.0
    LinearInput linearC = LinearInput(1 * 10 ** (M_PRECISION_DECIMALS), 10 * (10 ** B_PRECISION_DECIMALS)); //m=1.0; b=10.0
    ConstantRatio constRatioA = ConstantRatio(30_000, 20_000); // ratio = 3x per 2y
    ConstantRatio constRatioB = ConstantRatio(100, 1); // ratio = 100x per 1y
    ConstantRatio constRatioC = ConstantRatio(1, 20); // ratio = 1x per 20y
    uint256[] upperLimitsA = [1_000 * ATTO, 10_000 * ATTO, 30_000 * ATTO];
    ProtocolAMMCalcConcLiqMulCurves calc;

    function setUp() public {
        vm.startPrank(superAdmin);
        setUpProtocolAndAppManagerAndTokens();
        protocolAMMFactory = createProtocolAMMFactory();
        protocolAMMCalculatorFactory = createProtocolAMMCalculatorFactory();
        calc = ProtocolAMMCalcConcLiqMulCurves(protocolAMMCalculatorFactory.createConcLiqMulCurves(address(applicationAppManager)));
        switchToAppAdministrator();
    }

    function testAMMCalcConcLiqMulCurves_Calculatordeployed() public {
        assertEq(calc.appManagerAddress(),address(applicationAppManager));
    }

    /// Add LinearA Test

    /// build + execution block 
    function _addLinearA() internal {
        calc.addLinear(linearA);
    }

    /// tests
    function testAMMCalcConcLiqMulCurves_AddLinearA_Positive() public {
        _addLinearA();
        (uint256 m_num, uint256 m_den, uint256 b_num, uint256 b_den) = calc.linears(0);
        assertEq(m_num , linearA.m);
        assertEq(m_den , 10 ** M_PRECISION_DECIMALS);
        assertEq(b_num , 2 * linearA.b);
        assertEq(b_den , 2 * 10 ** B_PRECISION_DECIMALS);
    }

    function testAMMCalcConcLiqMulCurves_AddLinearA_BTooLarge() public {
        LinearInput memory linearBTooLarge = LinearInput(1 * 10 ** (M_PRECISION_DECIMALS - 1), Y_MAX + 1);
        vm.expectRevert(abi.encodeWithSignature("ValueOutOfRange(uint256)",Y_MAX + 1));
        calc.addLinear(linearBTooLarge);
    }

    function testAMMCalcConcLiqMulCurves_AddLinearA_MTooLarge() public {
        LinearInput memory linearMTooLarge = LinearInput(M_MAX + 1, 50 * (10 ** B_PRECISION_DECIMALS));
        vm.expectRevert(abi.encodeWithSignature("ValueOutOfRange(uint256)",M_MAX + 1));
        calc.addLinear(linearMTooLarge);
    }

    /// Add ConstRatioA Test

    /// build + execution block 
    function _addConstRatioA() internal {
        calc.addConstantRatio(constRatioA);
    }

    /// tests
    function testAMMCalcConcLiqMulCurves_AddConstRatioA_Positive() public {
        _addConstRatioA();
        (uint256 x, uint256 y) = calc.constRatios(0);
        assertEq(x, constRatioA.x);
        assertEq(y, constRatioA.y);
    }

    function testAMMCalcConcLiqMulCurves_AddConstRatioA_Negative() public {
        vm.expectRevert(abi.encodeWithSignature("AmountsAreZero()"));
        calc.addConstantRatio(ConstantRatio(0, 0));
    }

    /// setting upperLimitsA Test

    /// build + execution block 
    function _setUpperLimitsA() internal {
        calc.setUpperLimits(upperLimitsA);
    }

    /// tests
    function testAMMCalcConcLiqMulCurves_SetUpperLimitsA_Positive() public {
        _setUpperLimitsA();
        for(uint i; i < upperLimitsA.length;i++){
            assertEq(calc.sectionUpperLimits(i), upperLimitsA[i]);
        }
    }

    function testAMMCalcConcLiqMulCurves_SetUpperLimitsA_WrongOrder() public {
        upperLimitsA[0] = 100_000_000 * ATTO; // we make the first element greater than the second
        vm.expectRevert(abi.encodeWithSignature("WrongArrayOrder()"));
        calc.setUpperLimits(upperLimitsA);
    }

    /// encapsulation of previous steps for future buildings
    function _setCurvesA() internal{
        _addLinearA();
        _addConstRatioA();
        _setUpperLimitsA();
    }

    /// setting sectionLinearA Test

    /// build + execution block 
    function _addSectionLinearAToIndex0() internal {
        _setCurvesA();
        SectionCurve memory linearASection = SectionCurve(CurveTypes.LINEAR_FRACTION_B, 0);
        calc.addCurveToSection(linearASection); // this means section 0 will be linearA
    }

    /// tests
    function testAMMCalcConcLiqMulCurves_AddSectionLinearAToIndex0_Positive() public {
        _addSectionLinearAToIndex0();
        (CurveTypes _type, uint256 index) = calc.sectionCurves(0);
        assertEq(uint256(_type), uint256(CurveTypes.LINEAR_FRACTION_B));
        assertEq(index, 0);
    }

    function testAMMCalcConcLiqMulCurves_AddSectionLinearAToIndex0_Negative() public {
        _setCurvesA();
        SectionCurve memory linearASection = SectionCurve(CurveTypes.LINEAR_FRACTION_B, 1);
        vm.expectRevert(abi.encodeWithSignature("IndexOutOfRange()"));
        calc.addCurveToSection(linearASection); 
    }

    /// setting sectionConstantRatioA Test

    /// build + execution block 
    function _addSectionConstRatioAToIndex1() internal {
        _addSectionLinearAToIndex0();
        SectionCurve memory constRatioASection = SectionCurve(CurveTypes.CONST_RATIO, 0);
        calc.addCurveToSection(constRatioASection); // this means section 1 will be constRatio
    }

    /// tests
    function testAMMCalcConcLiqMulCurves_AddSectionConstRatioAToIndex1_Positive() public {
        _addSectionConstRatioAToIndex1();
        (CurveTypes _type, uint256 index) = calc.sectionCurves(1);
        assertEq(uint256(_type), uint256(CurveTypes.CONST_RATIO));
        assertEq(index, 0);
    }

    function testAMMCalcConcLiqMulCurves_AddSectionConstRatioAToIndex1_Negative() public {
        _addSectionLinearAToIndex0();
        SectionCurve memory constRatioASection = SectionCurve(CurveTypes.CONST_RATIO, 1);
        vm.expectRevert(abi.encodeWithSignature("IndexOutOfRange()"));
        calc.addCurveToSection(constRatioASection);
    }

    /// setting sectionConstantRatioA Test

    /// build + execution block 
    function _addSectionConstProductToIndex2() internal {
        _addSectionConstRatioAToIndex1();
        SectionCurve memory constProductSection = SectionCurve(CurveTypes.CONST_PRODUCT, 99); // index don't matter here
        calc.addCurveToSection(constProductSection); // this means section 2 will be constProduct
    }

    /// test
    function testAMMCalcConcLiqMulCurves_AddSectionConstProductAToIndex2() public {
        _addSectionConstProductToIndex2();
        (CurveTypes _type, uint256 index) = calc.sectionCurves(2);
        assertEq(uint256(_type), uint256(CurveTypes.CONST_PRODUCT));
        assertEq(index, 99);
    }

    /// General negative case for setting a curve section: Invalid Curve Type
    function testAMMCalcConcLiqMulCurves_AddSection_Negative() public {
        _addSectionConstRatioAToIndex1();
        SectionCurve memory constProductSection = SectionCurve(CurveTypes.LINEAR_WHOLE_B, 0); // index don't matter here
        vm.expectRevert(abi.encodeWithSignature("InvalidCurveType()"));
        calc.addCurveToSection(constProductSection); 
   }

    /// encapsulation of previous tests for future buildings
   function _setSectionsA() internal{
        _addSectionLinearAToIndex0();
        _addSectionConstRatioAToIndex1();
        _addSectionConstProductToIndex2();
   }


}
