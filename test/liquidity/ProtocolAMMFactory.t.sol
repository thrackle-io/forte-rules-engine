// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "src/liquidity/ProtocolERC20AMM.sol";
import "src/liquidity/calculators/IProtocolAMMFactoryCalculator.sol";
import "src/liquidity/calculators/ProtocolAMMCalcConst.sol";
import "src/liquidity/calculators/ProtocolAMMCalcCP.sol";
import "src/liquidity/calculators/ProtocolAMMCalcLinear.sol";
import "test/helpers/TestCommonFoundry.sol";

/**
 * @title Test all AMM Calculator Factory related functions
 * @notice This tests every function related to the AMM Calculator Factory including the different types of calculators
 * @dev A substantial amount of set up work is needed for each test.
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 */
contract ProtocolAMMFactoryTest is TestCommonFoundry {

    function setUp() public {
        vm.startPrank(superAdmin);
        setUpProtocolAndAppManagerAndTokens();
        protocolAMMFactory = createProtocolAMMFactory();
        switchToAppAdministrator();
    }

    function testCreateAMM() public {
        protocolAMMCalculatorFactory = createProtocolAMMCalculatorFactory();
        ProtocolERC20AMM protocolAMM = ProtocolERC20AMM(protocolAMMFactory.createERC20AMM(address(applicationCoin), address(applicationCoin2), address(applicationAppManager), protocolAMMCalculatorFactory.createConstantProduct(address(applicationAppManager))));
        ProtocolAMMCalcCP calc = ProtocolAMMCalcCP(protocolAMM.calculatorAddress());
        assertEq(calc.appManagerAddress(),address(applicationAppManager));
    }

    function testCreateAMMLinear() public {
        ProtocolERC20AMM protocolAMM = ProtocolERC20AMM(protocolAMMFactory.createLinearAMM(address(applicationCoin), address(applicationCoin2), 6000, 15 * 10 ** 17,  address(applicationAppManager)));
        ProtocolAMMCalcLinear calc = ProtocolAMMCalcLinear(protocolAMM.calculatorAddress());
        assertEq(calc.getSlope(),6000);
    }

    function testCreateAMMConstant() public {
        ProtocolERC20AMM protocolAMM = ProtocolERC20AMM(protocolAMMFactory.createConstantAMM(address(applicationCoin), address(applicationCoin2), 1, 2,  address(applicationAppManager)));
        ProtocolAMMCalcConst calc = ProtocolAMMCalcConst(protocolAMM.calculatorAddress());
        assertEq(calc.getX(),1);
    }

    function testCreateAMMConstantProduct() public {
        ProtocolERC20AMM protocolAMM = ProtocolERC20AMM(protocolAMMFactory.createConstantProductAMM(address(applicationCoin), address(applicationCoin2), address(applicationAppManager)));
        ProtocolAMMCalcCP calc = ProtocolAMMCalcCP(protocolAMM.calculatorAddress());
        assertEq(calc.appManagerAddress(),address(applicationAppManager));
    }
}