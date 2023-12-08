// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

/**
 * @title Curve Data Structures
 * @dev This is a collection of data structures that define different curves for TBCs.
 * @notice Every TBC curve must have its definition here.
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 */


/** 
* @dev Linear curve
* definition: y = m*x + b
*/
struct LinearInput{
    uint256 m;
    uint256 b;
}


/** 
* @dev Linear curve expressed in fractions.
* @notice this is how the internal line should be saved since this will allow more precision during mathematical operations.
* definition: y = (m_num/m_den) * x + b
*/ 
struct LinearWholeB {
    uint256 m_num;
    uint256 m_den;
    uint256 b;
}


/** 
* @dev Linear curve expressed in fractions.
* @notice this is how the internal line should be saved since this will allow more precision during mathematical operations.
* definition: y = (m_num/m_den) * x + b
*/ 
struct LinearFractionB{
    uint256 m_num;
    uint256 m_den;
    uint256 b_num;
    uint256 b_den;
}


/** 
* @dev Constant Ratio.
*/ 
struct ConstantRatio{
    uint32 x;
    uint32 y;
}


/** 
* @dev Constant Ratio.
*/ 
struct ConstantProduct{
    uint256 x;
    uint256 y;
}


/** 
* @dev 
*/ 
struct Sample01Struct{
    uint256 amountIn;
    int256 tracker;
}
