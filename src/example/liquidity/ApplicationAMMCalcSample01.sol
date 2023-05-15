// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.17;

import "../../liquidity/IProtocolAMMCalculator.sol";

/**
 * @title Automated Market Maker Swap Constant Product Calculator
 * @notice This contains the calculations for AMM swap.
 * @dev This is external and used by the ProtocolAMM. The intention is to be able to change the calculations
 *      as needed. It contains an example NT Algorithm
 *
 * f = func([0, 10], lambda x: ((10 - x)**2)/2, [0, 50], lambda y: 10 - (2*y)**(.5), tracker = 8)
 * g = func([0,100], lambda y: 10 - y**(.5), [0,10], lambda x: (10 - x)**2), tracker = 4
 * Note: These functions have been scaled to work only with ERC20s that have Decimals = 18
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett
 */
contract ApplicationAMMCalcSample01 is IProtocolAMMCalculator {
    error AmountsAreZero();
    error InsufficientPoolDepth(uint256 pool, int256 attemptedWithdrawal);
    int256 f_tracker = 8 * 10 ** 18;
    int256 g_tracker = 4 * 10 ** 18;

    /**
     * @dev This is the overall swap function. It branches to the necessary swap subfunction
     *      x = _reserve0
     *      y = _reserve1
     *      a = _amount0
     *      b = _amount1
     *      k = _reserve0 * _reserve1
     *
     * @param _reserve0 total amount of token0 in reserve
     * @param _reserve1 total amount of token1 in reserve
     * @param _amount0 amount of token0 possibly coming into the pool
     * @param _amount1 amount of token1 possibly coming into the pool
     * @return _amountOut amount of alternate coming out of the pool
     */
    function calculateSwap(uint256 _reserve0, uint256 _reserve1, uint256 _amount0, uint256 _amount1) external returns (uint256) {
        if (_amount0 == 0 && _amount1 == 0) {
            revert AmountsAreZero();
        }
        if (_amount0 == 0) {
            // trade token0 for token1
            return calculate1for0(_reserve0, _amount1);
        } else {
            // trade token1 for token0
            return calculate0for1(_reserve1, _amount0);
        }
    }

    /**
     * Perform the calculations for trading token1 for token0
     * @param _reserve0 total amount of token0 in reserve
     * @param _amount1 amount of token1 possibly coming into the pool
     * @return _amountOut amount of alternate coming out of the pool
     */
    function calculate1for0(uint256 _reserve0, uint256 _amount1) private returns (uint256 _amountOut) {
        int256 x_0 = g_tracker;
        uint256 deltaY = uint(x_0 + int(_amount1));
        // calculate for g(y)
        int256 delta = (10 ** 9) * (int256(sqrt(deltaY)) - int256(sqrt(uint(x_0))));
        if (delta < 0 || delta > int(_reserve0)) {
            revert InsufficientPoolDepth(_reserve0, delta);
        }
        // increment the tracker
        g_tracker += int(_amount1);
        // set the inverse tracker
        f_tracker = (10 ** 19) - ((10 ** 9) * int256(sqrt(uint(g_tracker))));
        _amountOut = uint(delta);
        return _amountOut;
    }

    /**
     * Perform the calculations for trading token0 for token1
     * @param _reserve1 total amount of token1 in reserve
     * @param _amount0 amount of token1 possibly coming into the pool
     * @return _amountOut amount of alternate coming out of the pool
     */
    function calculate0for1(uint256 _reserve1, uint256 _amount0) private returns (uint256 _amountOut) {
        int256 x_0 = f_tracker;
        // calculate for f(x)
        int256 delta = (((((10 ** 19)) - x_0) ** 2) / (2 * (10 ** 18))) - ((((10 ** 19) - ((x_0 + int(_amount0)))) ** 2) / (2 * (10 ** 18)));
        if (delta < 0 || delta > int(_reserve1)) {
            revert InsufficientPoolDepth(_reserve1, delta);
        }
        // increment the tracker
        f_tracker += int(_amount0);
        // set the inverse tracker
        g_tracker = (((10 ** 19) - (f_tracker)) ** 2) / (10 ** 18);
        _amountOut = uint(delta);
        return _amountOut;
    }

    /**
     * @dev This function calculates the square root using uniswap style logic
     */
    function sqrt(uint y) internal pure returns (uint z) {
        if (y > 3) {
            z = y;
            uint x = y / 2 + 1;
            while (x < z) {
                z = x;
                x = (y / x + x) / 2;
            }
        } else if (y != 0) {
            z = 1;
        }
    }
}
