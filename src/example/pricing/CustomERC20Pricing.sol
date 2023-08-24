// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";
import {IApplicationEvents} from "../../interfaces/IEvents.sol";
import "../../pricing/IProtocolERC20Pricing.sol";
import "../../economic/AppAdministratorOnly.sol";

/**
 * @title CustomERC20 Pricing example contract
 * @author @ShaneDuncan602, @oscarsernarosero, @TJ-Everett
 * @notice This contract is an example of how one could implement a custom pricing solution. It uses a Chainlink Price Feed to get the token price
 */
contract CustomERC20Pricing is Ownable, IApplicationEvents, IProtocolERC20Pricing, AppAdministratorOnly {
    address private aave = 0xD6DF932A45C0f255f85145f286eA0b292B21C90B;
    address private aaveFeed = 0x72484B12719E23115761D5DA1646945632979bB6;

    address private algo = 0xA8aa9dE3530ab3199a73C9F2115F6d37955546d7;
    address private algoFeed = 0x03Bc6D9EFed65708D35fDaEfb25E87631a0a3437;

    address private doge = 0xD9d32b18Fd437F5de774e926CFFdad8F514EeED0;
    address private dogeFeed = 0xbaf9327b6564454F4a3364C33eFeEf032b4b4444;

    address private appManagerAddress;

    error NoPriceFeed(address tokenAddress);

    constructor(address _appManagerAddress) {
        appManagerAddress = _appManagerAddress;
    }

    /**
     * @dev gets the price of a Token. It will return the Token's specific price. This function is left here to preserve the function signature
     * @param tokenContract is the address of the Token contract
     * @return price of the Token in weis of dollars. 10^18 => $ 1.00 USD
     * @notice that the price is for the whole token and not of its atomic unit. This means that if
     * an ERC20 with 18 decimals has a price of 2 dollars, then its atomic unit would be 2/10^18 USD.
     * 999_999_999_999_999_999 = 0xDE0B6B3A763FFFF, 1_000_000_000_000_000_000 = DE0B6B3A7640000
     */
    function getTokenPrice(address tokenContract) external view returns (uint256 price) {
        uint256 feedPrice;
        if (tokenContract == aave) {
            feedPrice = getChainlinkAAVEtoUSDFeedPrice();
        } else if (tokenContract == algo) {
            feedPrice = getChainlinkALGOtoUSDFeedPrice();
        } else if (tokenContract == doge) {
            feedPrice = getChainlinkALGOtoUSDFeedPrice();
        } else {
            revert NoPriceFeed(tokenContract);
        }
        return feedPrice;
    }

    /**
     * @dev gets the Chainlink price feed for DOGE in USD. This is an example that works for any decimal denomination.
     * @return price The current price in USD for this token according to Chainlink aggregation
     */
    function getChainlinkDOGEtoUSDFeedPrice() public view returns (uint256) {
        AggregatorV3Interface priceFeed = AggregatorV3Interface(dogeFeed);
        uint8 decimals = priceFeed.decimals();
        // prettier-ignore
        (/* uint80 roundID */,
            int price,
            /*uint startedAt*/,
            /*uint timeStamp*/,
            /*uint80 answeredInRound*/) = priceFeed.latestRoundData();

        if (decimals < 18) {
            price = price * int(10 ** (18 - decimals));
        } else if (decimals > 18) {
            price = price / int(10 ** (decimals - 18));
        }

        return (uint256(price));
    }

    /**
     * @dev gets the Chainlink price feed for AAVE in USD.
     * @notice This price feed is actually 8 decimals so it must be converted to 18.
     * @return price The current price in USD for this token according to Chainlink aggregation
     */
    function getChainlinkAAVEtoUSDFeedPrice() public view returns (uint256) {
        AggregatorV3Interface priceFeed = AggregatorV3Interface(aaveFeed);

        // prettier-ignore
        (/* uint80 roundID */,
            int price,
            /*uint startedAt*/,
            /*uint timeStamp*/,
            /*uint80 answeredInRound*/) = priceFeed.latestRoundData();
        price = price * 10 ** 10;
        return (uint256(price));
    }

    /**
     * @dev gets the Chainlink price feed for AAVE in USD.
     * @notice This price feed is actually 8 decimals so it must be converted to 18.
     * @return price The current price in USD for this token according to Chainlink aggregation
     */
    function getChainlinkALGOtoUSDFeedPrice() public view returns (uint256) {
        AggregatorV3Interface priceFeed = AggregatorV3Interface(algoFeed);

        // prettier-ignore
        (/* uint80 roundID */,
            int price,
            /*uint startedAt*/,
            /*uint timeStamp*/,
            /*uint80 answeredInRound*/) = priceFeed.latestRoundData();
        price = price * 10 ** 10;
        return (uint256(price));
    }

    /**
     * @dev This function allows appAdminstrators to set the token address
     */
    function setAAVEAddress(address _address) external appAdministratorOnly(appManagerAddress) {
        aave = _address;
    }

    /**
     * @dev This function allows appAdminstrators to set the Chainlink price feed address
     */
    function setAAVEFeedAddress(address _address) external appAdministratorOnly(appManagerAddress) {
        aaveFeed = _address;
    }

    /**
     * @dev This function allows appAdminstrators to set the token address
     */
    function setALGOAddress(address _address) external appAdministratorOnly(appManagerAddress) {
        algo = _address;
    }

    /**
     * @dev This function allows appAdminstrators to set the Chainlink price feed address
     */
    function setALGOFeedAddress(address _address) external appAdministratorOnly(appManagerAddress) {
        algoFeed = _address;
    }

    /**
     * @dev This function allows appAdminstrators to set the token address
     */
    function setDOGEAddress(address _address) external appAdministratorOnly(appManagerAddress) {
        doge = _address;
    }

    /**
     * @dev This function allows appAdminstrators to set the Chainlink price feed address
     */
    function setDOGEFeedAddress(address _address) external appAdministratorOnly(appManagerAddress) {
        dogeFeed = _address;
    }
}

/// This is the standard Chainlink feed interface
interface AggregatorV3Interface {
    function decimals() external view returns (uint8);

    function description() external view returns (string memory);

    function version() external view returns (uint256);

    function getRoundData(uint80 _roundId) external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);

    function latestRoundData() external view returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}
