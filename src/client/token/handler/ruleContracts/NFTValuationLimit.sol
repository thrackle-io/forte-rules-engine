// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/client/token/handler/ruleContracts/HandlerRuleContractsCommonImports.sol";
import "src/client/token/handler/common/AppAdministratorOrOwnerOnlyDiamondVersion.sol";

/**
 * @title nftValuationLimit variable setter and getter contract
 * @author @ShaneDuncan602 @oscarsernarosero @TJ-Everett @bfcoursewool
 * @dev Setters and getters for the rule in the handler. Meant to be inherited by a handler
 * facet to easily support the rule.
 */

contract NFTValuationLimit is ITokenHandlerEvents, AppAdministratorOrOwnerOnlyDiamondVersion {

    /**
     * @dev Set the NFT Valuation limit that will check collection price vs looping through each tokenId in collections
     * @param _newNFTValuationLimit set the number of NFTs in a wallet that will check for collection price vs individual token prices
     */
    function setNFTValuationLimit(uint16 _newNFTValuationLimit) public appAdministratorOrOwnerOnly(lib.handlerBaseStorage().appManager) {
        lib.nftValuationLimitStorage().nftValuationLimit = _newNFTValuationLimit;
        emit AD1467_NFTValuationLimitUpdated(_newNFTValuationLimit);
    }

    /**
     * @dev Get the nftValuationLimit
     * @return nftValautionLimit number of NFTs in a wallet that will check for collection price vs individual token prices
     */
    function getNFTValuationLimit() external view returns (uint256) {
        return lib.nftValuationLimitStorage().nftValuationLimit;
    }
}