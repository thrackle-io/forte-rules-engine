// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

/// note: this is a simple NFT marketplace contract from https://github.com/PatrickAlphaC/hardhat-nft-marketplace-fcc/blob/main/contracts/NftMarketplace.sol

import "lib/openzeppelin-contracts/contracts/token/ERC721/IERC721.sol"; 
import "lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

// Check out https://github.com/Fantom-foundation/Artion-Contracts/blob/5c90d2bc0401af6fb5abf35b860b762b31dfee02/contracts/FantomMarketplace.sol
// For a full decentralized nft marketplace

error PriceNotMet(address nftAddress, uint256 tokenId, uint256 price);
error ItemNotForSale(address nftAddress, uint256 tokenId);
error NotListed(address nftAddress, uint256 tokenId);
error AlreadyListed(address nftAddress, uint256 tokenId);
error NoProceeds();
error NotOwner();
error NotApprovedForMarketplace();
error PriceMustBeAboveZero();
error TransferFailed(address tokenAddress, bytes4 underlyingError);
error NoOffer(address nftAddress, uint256 tokenId);

// Error thrown for isNotOwner modifier
// error IsNotOwner()

contract NftMarketplace {
    struct Listing {
        uint256 price;
        address erc20Address;
        address seller;
        Offer offer;
    }

    struct Offer {
        address buyer;
        uint256 price;
    }

    event ItemListed(
        address indexed seller,
        address indexed nftAddress,
        uint256 indexed tokenId,
        uint256 price
    );

    event ItemCanceled(
        address indexed seller,
        address indexed nftAddress,
        uint256 indexed tokenId
    );

    event ItemBought(
        address indexed buyer,
        address indexed nftAddress,
        uint256 indexed tokenId,
        uint256 price
    );

    mapping(address => mapping(uint256 => Listing)) private s_listings;
    mapping(address => uint256) private s_proceeds;

    modifier notListed(
        address nftAddress,
        uint256 tokenId
    ) {
        Listing memory listing = s_listings[nftAddress][tokenId];
        if (listing.price > 0) {
            revert AlreadyListed(nftAddress, tokenId);
        }
        _;
    }

    modifier isListed(address nftAddress, uint256 tokenId) {
        Listing memory listing = s_listings[nftAddress][tokenId];
        if (listing.price <= 0) {
            revert NotListed(nftAddress, tokenId);
        }
        _;
    }

    modifier hasOffer(address nftAddress, uint256 tokenId) {
        Listing memory listing = s_listings[nftAddress][tokenId];
        if (listing.offer.buyer == address(0)) {
            revert NoOffer(nftAddress, tokenId);
        }
        _;
    }

    modifier isOwner(
        address nftAddress,
        uint256 tokenId,
        address spender
    ) {
        IERC721 nft = IERC721(nftAddress);
        address owner = nft.ownerOf(tokenId);
        if (spender != owner) {
            revert NotOwner();
        }
        _;
    }

    /////////////////////
    // Main Functions //
    /////////////////////
    /*
     * @notice Method for listing NFT
     * @param nftAddress Address of NFT contract
     * @param tokenId Token ID of NFT
     * @param price sale price for each item
     */
    function listItem(
        address nftAddress,
        uint256 tokenId,
        address erc20Address,
        uint256 price
    )
        external
        notListed(nftAddress, tokenId)
        isOwner(nftAddress, tokenId, msg.sender)
    {
        if (price <= 0) {
            revert PriceMustBeAboveZero();
        }
        IERC721 nft = IERC721(nftAddress);
        if (nft.getApproved(tokenId) != address(this)) {
            revert NotApprovedForMarketplace();
        }
        s_listings[nftAddress][tokenId] = Listing(price, erc20Address, msg.sender, Offer(address(0), 0));
        emit ItemListed(msg.sender, nftAddress, tokenId, price);
    }

    /*
     * @notice Method for cancelling listing
     * @param nftAddress Address of NFT contract
     * @param tokenId Token ID of NFT
     */
    function cancelListing(address nftAddress, uint256 tokenId)
        external
        isOwner(nftAddress, tokenId, msg.sender)
        isListed(nftAddress, tokenId)
    {
        delete (s_listings[nftAddress][tokenId]);
        emit ItemCanceled(msg.sender, nftAddress, tokenId);
    }

    /*
     * @notice Method for buying listing
     * @notice The owner of an NFT could unapprove the marketplace,
     * which would cause this function to fail
     * Ideally you'd also have a `createOffer` functionality.
     * @param nftAddress Address of NFT contract
     * @param tokenId Token ID of NFT
     */
    function buyItem(address nftAddress, uint256 tokenId)
        external
        payable
        isListed(nftAddress, tokenId)
    {
        Listing memory listedItem = s_listings[nftAddress][tokenId];
        IERC20 fungibleToken = IERC20(listedItem.erc20Address);

        if (fungibleToken.balanceOf(msg.sender) < listedItem.price) {
            revert PriceNotMet(nftAddress, tokenId, listedItem.price);
        }
        // Could just send the money...
        // https://fravoll.github.io/solidity-patterns/pull_over_push.html
        delete (s_listings[nftAddress][tokenId]);

        // This is added purely so we can gather custom errors and why it fails in testing
        try IERC20(listedItem.erc20Address).transferFrom(msg.sender, listedItem.seller, listedItem.price) {}
        catch (bytes memory reason) {
            bytes4 selector = bytes4(reason);
            revert TransferFailed(listedItem.erc20Address, selector);
        }
        try IERC721(nftAddress).safeTransferFrom(listedItem.seller, msg.sender, tokenId) {}
        catch (bytes memory reason) {
            bytes4 selector = bytes4(reason);
            revert TransferFailed(nftAddress, selector);
        }
        emit ItemBought(msg.sender, nftAddress, tokenId, listedItem.price);
    }

    function sellItem(address nftAddress, uint256 tokenId)
        external
        payable
        isListed(nftAddress, tokenId) 
        hasOffer(nftAddress, tokenId) {
            Listing memory listedItem = s_listings[nftAddress][tokenId];
            IERC721 nft = IERC721(nftAddress);
            if (nft.ownerOf(tokenId) != msg.sender) {
                revert NotOwner();
            }

            delete (s_listings[nftAddress][tokenId]);

            // This is added purely so we can gather custom errors and why it fails in testing
            try IERC721(nftAddress).safeTransferFrom(listedItem.seller, listedItem.offer.buyer, tokenId) {}
            catch (bytes memory reason) {
                bytes4 selector = bytes4(reason);
                revert TransferFailed(nftAddress, selector);
            }
            try IERC20(listedItem.erc20Address).transferFrom(listedItem.offer.buyer, msg.sender, listedItem.offer.price) {}
            catch (bytes memory reason) {
                bytes4 selector = bytes4(reason);
                revert TransferFailed(listedItem.erc20Address, selector);
            }
            emit ItemBought(listedItem.offer.buyer, nftAddress, tokenId, listedItem.offer.price);
    }
    
    function createOffer(address nftAddress, uint256 tokenId, uint256 price) external isListed(nftAddress, tokenId) {
        Listing memory listing = s_listings[nftAddress][tokenId];

        require(IERC20(listing.erc20Address).allowance(msg.sender, address(this)) >= price, "Insufficient balance");
        if (price > listing.offer.price || msg.sender == listing.offer.buyer) {
            s_listings[nftAddress][tokenId].offer = Offer(msg.sender, price);
        }
    }
    



    /*
     * @notice Method for updating listing
     * @param nftAddress Address of NFT contract
     * @param tokenId Token ID of NFT
     * @param newPrice Price in Wei of the item
     */
    function updateListing(
        address nftAddress,
        uint256 tokenId,
        uint256 newPrice
    )
        external
        isListed(nftAddress, tokenId)
        isOwner(nftAddress, tokenId, msg.sender)
    {
        //We should check the value of `newPrice` and revert if it's below zero (like we also check in `listItem()`)
        if (newPrice <= 0) {
            revert PriceMustBeAboveZero();
        }
        s_listings[nftAddress][tokenId].price = newPrice;
        emit ItemListed(msg.sender, nftAddress, tokenId, newPrice);
    }

    /*
     * @notice Method for withdrawing proceeds from sales
     */
    function withdrawProceeds() external {
        uint256 proceeds = s_proceeds[msg.sender];
        if (proceeds <= 0) {
            revert NoProceeds();
        }
        s_proceeds[msg.sender] = 0;
        (bool success, ) = payable(msg.sender).call{value: proceeds}("");
        require(success, "Transfer failed");
    }

    /////////////////////
    // Getter Functions //
    /////////////////////

    function getListing(address nftAddress, uint256 tokenId)
        external
        view
        returns (Listing memory)
    {
        return s_listings[nftAddress][tokenId];
    }

    function getProceeds(address seller) external view returns (uint256) {
        return s_proceeds[seller];
    }
}
