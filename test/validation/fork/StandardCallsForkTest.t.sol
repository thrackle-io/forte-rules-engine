// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "@openzeppelin/token/ERC20/IERC20.sol";
import "@openzeppelin/token/ERC721/IERC721.sol";
import "@openzeppelin/token/ERC1155/IERC1155.sol";

// MINIMAL PROTOCOL INTERFACES

interface IUniswapV2Factory {
    function createPair(address tokenA, address tokenB) external returns (address pair);
    function getPair(address tokenA, address tokenB) external view returns (address pair);
}

interface IUniswapV2Router {
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);

    function addLiquidity(
        address tokenA,
        address tokenB,
        uint amountADesired,
        uint amountBDesired,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB, uint liquidity);
}

interface ISeaport {
    enum ItemType {
        NATIVE, // 0: ETH (or other native token for the given chain)
        ERC20, // 1: ERC20 items (ERC777 and ERC20 analogues with safetransfer)
        ERC721, // 2: ERC721 items
        ERC1155, // 3: ERC1155 items
        ERC721_WITH_CRITERIA, // 4: ERC721 items where a number of tokenIds are supported
        ERC1155_WITH_CRITERIA // 5: ERC1155 items where a number of ids are supported
    }

    enum OrderType {
        FULL_OPEN, // 0: no partial fills, anyone can execute
        PARTIAL_OPEN, // 1: partial fills supported, anyone can execute
        FULL_RESTRICTED, // 2: no partial fills, only offerer or zone can execute
        PARTIAL_RESTRICTED // 3: partial fills supported, only offerer or zone can execute
    }

    struct OfferItem {
        ItemType itemType;
        address token;
        uint256 identifierOrCriteria;
        uint256 startAmount;
        uint256 endAmount;
    }

    struct ConsiderationItem {
        ItemType itemType;
        address token;
        uint256 identifierOrCriteria;
        uint256 startAmount;
        uint256 endAmount;
        address payable recipient;
    }

    struct OrderParameters {
        address offerer;
        address zone;
        OfferItem[] offer;
        ConsiderationItem[] consideration;
        OrderType orderType;
        uint256 startTime;
        uint256 endTime;
        bytes32 zoneHash;
        uint256 salt;
        bytes32 conduitKey;
        uint256 totalOriginalConsiderationItems;
    }

    struct OrderComponents {
        address offerer;
        address zone;
        OfferItem[] offer;
        ConsiderationItem[] consideration;
        OrderType orderType;
        uint256 startTime;
        uint256 endTime;
        bytes32 zoneHash;
        uint256 salt;
        bytes32 conduitKey;
        uint256 counter;
    }

    struct Order {
        OrderParameters parameters;
        bytes signature;
    }

    struct AdvancedOrder {
        OrderParameters parameters;
        uint120 numerator;
        uint120 denominator;
        bytes signature;
        bytes extraData;
    }

    struct CriteriaResolver {
        uint256 orderIndex;
        uint8 side;
        uint256 index;
        uint256 identifier;
        bytes32[] criteriaProof;
    }

    function fulfillAdvancedOrder(
        AdvancedOrder calldata advancedOrder,
        CriteriaResolver[] calldata criteriaResolvers,
        bytes32 fulfillerConduitKey,
        address recipient
    ) external payable returns (bool fulfilled);

    function fulfillOrder(Order calldata order, bytes32 fulfillerConduitKey) external payable returns (bool fulfilled);

    function getCounter(address offerer) external view returns (uint256 counter);

    // For EIP-712 signature creation
    function getOrderHash(OrderComponents calldata order) external view returns (bytes32 orderHash);
    function information() external view returns (string memory version, bytes32 domainSeparator, address conduitController);
}

interface IERC20Staking {
    function stake(uint256 amount) external;
    function unstake(uint256 amount) external;
    function getStaked(address user) external view returns (uint256);
}

contract StandardCallsForked is RulesEngineCommon {
    // MAINNET CONTRACT ADDRESSES

    // for Uniswap tests
    address constant UNISWAP_V2_ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;
    address constant UNISWAP_V2_FACTORY = 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f;

    // for OpenSea tests
    address constant SEAPORT_V1_5 = 0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC;

    address constant BLACKLISTED_USER = 0x000000000000000000000000000000000000dEaD;
    address constant OPENSEA_FEE_RECIPIENT = 0x5b3256965e7C3cF26E11FCAf296DfC8807C01073;

    ExampleERC20 public rulesEnabledTokenA;
    ExampleERC20 public rulesEnabledTokenB;
    ExampleERC721 public rulesEnabledNFT;
    ExampleERC1155 public rulesEnabledERC1155;
    address public alice = address(0xa11ce);
    address public bob = address(0xb0b);
    address public charlie = address(0x1337);

    function setUp() public {
        // Create and select mainnet fork
        uint256 forkId = vm.createFork(vm.envOr("ETHEREUM_RPC_URL", string("")));
        vm.selectFork(forkId);

        // Verify we're on mainnet by checking a known contract
        require(UNISWAP_V2_ROUTER.code.length > 0, "Fork setup failed: Uniswap V2 Router not found");

        // Deploy Rules Engine
        red = createRulesEngineDiamond(address(this));
        _setupEffectProcessor();

        vm.startPrank(address(this));
        rulesEnabledTokenA = new ExampleERC20("Rules Token A", "RTA");
        rulesEnabledTokenA.setRulesEngineAddress(address(red));
        rulesEnabledTokenA.setCallingContractAdmin(callingContractAdmin);

        rulesEnabledTokenB = new ExampleERC20("Rules Token B", "RTB");
        rulesEnabledTokenB.setRulesEngineAddress(address(red));
        rulesEnabledTokenB.setCallingContractAdmin(callingContractAdmin);

        rulesEnabledNFT = new ExampleERC721("Rules Enabled NFT", "REN");
        rulesEnabledNFT.setRulesEngineAddress(address(red));
        rulesEnabledNFT.setCallingContractAdmin(callingContractAdmin);

        rulesEnabledERC1155 = new ExampleERC1155("https://example.com/metadata/");
        rulesEnabledERC1155.setRulesEngineAddress(address(red));
        rulesEnabledERC1155.setCallingContractAdmin(callingContractAdmin);

        // Mint tokens for testing
        rulesEnabledTokenA.mint(alice, 10_000 * 1e18);
        rulesEnabledTokenA.mint(bob, 10_000 * 1e18);
        rulesEnabledTokenA.mint(charlie, 10_000 * 1e18);

        rulesEnabledTokenB.mint(alice, 10_000 * 1e18);
        rulesEnabledTokenB.mint(bob, 10_000 * 1e18);
        rulesEnabledTokenB.mint(charlie, 10_000 * 1e18);

        // Mint NFTs for testing
        rulesEnabledNFT.safeMint(alice); // ID 1
        rulesEnabledNFT.safeMint(alice); // ID 2
        rulesEnabledNFT.safeMint(bob); // ID 3

        // Mint ERC1155 tokens
        rulesEnabledERC1155.mint(alice, 1, 200, "");
        rulesEnabledERC1155.mint(bob, 2, 50, "");
        vm.stopPrank();
    }

    // UNISWAP V2 INTEGRATION TESTS

    function testUniswapV2Swap_WithAmountLimits() public {
        // Create amount limit rule (max 1000 tokens per swap)
        vm.startPrank(policyAdmin);
        uint256 policyId = _setupSwapAmountLimitRule();
        vm.stopPrank();

        vm.startPrank(callingContractAdmin);
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(rulesEnabledTokenA), policyIds);
        vm.stopPrank();

        // Add liquidity to Uniswap V2 pool first
        vm.startPrank(alice);

        // Create the pair
        IUniswapV2Factory(UNISWAP_V2_FACTORY).createPair(address(rulesEnabledTokenA), address(rulesEnabledTokenB));

        // Approve tokens for Uniswap router
        rulesEnabledTokenA.approve(UNISWAP_V2_ROUTER, type(uint256).max);
        rulesEnabledTokenB.approve(UNISWAP_V2_ROUTER, type(uint256).max);

        // Add liquidity (1000 A : 1000 B)
        IUniswapV2Router(UNISWAP_V2_ROUTER).addLiquidity(
            address(rulesEnabledTokenA),
            address(rulesEnabledTokenB),
            1000 * 1e18,
            1000 * 1e18,
            950 * 1e18, // min A
            950 * 1e18, // min B
            alice,
            block.timestamp + 1 hours
        );

        // Small swap (under limit)
        address[] memory path = new address[](2);
        path[0] = address(rulesEnabledTokenA);
        path[1] = address(rulesEnabledTokenB);

        uint256 smallAmount = 500 * 1e18; // Under 1000 limit
        uint256 balanceBefore = rulesEnabledTokenB.balanceOf(alice);

        vm.startSnapshotGas("Uniswap_SmallSwap_HappyPath");
        IUniswapV2Router(UNISWAP_V2_ROUTER).swapExactTokensForTokens(
            smallAmount,
            0, // Accept any amount out
            path,
            alice,
            block.timestamp + 1 hours
        );
        vm.stopSnapshotGas();

        // Verify swap succeeded
        assertGt(rulesEnabledTokenB.balanceOf(alice), balanceBefore);

        // Large swap (over limit, should revert)
        uint256 largeAmount = 1500 * 1e18; // Over 1000 limit

        // This is the error caught by uniswap's TransferHelper.
        // The root cause is due to the rules engine reverting correctly, but the error message is overriden by the failed call in uniswap.
        vm.expectRevert("TransferHelper: TRANSFER_FROM_FAILED");
        IUniswapV2Router(UNISWAP_V2_ROUTER).swapExactTokensForTokens(largeAmount, 0, path, alice, block.timestamp + 1 hours);

        vm.stopPrank();
    }

    // OPENSEA/SEAPORT INTEGRATION TESTS

    function testOpenSeaNFTPurchase_WithBlacklist() public {
        // Create blacklist rule for NFT purchases
        vm.startPrank(policyAdmin);
        uint256 policyId = _setupNFTBlacklistRule();
        vm.stopPrank();

        vm.startPrank(callingContractAdmin);
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(rulesEnabledNFT), policyIds);
        vm.stopPrank();

        // Test happy path first
        _testSeaportHappyPathGeneric(
            ISeaport.ItemType.ERC721,
            address(rulesEnabledNFT),
            1, // tokenId
            1, // amount (always 1 for NFTs)
            1 ether, // total payment
            "OpenSea_NFT_Purchase_HappyPath"
        );

        // Test blacklisted user scenario
        _testSeaportBlacklistedUserGeneric(
            ISeaport.ItemType.ERC721,
            address(rulesEnabledNFT),
            2, // different tokenId for blacklist test
            1, // amount
            1 ether // total payment
        );
    }

    function testOpenSeaERC1155Purchase_WithBlacklist() public {
        // Create blacklist rule for ERC1155 transfers
        vm.startPrank(policyAdmin);
        uint256 policyId = _setupERC1155BlacklistRule();
        vm.stopPrank();

        vm.startPrank(callingContractAdmin);
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = policyId;
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(rulesEnabledERC1155), policyIds);
        vm.stopPrank();

        // Test happy path first
        _testSeaportHappyPathGeneric(
            ISeaport.ItemType.ERC1155,
            address(rulesEnabledERC1155),
            1, // tokenId
            50, // amount
            0.5 ether, // total payment
            "OpenSea_ERC1155_Purchase_HappyPath"
        );

        // Test blacklisted user scenario
        _testSeaportBlacklistedUserGeneric(
            ISeaport.ItemType.ERC1155,
            address(rulesEnabledERC1155),
            1, // tokenId
            50, // amount
            0.5 ether // total payment
        );
    }

    // HELPER FUNCTIONS

    function _signSeaportOrderEIP712(
        uint256 privateKey,
        ISeaport.OrderComponents memory order
    ) internal view returns (bytes memory signature) {
        // Use Seaport's getOrderHash to get the proper EIP-712 hash
        bytes32 orderHash = ISeaport(SEAPORT_V1_5).getOrderHash(order);

        // Get the domain separator from Seaport
        (, bytes32 domainSeparator, ) = ISeaport(SEAPORT_V1_5).information();

        // Create the EIP-712 message hash with proper format
        bytes32 messageHash = keccak256(abi.encodePacked(bytes2(0x1901), domainSeparator, orderHash));

        // Create signature using vm.sign
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        signature = abi.encodePacked(r, s, v);
    }

    function _testSeaportHappyPathGeneric(
        ISeaport.ItemType itemType,
        address tokenAddress,
        uint256 tokenId,
        uint256 amount,
        uint256 totalPayment,
        string memory gasSnapshotName
    ) internal {
        // Setup seller and token transfer
        (address seller, uint256 sellerPrivateKey) = _setupSellerForSeaport(itemType, tokenAddress, tokenId, amount, "seaportSeller");

        // Create order
        ISeaport.Order memory order = _createSeaportOrder(
            seller,
            sellerPrivateKey,
            itemType,
            tokenAddress,
            tokenId,
            amount,
            totalPayment,
            0
        );

        // Execute happy path purchase
        _executeSeaportPurchase(order, itemType, tokenAddress, tokenId, amount, totalPayment, gasSnapshotName);
    }

    function _setupSellerForSeaport(
        ISeaport.ItemType itemType,
        address tokenAddress,
        uint256 tokenId,
        uint256 amount,
        string memory sellerName
    ) internal returns (address seller, uint256 sellerPrivateKey) {
        // Create seller address and private key - this is needed for the Seaport order signature
        (seller, sellerPrivateKey) = makeAddrAndKey(sellerName);

        // Setup token transfer and approvals based on type
        if (itemType == ISeaport.ItemType.ERC721) {
            // Transfer NFT from alice to seller for this test
            vm.startPrank(alice);
            IERC721(tokenAddress).transferFrom(alice, seller, tokenId);
            vm.stopPrank();

            // Seller approves Seaport to transfer their NFT
            vm.startPrank(seller);
            IERC721(tokenAddress).setApprovalForAll(SEAPORT_V1_5, true);
            vm.stopPrank();
        } else if (itemType == ISeaport.ItemType.ERC1155) {
            // Transfer ERC1155 tokens from alice to seller
            vm.startPrank(alice);
            IERC1155(tokenAddress).safeTransferFrom(alice, seller, tokenId, amount, "");
            vm.stopPrank();

            // Seller approves Seaport to transfer their tokens
            vm.startPrank(seller);
            IERC1155(tokenAddress).setApprovalForAll(SEAPORT_V1_5, true);
            vm.stopPrank();
        }
    }

    function _createSeaportOrder(
        address seller,
        uint256 sellerPrivateKey,
        ISeaport.ItemType itemType,
        address tokenAddress,
        uint256 tokenId,
        uint256 amount,
        uint256 totalPayment,
        uint256 salt
    ) internal view returns (ISeaport.Order memory) {
        // Create offer items array
        ISeaport.OfferItem[] memory offerItems = new ISeaport.OfferItem[](1);
        offerItems[0] = ISeaport.OfferItem({
            itemType: itemType,
            token: tokenAddress,
            identifierOrCriteria: tokenId,
            startAmount: amount,
            endAmount: amount
        });

        // Calculate seller amount (97.5%) and fee amount (2.5%)
        uint256 sellerAmount = (totalPayment * 975) / 1000;
        uint256 feeAmount = totalPayment - sellerAmount;

        // Create consideration items array
        ISeaport.ConsiderationItem[] memory considerationItems = new ISeaport.ConsiderationItem[](2);
        considerationItems[0] = ISeaport.ConsiderationItem({
            itemType: ISeaport.ItemType.NATIVE,
            token: address(0),
            identifierOrCriteria: 0,
            startAmount: sellerAmount,
            endAmount: sellerAmount,
            recipient: payable(seller)
        });
        considerationItems[1] = ISeaport.ConsiderationItem({
            itemType: ISeaport.ItemType.NATIVE,
            token: address(0),
            identifierOrCriteria: 0,
            startAmount: feeAmount,
            endAmount: feeAmount,
            recipient: payable(OPENSEA_FEE_RECIPIENT)
        });

        // Create and sign order using the seller's proper private key
        return _createAndSignOrder(seller, sellerPrivateKey, offerItems, considerationItems, salt);
    }

    function _executeSeaportPurchase(
        ISeaport.Order memory order,
        ISeaport.ItemType itemType,
        address tokenAddress,
        uint256 tokenId,
        uint256 amount,
        uint256 totalPayment,
        string memory gasSnapshotName
    ) internal {
        // Give buyer some ETH
        vm.deal(charlie, 10 ether);

        // Execute purchase
        vm.startPrank(charlie);
        uint256 charlieBalanceBefore = charlie.balance;
        uint256 sellerBalanceBefore = order.parameters.consideration[0].recipient.balance;

        // Store before state for verification
        uint256 charlieTokenBalanceBefore;
        if (itemType == ISeaport.ItemType.ERC1155) {
            charlieTokenBalanceBefore = IERC1155(tokenAddress).balanceOf(charlie, tokenId);
        }

        vm.startSnapshotGas(gasSnapshotName);
        ISeaport(SEAPORT_V1_5).fulfillOrder{value: totalPayment}(order, bytes32(0));
        vm.stopSnapshotGas();

        // Verify transfer based on token type
        if (itemType == ISeaport.ItemType.ERC721) {
            assertEq(IERC721(tokenAddress).ownerOf(tokenId), charlie, "Charlie should own the NFT");
        } else if (itemType == ISeaport.ItemType.ERC1155) {
            assertEq(
                IERC1155(tokenAddress).balanceOf(charlie, tokenId),
                charlieTokenBalanceBefore + amount,
                "Charlie should receive the correct amount of ERC1155 tokens"
            );
        }

        uint256 sellerAmount = (totalPayment * 975) / 1000;
        assertEq(charlie.balance, charlieBalanceBefore - totalPayment, "Charlie should pay the total amount");
        assertEq(
            order.parameters.consideration[0].recipient.balance,
            sellerBalanceBefore + sellerAmount,
            "Seller should receive 97.5% of payment"
        );
        vm.stopPrank();
    }

    function _testSeaportBlacklistedUserGeneric(
        ISeaport.ItemType itemType,
        address tokenAddress,
        uint256 tokenId,
        uint256 amount,
        uint256 totalPayment
    ) internal {
        // Setup seller for blacklisted test
        (address seller, uint256 sellerPrivateKey) = _setupSellerForBlacklistTest(itemType, tokenAddress, tokenId, amount);

        // Create order with different salt
        ISeaport.Order memory newOrder = _createSeaportOrder(
            seller,
            sellerPrivateKey,
            itemType,
            tokenAddress,
            tokenId,
            amount,
            totalPayment,
            1
        );

        // Test blacklisted user purchase
        vm.deal(BLACKLISTED_USER, 10 ether);
        vm.startPrank(BLACKLISTED_USER);
        vm.expectRevert("Rules Engine Revert");
        ISeaport(SEAPORT_V1_5).fulfillOrder{value: totalPayment}(newOrder, bytes32(0));
        vm.stopPrank();
    }

    function _setupSellerForBlacklistTest(
        ISeaport.ItemType itemType,
        address tokenAddress,
        uint256 tokenId,
        uint256 amount
    ) internal returns (address seller, uint256 sellerPrivateKey) {
        // Create seller address and private key
        (seller, sellerPrivateKey) = makeAddrAndKey("seaportSellerBlacklist");

        // Setup based on token type
        if (itemType == ISeaport.ItemType.ERC721) {
            // Mint a new NFT for testing the blacklist
            vm.startPrank(address(this));
            ExampleERC721(tokenAddress).safeMint(seller);
            vm.stopPrank();

            // Approve Seaport
            vm.startPrank(seller);
            IERC721(tokenAddress).setApprovalForAll(SEAPORT_V1_5, true);
            vm.stopPrank();
        } else if (itemType == ISeaport.ItemType.ERC1155) {
            // Transfer ERC1155 tokens from alice to seller
            vm.startPrank(alice);
            IERC1155(tokenAddress).safeTransferFrom(alice, seller, tokenId, amount, "");
            vm.stopPrank();

            vm.startPrank(seller);
            IERC1155(tokenAddress).setApprovalForAll(SEAPORT_V1_5, true);
            vm.stopPrank();
        }
    }

    function _createAndSignOrder(
        address seller,
        uint256 sellerPrivateKey,
        ISeaport.OfferItem[] memory offerItems,
        ISeaport.ConsiderationItem[] memory considerationItems,
        uint256 salt
    ) internal view returns (ISeaport.Order memory) {
        // Create order components for signing (includes counter)
        ISeaport.OrderComponents memory orderComponents = ISeaport.OrderComponents({
            offerer: seller,
            zone: address(0),
            offer: offerItems,
            consideration: considerationItems,
            orderType: ISeaport.OrderType.FULL_OPEN,
            startTime: block.timestamp,
            endTime: block.timestamp + 1000,
            zoneHash: bytes32(0),
            salt: salt,
            conduitKey: bytes32(0),
            counter: ISeaport(SEAPORT_V1_5).getCounter(seller)
        });

        // Sign the order with proper EIP-712 format
        bytes memory signature = _signSeaportOrderEIP712(sellerPrivateKey, orderComponents);

        // Create order parameters for the Order struct
        ISeaport.OrderParameters memory orderParameters = ISeaport.OrderParameters({
            offerer: seller,
            zone: address(0),
            offer: offerItems,
            consideration: considerationItems,
            orderType: ISeaport.OrderType.FULL_OPEN,
            startTime: block.timestamp,
            endTime: block.timestamp + 1000,
            zoneHash: bytes32(0),
            salt: salt,
            conduitKey: bytes32(0),
            totalOriginalConsiderationItems: considerationItems.length
        });

        return ISeaport.Order({parameters: orderParameters, signature: signature});
    }

    // RULE IMPLEMENTATIONS

    function _setupSwapAmountLimitRule() internal returns (uint256 policyId) {
        // Create policy for swap amount limits
        policyId = _createBlankPolicy();

        // Add calling function for transferFrom (this is what gets called when swapping)
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR; // from
        pTypes[1] = ParamTypes.ADDR; // to
        pTypes[2] = ParamTypes.UINT; // amount

        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(keccak256("transferFrom(address,address,uint256)")), // 0x23b872dd
            pTypes,
            "transferFrom(address,address,uint256)",
            ""
        );

        // Rule: amount <= 1000 tokens → PASS (if false, revert)
        Rule memory rule;
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0; // amount placeholder
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1000 * 1e18; // 1k token limit
        rule.instructionSet[4] = uint(LogicalOp.LTEQL);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].typeSpecificIndex = 2; // amount parameter in transferFrom(from, to, amount)

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(
            policyId,
            rule,
            "Swap Amount Limit",
            "Restrict swaps over 1000 tokens"
        );

        // Update policy with the rule
        bytes4[] memory functions = new bytes4[](1);
        functions[0] = bytes4(keccak256("transferFrom(address,address,uint256)"));
        uint256[] memory functionIds = new uint256[](1);
        functionIds[0] = callingFunctionId;
        uint256[][] memory ruleIdsArray = new uint256[][](1);
        ruleIdsArray[0] = new uint256[](1);
        ruleIdsArray[0][0] = ruleId;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            functions,
            functionIds,
            ruleIdsArray,
            PolicyType.CLOSED_POLICY,
            "policyName",
            "policyDescription"
        );

        return policyId;
    }

    function _setupNFTBlacklistRule() internal returns (uint256 policyId) {
        // Create policy for NFT blacklist
        policyId = _createBlankPolicy();

        // Add specific calling function for safeTransferFrom
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR; // from
        pTypes[1] = ParamTypes.ADDR; // to
        pTypes[2] = ParamTypes.UINT; // tokenId

        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(keccak256("transferFrom(address,address,uint256)")),
            pTypes,
            "transferFrom(address,address,uint256)",
            ""
        );

        // to != BLACKLISTED_USER → PASS (if false, revert)
        Rule memory rule;
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0; // references 'to' address
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(uint160(BLACKLISTED_USER));
        rule.instructionSet[4] = uint(LogicalOp.NOTEQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 1; // 'to' parameter

        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(
            policyId,
            rule,
            "NFT Blacklist",
            "Prevent blacklisted users from receiving NFTs"
        );

        // Update policy with the rule
        bytes4[] memory functions = new bytes4[](1);
        functions[0] = bytes4(keccak256("transferFrom(address,address,uint256)"));
        uint256[] memory functionIds = new uint256[](1);
        functionIds[0] = callingFunctionId;
        uint256[][] memory ruleIdsArray = new uint256[][](1);
        ruleIdsArray[0] = new uint256[](1);
        ruleIdsArray[0][0] = ruleId;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            functions,
            functionIds,
            ruleIdsArray,
            PolicyType.CLOSED_POLICY,
            "policyName",
            "policyDescription"
        );

        return policyId;
    }

    function _setupERC1155BlacklistRule() internal returns (uint256 policyId) {
        // Create policy for ERC1155 blacklist
        policyId = _createBlankPolicy();

        // Add specific calling function for safeTransferFrom (ERC1155)
        vm.stopPrank();
        vm.startPrank(policyAdmin);
        ParamTypes[] memory pTypes = new ParamTypes[](5);
        pTypes[0] = ParamTypes.ADDR; // from
        pTypes[1] = ParamTypes.ADDR; // to
        pTypes[2] = ParamTypes.UINT; // id
        pTypes[3] = ParamTypes.UINT; // amount
        pTypes[4] = ParamTypes.BYTES; // data

        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyId,
            bytes4(keccak256("safeTransferFrom(address,address,uint256,uint256,bytes)")),
            pTypes,
            "safeTransferFrom(address,address,uint256,uint256,bytes)",
            ""
        );

        // to != BLACKLISTED_USER → PASS (if false, revert)
        Rule memory rule;
        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0; // references 'to' address
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(uint160(BLACKLISTED_USER));
        rule.instructionSet[4] = uint(LogicalOp.NOTEQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 1; // 'to' parameter

        // If condition is false (blacklisted), revert
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(
            policyId,
            rule,
            "ERC1155 Blacklist",
            "Prevent blacklisted users from receiving ERC1155 tokens"
        );

        // Update policy with the rule
        bytes4[] memory functions = new bytes4[](1);
        functions[0] = bytes4(keccak256("safeTransferFrom(address,address,uint256,uint256,bytes)"));
        uint256[] memory functionIds = new uint256[](1);
        functionIds[0] = callingFunctionId;
        uint256[][] memory ruleIdsArray = new uint256[][](1);
        ruleIdsArray[0] = new uint256[](1);
        ruleIdsArray[0][0] = ruleId;

        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyId,
            functions,
            functionIds,
            ruleIdsArray,
            PolicyType.CLOSED_POLICY,
            "policyName",
            "policyDescription"
        );

        return policyId;
    }
}
