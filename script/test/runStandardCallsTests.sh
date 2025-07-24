#!/bin/bash

# Focused Standard Calls Fork Testing Script
# Tests Rules Engine with real mainnet contracts and clear happy/sad path validation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Rules Engine Standard Calls Fork Tests ===${NC}"

# Check if MAINNET_RPC_URL is set
if [ -z "$MAINNET_RPC_URL" ]; then
    echo -e "${YELLOW}Warning: MAINNET_RPC_URL not set.${NC}"
    echo "To run fork tests, set MAINNET_RPC_URL environment variable:"
    echo "export MAINNET_RPC_URL=https://mainnet.infura.io/v3/YOUR_API_KEY"
    echo ""
    echo -e "${RED}Skipping all fork tests${NC}"
    exit 1
fi

echo -e "${GREEN}Using mainnet fork for realistic protocol testing${NC}"
echo ""

# Focused test categories - each with happy and sad path
TESTS=(
    "testOpenSeaMarketplaceTransfer_HappyAndSadPath"
    "testUniswapRouterERC20Transfer_HappyAndSadPath" 
    "testLidoStakingFlow_HappyAndSadPath"
    "testOpenSeaERC1155Transfer_HappyAndSadPath"
    "testRealMainnetContracts_GasComparison"
)

echo -e "${GREEN}Running focused integration tests with real mainnet contracts:${NC}"
echo "✓ OpenSea Seaport marketplace whitelist rules"
echo "✓ Uniswap router transfer amount limits"
echo "✓ Lido staking minimum amount rules"
echo "✓ OpenSea ERC1155 transfer limits"
echo "✓ Gas comparison with real mainnet contracts"
echo ""

for test in "${TESTS[@]}"; do
    echo -e "${YELLOW}🔄 Running: $test${NC}"
    
    forge test --match-test "$test" --fork-url "$MAINNET_RPC_URL" -vv --gas-report
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ $test passed${NC}"
    else
        echo -e "${RED}❌ $test failed${NC}"
    fi
    echo ""
done

echo -e "${GREEN}Running complete test suite...${NC}"
forge test --match-contract "StandardCallsForked" --fork-url "$MAINNET_RPC_URL" -vv --gas-report

echo ""
echo -e "${GREEN}=== TEST SUMMARY ===${NC}"
echo "✅ Marketplace whitelist rules (OpenSea Seaport)"
echo "✅ DEX integration rules (Uniswap Router)" 
echo "✅ Staking protocol rules (Lido)"
echo "✅ Multi-token standard support (ERC20/721/1155)"
echo "✅ Happy path: Rules allow legitimate transactions"
echo "✅ Sad path: Rules block unauthorized transactions"
echo "✅ Gas analysis: Performance impact measurement"
echo ""
echo -e "${GREEN}All tests validate Rules Engine integration with real mainnet protocols!${NC}"
