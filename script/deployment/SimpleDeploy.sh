#!/bin/bash
echo "################################################################"
echo Build and deploy Aquifi Rules Diamond
echo "################################################################"
echo

forge script script/deployment/DeployRulesDiamond.s.sol --ffi --broadcast -vvv --non-interactive --rpc-url=$ETH_RPC_URL --gas-price $GAS_NUMBER  --legacy