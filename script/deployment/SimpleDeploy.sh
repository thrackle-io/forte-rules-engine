#!/bin/bash
echo "################################################################"
echo Build and deploy Rules Diamond
echo "################################################################"
echo

# Explicitly export variables from .env
export ETH_RPC_URL=$(grep ETH_RPC_URL .env | cut -d '=' -f2)
export GAS_NUMBER=$(grep GAS_NUMBER .env | cut -d '=' -f2)

forge script script/deployment/DeployRulesDiamond.s.sol --ffi --broadcast -vvv --non-interactive --rpc-url="${ETH_RPC_URL}" --gas-price="${GAS_NUMBER}" --legacy
