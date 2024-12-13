#!/bin/bash

# Start anvil in background and save its PID
anvil --dump-state diamondDeployedAnvilState.json & 
ANVIL_PID=$!

# Wait a moment for anvil to start up
sleep 2

source .env
# Run forge command
. ./script/deployment/SimpleDeploy.sh

# Kill anvil using the saved PID
kill $ANVIL_PID

# Optional: Wait for anvil to fully terminate
wait $ANVIL_PID