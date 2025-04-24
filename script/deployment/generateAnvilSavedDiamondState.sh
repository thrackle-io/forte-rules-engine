#!/bin/bash

#!/bin/bash

# This script automates the process of deploying contracts using Anvil and Forge.
# It starts an Anvil instance in the background, runs the deployment script, and saves the Anvil state to a JSON file.
# After deployment, it terminates the Anvil process to clean up resources.
# 
# Steps:
# 1. Start Anvil in the background and save its process ID (PID).
# 2. Wait briefly to ensure Anvil is fully initialized.
# 3. Source environment variables from the `.env` file.
# 4. Execute the deployment script (`SimpleDeploy.sh`) using Forge.
# 5. Terminate the Anvil process using the saved PID.
# 6. Optionally, wait for the Anvil process to fully terminate.

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