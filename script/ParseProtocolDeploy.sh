#!/bin/bash

ENV_FILE=".env"

CHAIN_ID=31337
settingChainID=false

  for var in "$@"
  do
    if [[ "$var" = "--chainid" ]]
    then
      settingChainID=true
    elif $settingChainID;
    then
      CHAIN_ID="$var"
      settingVal=false
    elif [[ "$var" = "--help" ]]
    then
      echo "--------------------------------------------------"
      echo "Possible Arguments:"
      echo "--chainid - set the chain id for the deployment"
      echo "--------------------------------------------------"
      exit
    else
      echo "Unknown Argument"
    fi
  done

# Retreive the Rule Processor Diamond Address
RULE_PROCESSOR_DIAMOND_UNCUT=$(jq '.transactions[] | select(.contractName=="RuleProcessorDiamond") | .contractAddress' broadcast/DeployAllModules.s.sol/$CHAIN_ID/run-latest.json)

RULE_PROCESSOR_DIAMOND="${RULE_PROCESSOR_DIAMOND_UNCUT//\"}"

echo $RULE_PROCESSOR_DIAMOND
echo 

QUORRA=$(sed -n 's/QUORRA=//p' .env)
QUORRA_PRIVATE_KEY=$(sed -n 's/QUORRA_PRIVATE_KEY=//p' .env) 

os=$(uname -a)
if [[ $os == *"Darwin"* ]]; then
  sed -i '' 's/RULE_PROCESSOR_DIAMOND=.*/RULE_PROCESSOR_DIAMOND='$RULE_PROCESSOR_DIAMOND'/g' $ENV_FILE
  sed -i '' 's/DEPLOYMENT_RULE_PROCESSOR_DIAMOND=.*/DEPLOYMENT_RULE_PROCESSOR_DIAMOND='$RULE_PROCESSOR_DIAMOND'/g' $ENV_FILE
else
  sed -i 's/RULE_PROCESSOR_DIAMOND=.*/RULE_PROCESSOR_DIAMOND='$RULE_PROCESSOR_DIAMOND'/g' $ENV_FILE
  sed -i 's/DEPLOYMENT_RULE_PROCESSOR_DIAMOND=.*/DEPLOYMENT_RULE_PROCESSOR_DIAMOND='$RULE_PROCESSOR_DIAMOND'/g' $ENV_FILE
fi

if [[ $os == *"Darwin"* ]]; then
  sed -i '' 's/^DEPLOYMENT_OWNER=.*/DEPLOYMENT_OWNER='$QUORRA'/g' $ENV_FILE
  sed -i '' 's/^DEPLOYMENT_OWNER_KEY=.*/DEPLOYMENT_OWNER_KEY='$QUORRA_PRIVATE_KEY'/g' $ENV_FILE
else
  sed -i 's/^DEPLOYMENT_OWNER=.*/DEPLOYMENT_OWNER='$QUORRA'/g' $ENV_FILE
  sed -i 's/^DEPLOYMENT_OWNER_KEY=.*/DEPLOYMENT_OWNER_KEY='$QUORRA_PRIVATE_KEY'/g' $ENV_FILE
fi