#!/bin/bash
# This script should only be run after the environment variables are set
# correctly according to docs/userGuides/deployment/DEPLOY-PROTOCOL.md
echo "################################################################"
echo Build and deploy an Example Application Architecture
echo "################################################################"
echo

echo "################################################################"
echo Deploy the AppManager and ApplicationHandler
echo "################################################################"
echo
forge script script/clientScripts/Application_Deploy_01_AppManager.s.sol --ffi --broadcast

echo "################################################################"
echo Retrieve the contract info and set environment variables
echo "################################################################"
echo
bash script/ParseApplicationDeploy.sh 1

echo "################################################################"
echo Deploy the ApplicationERC20 and the Handler Diamond
echo "################################################################"
echo
forge script script/clientScripts/Application_Deploy_02_ApplicationFT1.s.sol --ffi --broadcast 

echo "################################################################"
echo Retrieve the contract info and set environment variables
echo "################################################################"
echo
bash script/ParseApplicationDeploy.sh 2

echo "################################################################"
echo Deploy the ApplicationERC721 and the Handler Diamond
echo "################################################################"
echo
forge script script/clientScripts/Application_Deploy_04_ApplicationNFT.s.sol --ffi --broadcast

echo "################################################################"
echo Retrieve the contract info and set environment variables
echo "################################################################"
echo
bash script/ParseApplicationDeploy.sh 3


echo "################################################################"
echo Deploy the Oracle Contracts
echo "################################################################"
echo
forge script script/clientScripts/Application_Deploy_05_Oracle.s.sol --ffi --broadcast 

echo "################################################################"
echo Retrieve the contract info and set environment variables
echo "################################################################"
echo
bash script/ParseApplicationDeploy.sh 4

echo "################################################################"
echo Deploy the Pricing Contracts
echo "################################################################"
echo
forge script script/clientScripts/Application_Deploy_06_Pricing.s.sol --ffi --broadcast

echo "################################################################"
echo Retrieve the contract info and set environment variables
echo "################################################################"
echo
bash script/ParseApplicationDeploy.sh 5