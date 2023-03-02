#!/usr/bin/env bash
export $(grep -v -e '^#'  -e '^MNEMONIC' .env | xargs -0)
# Exit immediately if a command exits with a non-zero status.
set -e
echo "Starting deployment for $NETWORK environment"

echo "Deploying source chain contract on network $NETWORK"
 npx hardhat run scripts/deploySourceChain.ts --network $NETWORK --show-stack-traces 

mkdir -p deployed/$NETWORK
cp -r artifacts deployed/$NETWORK/abi
cat .deployment.tmp.json | jq '.' > deployed/$NETWORK/sourceChainaddress.json
rm -rf .deployment.tmp.json

echo "Done"