#!/usr/bin/env bash
export $(grep -v -e '^#'  -e '^MNEMONIC' .env | xargs -0)
# Exit immediately if a command exits with a non-zero status.
set -e
echo "Starting deployment for $NETWORK environment"
# Copy address from previous deployment, if it exists
if [[ -f "deployed/$NETWORK/addresses.json" ]]
then
    echo "Previous addresses"
    cat deployed/$NETWORK/addresses.json
    cp deployed/$NETWORK/addresses.json .previous-deployment-addresses
    rm -rf deployed/$NETWORK
fi

echo "Deploying contracts on network $NETWORK"
 npx hardhat --network $NETWORK deploy --show-stack-traces

mkdir -p deployed/$NETWORK
cp -r artifacts deployed/$NETWORK/abi
cat .contract-deployment.tmp.json | jq '.' > deployed/$NETWORK/addresses.json
rm -rf .contract-deployment.tmp.json

if [[ -f "./.previous-deployment-addresses" ]]
then
    rm -rf .previous-deployment-addresses
fi

echo "Done"