
# Deploy and verify contract
forge script DeployScript --rpc-url $RPC_URL --broadcast --private-key $PRIVATE_KEY --verify --etherscan-api-key $ETHERSCAN_API_KEY
