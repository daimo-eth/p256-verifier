
# Deploy contract
forge script DeployScript --via-ir --optimizer-runs=999999 --rpc-url $RPC_URL --broadcast --private-key $PRIVATE_KEY

# Update contract address
ADDR=0x86e49A916721C4542CD1378D43c9f5C7B501de81

# Verify to Etherscan
forge verify-contract $ADDR P256Verifier --optimizer-runs=999999 --constructor-args "0x" --show-standard-json-input > script/etherscan.json

# Workaround foundry bug. https://github.com/foundry-rs/foundry/issues/3507
# Manually add "viaIR": true to etherscan.json
# Finally, manually verify to Etherscan

# Success
# https://goerli.basescan.org/address/0x86e49A916721C4542CD1378D43c9f5C7B501de81#code