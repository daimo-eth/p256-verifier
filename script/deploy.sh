
# Deploy contract
forge script DeployScript --via-ir --optimizer-runs=999999 --rpc-url $RPC_URL --broadcast --private-key $PRIVATE_KEY

# Update contract address
ADDR=0xA77aB3533750B0C4b229e441fEe37f13c65A2b1F

# Verify to Etherscan
forge verify-contract $ADDR P256Verifier --optimizer-runs=999999 --constructor-args "0x" --show-standard-json-input > script/etherscan.json

# Workaround foundry bug. https://github.com/foundry-rs/foundry/issues/3507
# Manually add "viaIR": true to etherscan.json
# Finally, manually verify to Etherscan

# Success
# https://goerli.basescan.org/address/0xA77aB3533750B0C4b229e441fEe37f13c65A2b1F#code