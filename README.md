## `P256Verifier` Solidity contract

This repo implements a gas-efficient P256 signature verifier. Verifying a signature costs about 350k gas. Pure function, no precomputation. This implementation was inspired by [Renaud Dubois/Ledger's implementation](https://github.com/rdubois-crypto/FreshCryptoLib).

The contract matches the proposed [EIP-7212 precompile](https://eips.ethereum.org/EIPS/eip-7212), letting us ship it as a [progressive precompile](https://ethereum-magicians.org/t/progressive-precompiles-via-create2-shadowing/).

**The contract exists at a deterministic CREATE2 address. You can use it on any EVM chain. If the chain implements EIP-7212 at the same CREATE2 address, you pay ~3k gas. If not, you pay ~200k gas. Either way, the contract address and results are identical.** This is particularly beneficial for chains that want to maintain full EVM compatibility while adding this new precompiles (upto gas schedules).

The secp256r1 elliptic curve, aka P256, is interesting because it's supported by high-quality consumer enclaves including Yubikey, Apple's Secure Enclave, the Android Keystore, and WebAuthn. P256 verification is especially useful for contract wallets, enabling hardware-based signing keys.

## Usage

**Address `0x86e49A916721C4542CD1378D43c9f5C7B501de81`**

Available on any chain. If missing, see `deploy.sh`.

```solidity
bytes32 hash; // message hash
uint256 r, s; // signature
uint256 x, y; // public key

address verifier = 0x86e49A916721C4542CD1378D43c9f5C7B501de81;
bytes memory args = abi.encode(hash, r, s, x, y);
(bool success, bytes memory ret) = verifier.staticcall(args);
assert(success); // never reverts, always returns 0 or 1
bool valid = abi.decode(ret, (uint256)) == 1;
```

## Development

Run `foundryup` to ensure you have the latest foundry. Then,

```
git clone --recurse-submodules git@github.com:daimo-eth/p256-verifier
cd p256-verifier
forge test --via-ir -vv
```

This runs test input and output handling as well as all applicable Wycheproof
test vectors, covering a range of edge cases.

<details>
<summary>Code coverage</summary>
Install the recommended VSCode extension to view line-by-line test coverage.
To regenerate coverage:

```
forge coverage --via-ir --ir-minimum --report lcov
```

</details>

<details>
<summary>Test vectors</summary>

To regenerate test vectors:

```
cd test-vectors
npm i

# Download, extract, clean test vectors
# This regenerates ../test/vectors.jsonl
npm start

# Validate that all vectors produce expected results with SubtleCrypto and noble library implementation
npm test

# Validate that all vectors also work with EIP-7212
# Test the fallback contract...
cd ..
forge test --via-ir -vv

# In future, execution spec and clients can test against the same clean vectors
```

</details>
