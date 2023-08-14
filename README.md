## EIP-7212 fallback `P256Verifier` contract

This repo implements a gas-efficient P256 signature verifier based on [Renaud Dubois from Ledger's implementation](https://github.com/rdubois-crypto/FreshCryptoLib).

Verifying a signature costs about 200k gas. Pure function, no precomputation.

This implementation is a fallback contract exactly matching the proposed [EIP-7212 precompile](https://eips.ethereum.org/EIPS/eip-7212), letting us ship it as a [progressive precompile](https://ethereum-magicians.org/t/progressive-precompiles-via-create2-shadowing/).

**The contract exists at a deterministic CREATE2 address. You can use it on any EVM chain. If a chain has implemented EIP-7212, you pay ~3k gas. If not, you pay ~200k gas. Either way, the contract address and results are identical.**

The secp256r1 elliptic curve, aka P256, is interesting because it's a widely implemented standard. P256 is used in hardware keys such as Yubikey, Apple's Secure Element, the Android Keystore, and WebAuthn. P256 verification is especially useful for contract wallets, enabling hardware-based signing keys.

## Development

Run `foundryup` to ensure you have the latest foundry. Then,

```
git clone --recurse-submodules git@github.com:daimo-eth/eip-7212
cd eip-7212
forge test
```
