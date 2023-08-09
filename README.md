This repo implements a gas-efficient P256 signature verifier based on [Renaud Dubois / Ledger's implementation](https://github.com/rdubois-crypto/FreshCryptoLib).

Verifying a signature costs about 200k gas. Pure function, no precomputation.

This implementation is a fallback contract exactly matching the proposed [EIP-7212 precompile](https://eips.ethereum.org/EIPS/eip-7212). This lets us ship it as a [progressive precompile](https://ethereum-magicians.org/t/progressive-precompiles-via-create2-shadowing/).

**The contract exists at a deterministic CREATE2 address. This means you can use it on any EVM chain. If a chain has implemented EIP-7212, you pay ~3k gas. If not, you pay ~200k gas, but results are identical.**

The secp256r1 elliptic curve, aka P256, is interesting because it's a widely implemented standard used in hardware keys such as Yubikey, iOS Secure Element, Android Keystore, and WebAuthn. P256 verification is especially useful for contract wallets, enabling hardware-based signing keys.
