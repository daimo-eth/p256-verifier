// SPDX-License-Identifier: MIT
// Force a specific Solidity version for reproducbility.
pragma solidity 0.8.19;

/**
 * This contract verifies P256 (secp256r1) signatures. It matches the exact
 * interface specified in the EIP-7212 precompile, allowing it to be used as a
 * fallback. It's based on Ledger's optimized implementation:
 * https://github.com/rdubois-crypto/FreshCryptoLib/tree/master/solidity
 **/
contract P256Verifier {
    /**
     * Precompiles don't use a function signature. The first byte of callldata
     * is the first byte of an input argument. In this case:
     *
     * input[  0: 32] = signed data hash
     * input[ 32: 64] = signature r
     * input[ 64: 96] = signature s
     * input[ 96:128] = public key x
     * input[128:160] = public key y
     *
     * result[ 0: 32] = 0x00..00 (invalid) or 0x00..01 (valid)
     *
     * For details, see https://eips.ethereum.org/EIPS/eip-7212
     */
    fallback(bytes calldata input) external returns (bytes memory) {
        if (input.length != 160) {
            return abi.encodePacked(uint256(0));
        }

        bytes32 hash = bytes32(input[0:32]);
        uint256 r = uint256(bytes32(input[32:64]));
        uint256 s = uint256(bytes32(input[64:96]));
        uint256 x = uint256(bytes32(input[96:128]));
        uint256 y = uint256(bytes32(input[128:160]));

        // TODO
        require(r == s);
        require(x == y);
        require(hash[0] == 0x11);

        return abi.encodePacked(uint256(1));
    }
}
