// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import "./utils/Base64URL.sol";
import "./P256.sol";

/**
 * Helper library for external contracts to verify WebAuthn signatures.
 **/
library WebAuthn {
    function contains(
        string memory substr,
        string memory str,
        uint256 location
    ) internal pure returns (bool) {
        bytes memory substr_bytes = bytes(substr);
        bytes memory str_bytes = bytes(str);

        uint256 substr_len = substr_bytes.length;
        uint256 str_len = str_bytes.length;

        for (uint256 i = 0; i < substr_len; i++) {
            if (location + i >= str_len) {
                return false;
            }

            if (substr_bytes[i] != str_bytes[location + i]) {
                return false;
            }
        }
        return true;
    }

    function checkAuthFlags(
        bytes1 flags,
        bool requireUserVerification
    ) internal pure returns (bool) {
        // Check the UP bit
        if (flags & 0x01 != 0x01) {
            return false;
        }

        // Check the UV bit
        if (requireUserVerification && (flags & 0x04) != 0x04) {
            return false;
        }

        return true;
    }

    function verifySignature(
        bytes memory challenge,
        bytes memory authenticatorData,
        bool requireUserVerification,
        string memory clientDataJSON,
        uint256 challengeLocation,
        uint256 r,
        uint256 s,
        uint256 x,
        uint256 y
    ) public view returns (bool) {
        // Check that authenticatorData has good flags
        if (!checkAuthFlags(authenticatorData[32], requireUserVerification)) {
            return false;
        }

        // Check that challenge is in the clientDataJSON
        string memory challenge_b64url = Base64URL.encode(challenge);
        string memory challenge_property = string.concat(
            '"challenge":"',
            challenge_b64url,
            '"'
        );

        if (!contains(challenge_property, clientDataJSON, challengeLocation)) {
            return false;
        }

        bytes32 clientDataJSON_hash = sha256(bytes(clientDataJSON));
        bytes32 message_hash = sha256(
            abi.encodePacked(authenticatorData, clientDataJSON_hash)
        );

        return P256.verifySignature(message_hash, r, s, x, y);
    }
}
