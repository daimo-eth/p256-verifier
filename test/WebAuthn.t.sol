// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {Test, console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {WebAuthn} from "../src/WebAuthn.sol";

contract WebAuthnTest is Test {
    // Simple manual test
    function testHandParsed() public {
        uint256[2] memory publicKey = [
            0x80d9326e49eb6314d03f58830369ea5bafbc4e2709b30bff1f4379586ca869d9,
            0x806ed746d8ac6c2779a472d8c1ed4c200b07978d9d8d8d862be8b7d4b7fb6350
        ];

        uint256 r = 0x32e005a53ae49a96ac88c715243638dd5c985fbd463c727d8eefd05bee4e2570;
        uint256 s = 0x7a4fef4d0b11187f95f69eefbb428df8ac799bbd9305066b1e9c9fe9a5bcf8c4;

        string
            memory clientDataJSON = '{"type":"webauthn.get","challenge":"dGVzdA","origin":"https://funny-froyo-3f9b75.netlify.app"}';
        bytes memory challenge = hex"74657374";
        uint256 challengeLocation = 23;
        bytes
            memory authenticatorData = hex"e0b592a7dd54eedeec65206e031fc196b8e5915f9b389735860c83854f65dc0e1d00000000";

        bool ret = WebAuthn.verifySignature({
            challenge: challenge,
            authenticatorData: authenticatorData,
            requireUserVerification: false,
            clientDataJSON: clientDataJSON,
            challengeLocation: challengeLocation,
            responseTypeLocation: 1,
            r: r,
            s: s,
            x: publicKey[0],
            y: publicKey[1]
        });
        assertTrue(ret);
    }
}
