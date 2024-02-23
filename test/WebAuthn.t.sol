// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Test, console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {WebAuthn} from "../src/WebAuthn.sol";
import {P256} from "../src/P256.sol";
import {P256Verifier} from "../src/P256Verifier.sol";

contract WebAuthnTest is Test {
    uint256[2] publicKey = [
        0x80d9326e49eb6314d03f58830369ea5bafbc4e2709b30bff1f4379586ca869d9,
        0x806ed746d8ac6c2779a472d8c1ed4c200b07978d9d8d8d862be8b7d4b7fb6350
    ];
    string clientDataJSON =
        '{"type":"webauthn.get","challenge":"dGVzdA","origin":"https://funny-froyo-3f9b75.netlify.app"}';
    bytes challenge = hex"74657374";
    bytes authenticatorData =
        hex"e0b592a7dd54eedeec65206e031fc196b8e5915f9b389735860c83854f65dc0e1d00000000";
    uint256 r =
        0x32e005a53ae49a96ac88c715243638dd5c985fbd463c727d8eefd05bee4e2570;
    uint256 s =
        0x7a4fef4d0b11187f95f69eefbb428df8ac799bbd9305066b1e9c9fe9a5bcf8c4;
    uint256 challengeLocation = 23;
    uint256 responseTypeLocation = 1;

    function setUp() public {
        // Deploy P256 Verifier
        vm.etch(P256.VERIFIER, type(P256Verifier).runtimeCode);
    }

    // Simple manual valid signature test
    function testHandParsed() public {
        bool ret = WebAuthn.verifySignature({
            challenge: challenge,
            authenticatorData: authenticatorData,
            requireUserVerification: false,
            clientDataJSON: clientDataJSON,
            challengeLocation: challengeLocation,
            responseTypeLocation: responseTypeLocation,
            r: r,
            s: s,
            x: publicKey[0],
            y: publicKey[1]
        });
        assertTrue(ret);
    }

    // Test failures in contains() function
    function testContains() public {
        bool ret;
        uint256 customChallengeLocation = challengeLocation;
        uint256 customResponseTypeLocation = responseTypeLocation;

        // Wrong challengeLocation
        customChallengeLocation = 50;
        ret = WebAuthn.verifySignature({
            challenge: challenge,
            authenticatorData: authenticatorData,
            requireUserVerification: false,
            clientDataJSON: clientDataJSON,
            challengeLocation: customChallengeLocation,
            responseTypeLocation: customResponseTypeLocation,
            r: r,
            s: s,
            x: publicKey[0],
            y: publicKey[1]
        });
        assertFalse(ret);

        // challengeLocation out of bounds of string
        customChallengeLocation = 100;
        ret = WebAuthn.verifySignature({
            challenge: challenge,
            authenticatorData: authenticatorData,
            requireUserVerification: false,
            clientDataJSON: clientDataJSON,
            challengeLocation: customChallengeLocation,
            responseTypeLocation: customResponseTypeLocation,
            r: r,
            s: s,
            x: publicKey[0],
            y: publicKey[1]
        });
        assertFalse(ret);

        // Wrong responseTypeLocation
        customChallengeLocation = 23;
        customResponseTypeLocation = 0;
        ret = WebAuthn.verifySignature({
            challenge: challenge,
            authenticatorData: authenticatorData,
            requireUserVerification: false,
            clientDataJSON: clientDataJSON,
            challengeLocation: customChallengeLocation,
            responseTypeLocation: customResponseTypeLocation,
            r: r,
            s: s,
            x: publicKey[0],
            y: publicKey[1]
        });
        assertFalse(ret);
    }

    // Test failures in checkAuthFlags() function
    function testAuthFlags() public {
        bool ret;
        bytes memory customAuthenticatorData = authenticatorData;

        // Too short authenticator data
        customAuthenticatorData = hex"00";
        ret = WebAuthn.verifySignature({
            challenge: challenge,
            authenticatorData: customAuthenticatorData,
            requireUserVerification: false,
            clientDataJSON: clientDataJSON,
            challengeLocation: challengeLocation,
            responseTypeLocation: responseTypeLocation,
            r: r,
            s: s,
            x: publicKey[0],
            y: publicKey[1]
        });
        assertFalse(ret);

        // No flags
        customAuthenticatorData = hex"00000000000000000000000000000000000000000000000000000000000000000000000000";
        ret = WebAuthn.verifySignature({
            challenge: challenge,
            authenticatorData: customAuthenticatorData,
            requireUserVerification: false,
            clientDataJSON: clientDataJSON,
            challengeLocation: challengeLocation,
            responseTypeLocation: responseTypeLocation,
            r: r,
            s: s,
            x: publicKey[0],
            y: publicKey[1]
        });
        assertFalse(ret);

        // User Verification not set data from SimpleWebauthn
        // https://github.com/MasterKale/SimpleWebAuthn/blob/master/packages/server/src/helpers/parseAuthenticatorData.test.ts#L14
        customAuthenticatorData = hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763810000008da1716578616d706c652e657874656e73696f6e78765468697320697320616e206578616d706c6520657874656e73696f6e2120496620796f7520726561642074686973206d6573736167652c20796f752070726f6261626c79207375636365737366756c6c792070617373696e6720636f6e666f726d616e63652074657374732e20476f6f64206a6f6221";
        ret = WebAuthn.verifySignature({
            challenge: challenge,
            authenticatorData: customAuthenticatorData,
            requireUserVerification: true,
            clientDataJSON: clientDataJSON,
            challengeLocation: challengeLocation,
            responseTypeLocation: responseTypeLocation,
            r: r,
            s: s,
            x: publicKey[0],
            y: publicKey[1]
        });
        assertFalse(ret);

        // Test BE and BS flags directly.
        bytes1 BE_not_set_BS_set = hex"15"; // hex(int('00010101', 2))
        customAuthenticatorData = authenticatorData;
        customAuthenticatorData[32] = BE_not_set_BS_set;
        ret = WebAuthn.verifySignature({
            challenge: challenge,
            authenticatorData: customAuthenticatorData,
            requireUserVerification: false,
            clientDataJSON: clientDataJSON,
            challengeLocation: challengeLocation,
            responseTypeLocation: responseTypeLocation,
            r: r,
            s: s,
            x: publicKey[0],
            y: publicKey[1]
        });
        assertFalse(ret);

        bytes1 BE_not_set_BS_not_set = hex"05"; // hex(int('00000101', 2))
        customAuthenticatorData = authenticatorData;
        customAuthenticatorData[32] = BE_not_set_BS_not_set;
        uint256 gasBefore = gasleft();
        ret = WebAuthn.verifySignature({
            challenge: challenge,
            authenticatorData: customAuthenticatorData,
            requireUserVerification: false,
            clientDataJSON: clientDataJSON,
            challengeLocation: challengeLocation,
            responseTypeLocation: responseTypeLocation,
            r: r,
            s: s,
            x: publicKey[0],
            y: publicKey[1]
        });
        uint256 gasUsed = gasBefore - gasleft();
        assert(gasUsed > 100_000); // didn't fail auth flags early check
        assertFalse(ret); // failed signature check instead
    }

    function testRequireUserVerification() public {
        bool ret = WebAuthn.verifySignature({
            challenge: challenge,
            authenticatorData: authenticatorData,
            requireUserVerification: true,
            clientDataJSON: clientDataJSON,
            challengeLocation: challengeLocation,
            responseTypeLocation: responseTypeLocation,
            r: r,
            s: s,
            x: publicKey[0],
            y: publicKey[1]
        });
        assertTrue(ret);
    }
}
