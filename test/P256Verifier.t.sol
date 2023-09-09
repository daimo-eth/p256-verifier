// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import {Test, console2} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {P256Verifier} from "../src/P256Verifier.sol";

using stdJson for string;

contract P256VerifierTest is Test {
    P256Verifier public verifier;

    function setUp() public {
        verifier = new P256Verifier();
    }

    /** Checks a single test vector: signature rs, pubkey Q = (x,y). */
    function evaluate(
        bytes32 hash,
        uint256 r,
        uint256 s,
        uint256 x,
        uint256 y
    ) private returns (bool) {
        bytes memory input = abi.encodePacked(hash, r, s, x, y);
        (bool success, bytes memory result) = address(verifier).call(input);
        assertEq(success, true, "call failed");
        assertEq(result.length, 32, "invalid result length");
        uint256 res = abi.decode(result, (uint256));
        assertTrue(res == 1 || res == 0, "invalid result");
        return res == 1;
    }

    function testBasic() public {
        // Zero inputs
        bool res = evaluate(
            bytes32(
                0x1111111122222222333333334444444455555555666666667777777788888888
            ),
            0x00,
            0x00,
            0x00,
            0x00
        );
        assertEq(res, false);

        // First valid Wycheproof vector
        uint256 x = 18614955573315897657680976650685450080931919913269223958732452353593824192568;
        uint256 y = 90223116347859880166570198725387569567414254547569925327988539833150573990206;
        res = evaluate(
            0xbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023,
            19738613187745101558623338726804762177711919211234071563652772152683725073944,
            34753961278895633991577816754222591531863837041401341770838584739693604822390,
            x,
            y
        );
        assertEq(res, true);

        // Same as above, but off by 1
        res = evaluate(
            0xbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023,
            19738613187745101558623338726804762177711919211234071563652772152683725073943,
            34753961278895633991577816754222591531863837041401341770838584739693604822390,
            x,
            y
        );
        assertEq(res, false);
    }

    function testWycheproof() public {
        string memory file = "./test/vectors.jsonl";
        while (true) {
            string memory vector = vm.readLine(file);
            if (bytes(vector).length == 0) {
                break;
            }

            uint256 x = vector.readUint(".x");
            uint256 y = vector.readUint(".y");
            uint256 r = vector.readUint(".r");
            uint256 s = vector.readUint(".s");
            bytes32 hash = vector.readBytes32(".hash");
            string memory expectedResult = vector.readString(".result");
            string memory comment = vector.readString(".comment");

            bool expected = keccak256(abi.encodePacked(expectedResult)) ==
                keccak256("valid");
            bool allowEither = keccak256(abi.encodePacked(expectedResult)) ==
                keccak256("acceptable");

            bool result = evaluate(hash, r, s, x, y);

            if (allowEither) {
                console2.log("ACCEPTABLE ", comment, ": we return ", result);
                continue; // Don't fail test either way
            }
            string memory err = string(
                abi.encodePacked(
                    "exp ",
                    expected ? "1" : "0",
                    " we return ",
                    result ? "1" : "0",
                    ": ",
                    comment
                )
            );
            assertTrue(result == expected, err);
        }
    }
}
