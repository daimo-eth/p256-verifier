// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.19;

import {Test, console2} from "forge-std/Test.sol";
import {P256Verifier} from "../src/P256Verifier.sol";

contract CounterTest is Test {
    P256Verifier public verifier;

    function setUp() public {
        verifier = new P256Verifier();
    }

    /** Checks a single test vector: signature rs, pubkey Q. */
    function checkCase(
        bytes32 hash,
        uint256 r,
        uint256 s,
        uint256 x,
        uint256 y,
        bool isValid
    ) private {
        bytes memory input = abi.encodePacked(hash, r, s, x, y);
        (bool success, bytes memory result) = address(verifier).call(input);
        assertEq(success, true, "call failed");
        assertEq(result.length, 32, "invalid result length");
        uint256 res = abi.decode(result, (uint256));
        assertEq(res, isValid ? 1 : 0, "invalid result");
    }

    function testBasic() public {
        checkCase(
            bytes32(
                0x1111111122222222333333334444444455555555666666667777777788888888
            ),
            0x00,
            0x00,
            0x00,
            0x00,
            false
        );

        // First valid Wycheproof vector
        uint256 x = 18614955573315897657680976650685450080931919913269223958732452353593824192568;
        uint256 y = 90223116347859880166570198725387569567414254547569925327988539833150573990206;
        checkCase(
            0xbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023,
            19738613187745101558623338726804762177711919211234071563652772152683725073944,
            34753961278895633991577816754222591531863837041401341770838584739693604822390,
            x,
            y,
            true
        );

        // Same as above, but off by 1
        checkCase(
            0xbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023,
            19738613187745101558623338726804762177711919211234071563652772152683725073943,
            34753961278895633991577816754222591531863837041401341770838584739693604822390,
            x,
            y,
            false
        );
    }
}
