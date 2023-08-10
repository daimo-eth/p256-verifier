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
    function checkCase(bytes32 hash, uint256 r, uint256 s, uint256 x, uint256 y, bool isValid) private {
        bytes memory input = abi.encodePacked(hash, r, s, x, y);
        (bool success, bytes memory result) = address(verifier).call(input);
        assertEq(success, true, "call failed");
        assertEq(result.length, 32, "invalid result length");
        uint256 res = abi.decode(result, (uint256));
        assertEq(res, isValid ? 1 : 0, "invalid result");
    }

    function testBasic() public {
        checkCase(bytes32(0x1111111122222222333333334444444455555555666666667777777788888888), 0x00, 0x00, 0x00, 0x00, true);   
    }
}
