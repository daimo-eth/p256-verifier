// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import "openzeppelin-contracts/contracts/utils/Base64.sol";

library Base64URL {
    function encode(bytes memory data) public pure returns (string memory) {
        string memory strb64 = Base64.encode(data);
        bytes memory b64 = bytes(strb64);

        // count and ignore all "=" symbols from the end of the string
        uint256 equalsCount = 0;
        for (int256 i = int256(b64.length) - 1; i >= 0; i--) {
            if (b64[uint256(i)] == "=") {
                equalsCount++;
            } else {
                break;
            }
        }

        uint256 len = b64.length - equalsCount;
        bytes memory result = new bytes(len);

        for (uint256 i = 0; i < len; i++) {
            if (b64[i] == "+") {
                result[i] = "-";
            } else if (b64[i] == "/") {
                result[i] = "_";
            } else {
                result[i] = b64[i];
            }
        }

        return string(result);
    }
}
