// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

contract Reverter {
    fallback() external {
        revert("Reverter: I am a contract that always reverts");
    }
}

contract ReverterWithDecimals is Reverter {
    function decimals() external pure returns (uint8) {
        return 18;
    }
}