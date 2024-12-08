// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title Simplified Lido Interface
 * @dev This contract exposes only the submit function of the Lido contract.
 */
interface ILido {
    /**
     * @notice Send funds to the Lido staking pool with an optional referral address
     * @dev This function allows users to deposit ETH and receive stETH in return.
     * @param _referral Address of the referral (optional).
     * @return Amount of StETH shares generated.
     */
    function submit(address _referral) external payable returns (uint256);
}
