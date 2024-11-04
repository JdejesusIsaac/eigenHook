// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract StrategyBaseMock {
     IERC20 public underlyingToken;
    uint256 public totalShares;
    mapping(address => uint256) public userShares;

    event Deposit(address indexed user, uint256 amount, uint256 shares);
    event Withdraw(address indexed user, uint256 shares, uint256 amount);

    constructor(IERC20 _underlyingToken) {
        underlyingToken = _underlyingToken;
    }

    /**
     * @notice Deposits tokens into the strategy and issues shares
     * @param token The token to deposit
     * @param amount The amount to deposit
     * @return shares The number of shares issued for the deposit
     */
    function deposit(IERC20 token, uint256 amount) external  returns (uint256 shares) {
        require(token == underlyingToken, "Invalid token");

        // Calculate shares based on a 1:1 ratio for simplicity (1 share per token deposited)
        shares = amount;

        // Update storage to reflect the new total shares and user shares
        totalShares += shares;
        userShares[msg.sender] += shares;

        emit Deposit(msg.sender, amount, shares);
        
        return shares; // Ensure shares are returned
    }

    /**
     * @notice Allows the strategy manager to withdraw tokens on behalf of a user
     * @param recipient The address to receive the tokens
     * @param token The token to withdraw
     * @param amountShares The amount of shares to redeem
     */
    function withdraw(address recipient, IERC20 token, uint256 amountShares) external {
        require(token == underlyingToken, "Invalid token");
        require(userShares[recipient] >= amountShares, "Insufficient shares");

        uint256 amountToSend = amountShares; // 1:1 token/share ratio

        // Update storage to reflect the redeemed shares
        totalShares -= amountShares;
        userShares[recipient] -= amountShares;

        // Transfer tokens to the recipient
        underlyingToken.transfer(recipient, amountToSend);

        emit Withdraw(recipient, amountShares, amountToSend);
    }
}
