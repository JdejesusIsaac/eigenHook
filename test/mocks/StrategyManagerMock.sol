// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol"; // Import ERC20 interface
import "./StrategyBaseMock.sol"; 
 // Import StrategyBaseMock, ensure the correct contract name is used

contract StrategyManagerMock {
    using SafeERC20 for IERC20;

    // State variables
    IERC20 public immutable underlyingToken;
    uint256 public totalShares;
    mapping(address => uint256) public stakerShares;
    mapping(address => mapping(address => uint256)) public stakerStrategyShares;

    // Events
    event Deposit(
        address indexed staker,
        IERC20 indexed token,
        address indexed strategy,
        uint256 amount,
        uint256 shares
    );

    // Errors
    error InvalidToken();
    error TransferFailed();

    constructor(IERC20 _underlyingToken) {
        underlyingToken = _underlyingToken;
    }

    function depositToStrategy(
        address staker,
        IERC20 token,
        uint256 amount
    ) external returns (uint256 shares) {
        if (token != underlyingToken) revert InvalidToken();

        // Transfer tokens from msg.sender to this contract
        token.safeTransferFrom(msg.sender, address(this), amount);

        // 1:1 share ratio for simplicity
        shares = amount;
        
        // Update state
        stakerShares[staker] += shares;
        stakerStrategyShares[staker][address(this)] += shares;
        totalShares += shares;

        emit Deposit(staker, token, address(this), amount, shares);
        return shares;
    }

    function getStakerShares(address staker) external view returns (uint256) {
        return stakerShares[staker];
    }

    function getStrategyShares(address staker, address strategy) external view returns (uint256) {
        return stakerStrategyShares[staker][strategy];
    }
}

//shares = StrategyBaseMock(strategy).deposit(token, amount);
