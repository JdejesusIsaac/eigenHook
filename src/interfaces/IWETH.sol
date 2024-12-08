// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IWETH is IERC20 {
    /// @notice Deposit ETH and receive WETH
    /// @dev Allows users to deposit ETH and receive WETH tokens 1:1
    function deposit() external payable;

    /// @notice Withdraw ETH from WETH
    /// @dev Burns WETH tokens and returns ETH to the caller
    /// @param amount The amount of WETH to withdraw
    function withdraw(uint256 amount) external;

    /// @notice Deposit ETH for another address
    /// @dev Allows depositing ETH and minting WETH directly to another address
    /// @param account The address to receive the WETH tokens
    function depositTo(address account) external payable;

    /// @notice Withdraw ETH to another address
    /// @dev Burns WETH tokens from caller and sends ETH to specified address
    /// @param account The address to receive the ETH
    /// @param amount The amount of WETH to withdraw
    function withdrawTo(address account, uint256 amount) external;

    /// @notice Transfer ETH to address with additional data
    /// @dev Useful for contracts that need to receive ETH with data
    /// @param to The address to receive the ETH
    /// @param value The amount of ETH to send
    /// @param data Additional data to send with the transfer
    function transfer(address to, uint value, bytes calldata data) external returns (bool);

    /// @notice Events emitted for deposits and withdrawals
    event Deposit(address indexed dst, uint wad);
    event Withdrawal(address indexed src, uint wad);
}

// Optional: Extended interface for flash loans if the WETH implementation supports it
interface IWETHExtended is IWETH {
    /// @notice Execute a flash loan
    /// @param receiver Address of the contract receiving the flash loan
    /// @param amount Amount of WETH to flash loan
    /// @param data Arbitrary data to pass to the receiver
    function flash(
        address receiver,
        uint256 amount,
        bytes calldata data
    ) external;

    /// @notice Event emitted on flash loan
    event Flash(
        address indexed receiver,
        uint256 amount,
        uint256 fee
    );
}

// Interface that contracts must implement to receive flash loans
interface IWETHFlashCallback {
    /// @notice Called after contract receives the flash loaned amount
    /// @param fee The fee that needs to be paid on flash loan repayment
    /// @param data Arbitrary data passed by the flash loan initiator
    function WETHFlashCallback(
        uint256 fee,
        bytes calldata data
    ) external;
}

// Example of WETH9 specific interface (most commonly used version)
interface IWETH9 is IWETH {
    /// @notice Returns the name of the token
    function name() external view returns (string memory);

    /// @notice Returns the symbol of the token
    function symbol() external view returns (string memory);

    /// @notice Returns the number of decimals of the token
    function decimals() external view returns (uint8);
}

// Helper interface for permit functionality (if supported)
interface IWETHPermit {
    /// @notice EIP-2612 permit function
    /// @param owner The owner of the tokens
    /// @param spender The spender to approve
    /// @param value The amount to approve
    /// @param deadline The deadline for the signature
    /// @param v The recovery byte of the signature
    /// @param r Half of the ECDSA signature pair
    /// @param s Half of the ECDSA signature pair
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    /// @notice Returns the current nonce for an address
    /// @param owner The address to get the nonce for
    /// @return The current nonce
    function nonces(address owner) external view returns (uint256);

    /// @notice The EIP-712 domain separator
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}