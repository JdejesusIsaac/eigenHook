// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IOFT, SendParam, MessagingFee, MessagingReceipt, OFTReceipt } from "@layerzerolabs/oft-evm/contracts/interfaces/IOFT.sol";


/// @notice Stargate implementation type.
enum StargateType {
    Pool,
    OFT
}

/// @notice Ticket data for bus ride.
struct Ticket {
    uint72 ticketId;
    bytes passengerBytes;
}

/// @title Interface for Stargate.
/// @notice Defines an API for sending tokens to destination chains.
interface IStargate is IOFT {
    /// @dev This function is same as `send` in OFT interface but returns the ticket data if in the bus ride mode,
    /// which allows the caller to ride and drive the bus in the same transaction.
    function sendToken(
        SendParam calldata _sendParam,
        MessagingFee calldata _fee,
        address _refundAddress
    ) external payable returns (MessagingReceipt memory msgReceipt, OFTReceipt memory oftReceipt, Ticket memory ticket);

    /// @notice Returns the Stargate implementation type.
    function stargateType() external pure returns (StargateType);
}

