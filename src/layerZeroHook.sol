
// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";

import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/src/types/BeforeSwapDelta.sol";
import {IStargate} from "../src/interfaces/IStargate.sol";
import { IOFT, SendParam, MessagingFee, MessagingReceipt, OFTReceipt } from "@layerzerolabs/oft-evm/contracts/interfaces/IOFT.sol";
//import {OftCmdHelper} from "@layerzerolabs/oft-evm/contracts/libraries/OftCmdHelper.sol";

import {Currency} from "v4-core/src/types/Currency.sol";
import {CurrencySettler} from "v4-core/test/utils/CurrencySettler.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";




contract crossStakingHook is BaseHook {
    using PoolIdLibrary for PoolKey;
    using CurrencySettler for Currency;

     enum PayFeesIn {
        Native
        
    }

    struct CrossChainSwapParams {
        PoolKey key;
        address receiver;
        IPoolManager.SwapParams params;
    }

    // NOTE: ---------------------------------------------------------
    // state variables should typically be unique to a pool
    // a single hook contract should be able to service multiple pools
    // ---------------------------------------------------------------

    
   

     // LayerZero Stargate
    address immutable stargateRouter;

    PayFeesIn public bridgeFeeTokenType = PayFeesIn.Native; // for local testing

    bytes32[] public receivedMessages; // Array to keep track of the IDs of received messages.

    // Event emitted when a message is received from another chain.
    
   

    constructor(
        IPoolManager _poolManager,
      
        
        address _stargateRouter
    ) BaseHook(_poolManager) {
      
       
        stargateRouter = _stargateRouter;
    }

    function getHookPermissions()
        public
        pure
        override
        returns (Hooks.Permissions memory)
    {
        return
            Hooks.Permissions({
                beforeInitialize: false,
                afterInitialize: false,
                beforeAddLiquidity: false,
                afterAddLiquidity: false,
                beforeRemoveLiquidity: false,
                afterRemoveLiquidity: false,
                beforeSwap: false,
                afterSwap: true, //
                beforeDonate: false,
                afterDonate: false,
                beforeSwapReturnDelta: false,
                afterSwapReturnDelta: true, //
                afterAddLiquidityReturnDelta: false,
                afterRemoveLiquidityReturnDelta: false
            });
    }

    function afterSwap(
        address,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        BalanceDelta delta,
        bytes calldata hookData,
        uint32 destinationChainSelector 
    ) external  returns (bytes4, int128) {
        if (hookData.length > 0) {
            (
                address receiver,
                bool isBridgeTx,
               
            ) = abi.decode(hookData, (address, bool, uint64));

            // TODO add more validations
            if (isBridgeTx && destinationChainSelector != 0) {
                // TODO handle ETH
                // handle zeroForOne trades
                int128 outputAmount = settleCurrencyLayerZero(
                    key,
                    delta,
                    params.zeroForOne,
                    receiver,
                    destinationChainSelector,
                    IStargate(stargateRouter)
                    
                );
                    
                return (BaseHook.afterSwap.selector, outputAmount);
            }
        }

        return (BaseHook.afterSwap.selector, 0);
    }

    function _unlockCallback(
        bytes calldata rawData
    ) internal virtual override  returns (bytes memory) {
        CrossChainSwapParams memory data = abi.decode(
            rawData,
            (CrossChainSwapParams)
        );

        BalanceDelta delta = poolManager.swap(data.key, data.params, "");

        if (delta.amount0() < 0) {
            data.key.currency0.settle(
                poolManager,
                data.receiver,
                uint128(-delta.amount0()),
                false
            );
        }
        if (delta.amount1() < 0) {
            data.key.currency1.settle(
                poolManager,
                data.receiver,
                uint128(-delta.amount1()),
                false
            );
        }
        if (delta.amount0() > 0) {
            data.key.currency0.take(
                poolManager,
                data.receiver,
                uint128(delta.amount0()),
                false
            );
        }
        if (delta.amount1() > 0) {
            data.key.currency1.take(
                poolManager,
                data.receiver,
                uint128(delta.amount1()),
                false
            );
        }

        return abi.encode(delta);
    }

   

     // LayerZero Stargate bridgeTokens implementation
   function bridgeTokensToLayerZero(
    address receiver,
    address outputToken,
    uint256 outputAmount,
    uint32 destinationChainSelector, // LayerZero endpoint ID for the destination chain
    IStargate stargate // Stargate contract instance
  //  MessagingFee memory messagingFee // Messaging fee details (calculated from Stargate)
   // address refundAddress // Address for refunding any leftover gas
) internal returns (uint256 valueToSend) {
    // Prepare the SendParam struct
    SendParam memory sendParam = SendParam({
        dstEid: destinationChainSelector,
        to: addressToBytes32(receiver),
        amountLD: outputAmount,
        minAmountLD: outputAmount, // Can set a slippage threshold if required
        extraOptions: new bytes(0),
        composeMsg: new bytes(0),
        oftCmd: "" // Use taxi mode for immediate bridging
    });

      MessagingFee memory messagingFee = IOFT(outputToken).quoteSend(
        sendParam,
        false);


    

    // Approve Stargate to spend the tokens
    IERC20(outputToken).approve(address(stargate), outputAmount);

   // Transfer tokens to the destination chain via Stargate
        stargate.sendToken{value: messagingFee.nativeFee}(
            sendParam,
            messagingFee,
            address(this) // Refund address (optional)
        );

       
         

        (, , OFTReceipt memory receipt) = stargate.quoteOFT(sendParam);
        sendParam.minAmountLD = receipt.amountReceivedLD;

        messagingFee = stargate.quoteSend(sendParam, false);
        valueToSend = messagingFee.nativeFee;

        if (stargate.token() == address(0x0)) {
            valueToSend += sendParam.amountLD;
        }

       
    // Optionally emit an event or handle the result if needed
   
}

function settleCurrencyLayerZero(
    PoolKey memory key,
    BalanceDelta delta,
    bool zeroForOne,
    address receiver,
    uint32 destinationChainSelector, // LayerZero endpoint ID for the destination chain
    IStargate stargate // Stargate contract instance
   // MessagingFee memory messagingFee // Messaging fee details (calculated from Stargate)
     // Address for refunding any leftover gas
) internal returns (int128) {
    int128 outputAmount = zeroForOne ? delta.amount1() : delta.amount0();
    Currency outputCurrency = zeroForOne ? key.currency1 : key.currency0;

    // Take the output currency from the pool
    poolManager.take(outputCurrency, address(this), uint128(outputAmount));

    // Get the token associated with the currency
    IERC20 outputToken = IERC20(Currency.unwrap(outputCurrency));

    // Bridge the tokens to the destination chain using Stargate
    bridgeTokensToLayerZero(
        receiver,
        address(outputToken),
        uint128(outputAmount),
        destinationChainSelector,
        stargate
        
       
    );

    return outputAmount;
}


function addressToBytes32(address _addr) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(_addr)));
    }


   
}

