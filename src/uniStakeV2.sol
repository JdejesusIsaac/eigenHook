
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
import {CCIPReceiver} from "chainlink-local/lib/ccip/contracts/src/v0.8/ccip/applications/CCIPReceiver.sol";
import {Client} from "chainlink-local/lib/ccip/contracts/src/v0.8/ccip/libraries/Client.sol";
import {IRouterClient} from "chainlink-local/lib/ccip/contracts/src/v0.8/ccip/interfaces/IRouterClient.sol";
import {IRouter} from "chainlink-local/lib/ccip/contracts/src/v0.8/ccip/interfaces/IRouter.sol";
import {LinkTokenInterface} from "../src/interfaces/LinkInterface.sol";

contract uniStakeHook is BaseHook {
    using PoolIdLibrary for PoolKey;
    using CurrencySettler for Currency;

    enum PayFeesIn {
        Native,
        LINK
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

    // CCIP
    address immutable ccipRouter;
    address immutable linkToken;

   // wstETH addresses on different chains
address constant WSTETH_ARB = 0x5979D7b546E38E414F7E9822514be443A4800529;
address constant WSTETH_BASE = 0xc1CBa3fCea344f92D9239c08C0568f6F2F0ee452;
address constant WSTETH_OPTIMISM = 0x1F32b1c2345538c0c6f582fCB022739c4A194Ebb;

// Chain selectors
uint64 constant SEPOLIA_TO_ARB_SELECTOR = 3478487238524512106;
uint64 constant SEPOLIA_TO_BASE_SELECTOR = 10344971235874465080;
uint64 constant SEPOLIA_TO_OPTIMISM_SELECTOR = 5224473277236331295;
   

    PayFeesIn public bridgeFeeTokenType = PayFeesIn.Native; // for local testing

    bytes32[] public receivedMessages; // Array to keep track of the IDs of received messages.

    // Event emitted when a message is received from another chain.
    event MessageReceived(
        bytes32 indexed messageId, // The unique ID of the message.
        uint64 indexed sourceChainSelector, // The chain selector of the source chain.
        address sender, // The address of the sender from the source chain.
        bytes message, // The message that was received.
        Client.EVMTokenAmount tokenAmount // The token amount that was received.
    );


   

    constructor(
        IPoolManager _poolManager,
        address _router,
        address _link
        
    ) BaseHook(_poolManager) {
        ccipRouter = _router;
        linkToken = _link;
        
    }

    //view function to get chain selectors for wstETH
    function getChainSelectors() public pure returns(uint64,uint64,uint64){
       
        return (SEPOLIA_TO_ARB_SELECTOR,SEPOLIA_TO_BASE_SELECTOR,SEPOLIA_TO_OPTIMISM_SELECTOR);


       
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
        uint64 destinationChainSelector,
        bytes calldata hookData
        
    ) external  returns (bytes4, int128) {
        if (hookData.length > 0) {
            (
                address receiver,
                bool isBridgeTx,
                
            ) = abi.decode(hookData, (address, bool, uint64));

            // TODO add more validations
            if (isBridgeTx && destinationChainSelector != 0) {
                  bool zeroForOne = params.zeroForOne;
                // TODO handle ETH
                // handle zeroForOne trades
                int128 outputAmount = processAndBridgeSwap(
                    key,
                    delta,
                    zeroForOne,
                    receiver,
                    destinationChainSelector
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

    function processAndBridgeSwap(
    PoolKey memory key,
    BalanceDelta delta,
    bool zeroForOne,
    address receiver,
    uint64 destinationChainSelector
) internal returns (int128) {
    int128 outputAmount = zeroForOne ? delta.amount1() : delta.amount0();
    
    // Determine output currency based on swap direction
    Currency outputCurrency = zeroForOne ? key.currency1 : key.currency0;

    // Set wstETH address based on destination chain selector
    address outputToken;
    
    if (destinationChainSelector == SEPOLIA_TO_ARB_SELECTOR) {
        outputToken = WSTETH_ARB;
    } else if (destinationChainSelector == SEPOLIA_TO_BASE_SELECTOR) {
        outputToken = WSTETH_BASE;
    } else if (destinationChainSelector == SEPOLIA_TO_OPTIMISM_SELECTOR) {
        outputToken = WSTETH_OPTIMISM;
    } else {
        revert("Unsupported destination chain");
    }

    poolManager.take(outputCurrency, address(this), uint128(outputAmount));
    
    IERC20(outputToken).approve(ccipRouter, uint128(outputAmount));

    bridgeStakingTokens(
        receiver,
        outputToken, // Use the determined wstETH address
        uint128(outputAmount),
        destinationChainSelector
    );

    return outputAmount;
}

   

   




    function bridgeStakingTokens(
        address receiver,
        address outputToken,
        uint256 outputAmount,
        uint64 destinationChainSelector
    ) internal {
        // TODO refactor

        Client.EVMTokenAmount[]
            memory tokensToSendDetails = new Client.EVMTokenAmount[](1);

        Client.EVMTokenAmount memory tokenToSendDetails = Client
            .EVMTokenAmount({
                token: address(outputToken),
                amount: outputAmount
            });

        tokensToSendDetails[0] = tokenToSendDetails;

        // bridge

        Client.EVM2AnyMessage memory message = Client.EVM2AnyMessage({
            receiver: abi.encode(receiver),
            data: "",
            tokenAmounts: tokensToSendDetails,
            extraArgs: "",
            feeToken: bridgeFeeTokenType == PayFeesIn.LINK
                ? linkToken
                : address(0)
        });

        uint256 fee = IRouterClient(ccipRouter).getFee(
            destinationChainSelector,
            message
        );

        bytes32 messageId;

        if (bridgeFeeTokenType == PayFeesIn.LINK) {
            LinkTokenInterface(linkToken).approve(ccipRouter, fee);
            messageId = IRouterClient(ccipRouter).ccipSend(
                destinationChainSelector,
                message
            );
        } else {
            messageId = IRouterClient(ccipRouter).ccipSend{value: fee}(
                destinationChainSelector,
                message
            );
        }
    }
}

