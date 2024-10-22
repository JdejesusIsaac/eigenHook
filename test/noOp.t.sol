// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;


import "forge-std/Test.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {TickMath} from "v4-core/src/libraries/TickMath.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";
import {CurrencyLibrary, Currency} from "v4-core/src/types/Currency.sol";
import {PoolSwapTest} from "v4-core/src/test/PoolSwapTest.sol";
import {NoOpSwap} from "../src/NoOp.sol";
import {StateLibrary} from "v4-core/src/libraries/StateLibrary.sol";

import {LiquidityAmounts} from "v4-core/test/utils/LiquidityAmounts.sol";
import {IPositionManager} from "v4-periphery/src/interfaces/IPositionManager.sol";
import {EasyPosm} from "./utils/EasyPosm.sol";
import {Fixtures} from "./utils/Fixtures.sol";


contract NoOpTest is Test, Fixtures {
     using EasyPosm for IPositionManager;
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using StateLibrary for IPoolManager;

    NoOpSwap hook;
    PoolId poolId;


    uint256 tokenId;
    int24 tickLower;
    int24 tickUpper;

    function setUp() public {
    // Creates the pool manager, utility routers, and test tokens
    deployFreshManagerAndRouters();
    deployMintAndApprove2Currencies();

    deployAndApprovePosm(manager);

    // Deploy the hook with the BEFORE_SWAP_FLAG
    address flags = address(
        uint160(
            Hooks.BEFORE_SWAP_FLAG | Hooks.BEFORE_SWAP_RETURNS_DELTA_FLAG
        ) ^ (0x4444 << 144) // Namespace the hook to avoid collisions
    );

    bytes memory constructorArgs = abi.encode(manager);
    deployCodeTo("noOp.sol:NoOpSwap", constructorArgs, flags);
    hook = NoOpSwap(flags);

    // Define the pool key with two currencies, fee tier, and tick spacing
    key = PoolKey(currency0, currency1, 3000, 60, IHooks(hook));
    poolId = key.toId();

    // Initialize the pool
    manager.initialize(key, SQRT_PRICE_1_1, ZERO_BYTES);

    // Provide full-range liquidity to the pool
    tickLower = TickMath.minUsableTick(key.tickSpacing);
    tickUpper = TickMath.maxUsableTick(key.tickSpacing);

    uint128 liquidityAmount = 100e18;

    (uint256 amount0Expected, uint256 amount1Expected) = LiquidityAmounts.getAmountsForLiquidity(
        SQRT_PRICE_1_1,
        TickMath.getSqrtPriceAtTick(tickLower),
        TickMath.getSqrtPriceAtTick(tickUpper),
        liquidityAmount
    );

    (tokenId,) = posm.mint(
        key,
        tickLower,
        tickUpper,
        liquidityAmount,
        amount0Expected + 1,
        amount1Expected + 1,
        address(this),
        block.timestamp,
        ZERO_BYTES
    );
}

function testNoOpSwap() public {
    // Ensure that no swap has occurred yet
    assertEq(hook.beforeSwapCount(poolId), 0);

    // Perform an exact input swap with 69e18 tokens (should trigger NoOp)
    bool zeroForOne = true;
    int256 amountSpecified = -69e18; // Negative number indicates exact input swap!
    
    BalanceDelta swapDelta = swap(key, zeroForOne, amountSpecified, ZERO_BYTES);

    // Check that the swap was skipped by ensuring the amountTaken is 69e18
    assertEq(swapDelta.amount0(), 0); // No swap should occur for token0
    assertEq(swapDelta.amount1(), 0); // No swap should occur for token1

    // Ensure the hook counted the swap attempt
    assertEq(hook.beforeSwapCount(poolId), 1);
}

function testRegularSwap() public {
    // Ensure that no swap has occurred yet
    assertEq(hook.beforeSwapCount(poolId), 0);

    // Perform an exact input swap with an amount different from 69e18 (should not trigger NoOp)
    bool zeroForOne = true;
    int256 amountSpecified = -50e18; // Negative number indicates exact input swap!
    
    BalanceDelta swapDelta = swap(key, zeroForOne, amountSpecified, ZERO_BYTES);

    // Check that the swap proceeded normally
    assertEq(swapDelta.amount0(), amountSpecified);
    assert(swapDelta.amount1() != 0); // Non-zero output for the swap

    // Ensure the hook counted the swap attempt
    assertEq(hook.beforeSwapCount(poolId), 1);
}



}
    

