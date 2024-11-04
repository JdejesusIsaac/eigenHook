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
import {PortalHook} from "../src/uniStake.sol";
import {StateLibrary} from "v4-core/src/libraries/StateLibrary.sol";
import {PositionConfig} from "v4-periphery/src/libraries/PositionConfig.sol";
import {SortTokens} from "v4-core/test/utils/SortTokens.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";
import {IPositionManager} from "v4-periphery/src/interfaces/IPositionManager.sol";
import {EasyPosm} from "./utils/EasyPosm.sol";
import {Fixtures} from "./utils/Fixtures.sol";
import {LiquidityAmounts} from "v4-core/test/utils/LiquidityAmounts.sol";


import {StrategyManagerMock} from "../test/mocks/StrategyManagerMock.sol";
import {StrategyBaseMock} from "../test/mocks/StrategyBaseMock.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {DelegateToMock} from "./hookMock2.sol";


contract ToHookTest is Test, Fixtures {
   using EasyPosm for IPositionManager;
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using StateLibrary for IPoolManager;
  

    DelegateToMock hook;
    StrategyManagerMock strategyManager;
    StrategyBaseMock strategy;

    PoolId poolId;

    uint256 tokenId;
    PositionConfig config;

    // CCIP
    

     int24 tickLower;
    int24 tickUpper;


    address staker = address(0x123);  // Simulated staker address
    address tokenHolder = address(0x456);  // Simulated token holder address
        function setUp() public {
        deployFreshManagerAndRouters();
        deployMintAndApprove2Currencies();
        deployAndApprovePosm(manager);

        // Create pool key first to determine token ordering
        key = PoolKey(currency0, currency1, 3000, 60, IHooks(address(0)));
        
        // Initialize StrategyManager with the LST token (token1 in this case)
        // We want to deposit token1 after swapping token0 for token1
        strategyManager = new StrategyManagerMock(IERC20(Currency.unwrap(currency1)));

        // Deploy hook with correct flags
        address flags = address(
            uint160(
                Hooks.AFTER_SWAP_FLAG | Hooks.AFTER_SWAP_RETURNS_DELTA_FLAG
            ) ^ (0x4441 << 144)
        );

        // Deploy hook
        deployCodeTo(
            "hookMock2.sol:DelegateToMock",
            abi.encode(manager, address(strategyManager)),
            flags
        );
        hook = DelegateToMock(payable(flags));

        // Update pool key with hook
        key = PoolKey(currency0, currency1, 3000, 60, IHooks(address(hook)));
        poolId = key.toId();

        // Initialize pool
        manager.initialize(key, SQRT_PRICE_1_1, ZERO_BYTES);

        // Add liquidity
        tickLower = TickMath.minUsableTick(key.tickSpacing);
        tickUpper = TickMath.maxUsableTick(key.tickSpacing);
        uint128 liquidityAmount = 100e18;

        (uint256 amount0Expected, uint256 amount1Expected) = LiquidityAmounts.getAmountsForLiquidity(
            SQRT_PRICE_1_1,
            TickMath.getSqrtPriceAtTick(tickLower),
            TickMath.getSqrtPriceAtTick(tickUpper),
            liquidityAmount
        );

        // Mint position
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

        // Approve tokens for hook
        IERC20(Currency.unwrap(currency0)).approve(address(hook), type(uint256).max);
        IERC20(Currency.unwrap(currency1)).approve(address(hook), type(uint256).max);
    }

    function testSwapDeposit1() public {
        // We want to swap token0 for token1
        bool zeroForOne = true;  // Swap token0 for token1
        int256 amountSpecified = -1e18;  // Exact input of 1 token0
        
        // Encode staker address in hook data
        bytes memory hookData = abi.encode(staker);

        // Perform swap
        BalanceDelta swapDelta = swap(
            key,
            zeroForOne,
            amountSpecified,
            hookData
        );

        // Verify swap occurred correctly
        assertEq(
            int256(swapDelta.amount0()), 
            amountSpecified, 
            "Swap amount for token0 should match the specified amount"
        );

        // Verify deposit occurred
        uint256 shares = strategyManager.stakerShares(staker);
        assertGt(shares, 0, "No shares were minted");
    }
}


