// SPDX-License-Identifier: GPL-2.0-or-later
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
import {uniStakeV1} from "../src/uniStakeV1.sol";
import {StateLibrary} from "v4-core/src/libraries/StateLibrary.sol";
import {PositionConfig} from "v4-periphery/src/libraries/PositionConfig.sol";
import {SortTokens} from "v4-core/test/utils/SortTokens.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";
import {IPositionManager} from "v4-periphery/src/interfaces/IPositionManager.sol";
import {EasyPosm} from "./utils/EasyPosm.sol";
import {Fixtures} from "./utils/Fixtures.sol";


import {CCIPLocalSimulator, IRouterClient, LinkToken, BurnMintERC677Helper} from   "chainlink-local/src/ccip/CCIPLocalSimulator.sol";

import {Client} from "chainlink-local/lib/ccip/contracts/src/v0.8/ccip/libraries/Client.sol";
//mport { IOFT, SendParam, MessagingFee, MessagingReceipt, OFTReceipt } from "@layerzerolabs/lz-evm-oapp-v2/contracts/oft/interfaces/IOFT.sol";
//
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount)
        external
        returns (bool);
    function allowance(address owner, address spender)
        external
        view
        returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount)
        external
        returns (bool);
}

contract unistakeHookTest is Test, Fixtures {
    using EasyPosm for IPositionManager;
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using StateLibrary for IPoolManager;

   uniStakeV1  hook;
    PoolId poolId;

    uint256 tokenId;
    PositionConfig config;

    // CCIP
    CCIPLocalSimulator public ccipLocalSimulator;
    address alice = vm.addr(1);
    address bob;
    IRouterClient ccipRouter;
    uint64 destinationChainSelector;
    BurnMintERC677Helper ccipBnMToken;
   // BurnMintERC677Helper currencyC0;
   // BurnMintERC677Helper currencyC1;
     MockERC20 currencyC0;
    MockERC20 currencyC1;
    LinkToken linkToken;

    address private constant STETH = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;

    address constant WSTETH_ARB = 0x5979D7b546E38E414F7E9822514be443A4800529;
    address constant WSTETH_BASE = 0xc1CBa3fCea344f92D9239c08C0568f6F2F0ee452;
    address constant WSTETH_OPTIMISM = 0x1F32b1c2345538c0c6f582fCB022739c4A194Ebb;
    
    IERC20 private constant steth = IERC20(STETH);
    IERC20 private constant wstethArb = IERC20(WSTETH_ARB);
    IERC20 private constant wstethBase = IERC20(WSTETH_BASE);
    IERC20 private constant wstethOptimism = IERC20(WSTETH_OPTIMISM);

    function setUp() public {
        ccipLocalSimulator = new CCIPLocalSimulator();
        (
            uint64 chainSelector,
            IRouterClient sourceRouter,
            ,
            ,
            LinkToken link,
            BurnMintERC677Helper ccipBnM, // not using this
        ) = ccipLocalSimulator.configuration();

        ccipRouter = sourceRouter;
        destinationChainSelector = chainSelector;
        linkToken = link;

        // Create MockERC20 tokens
        currencyC0 = new MockERC20("Mock Token 0", "MT0", 18);
        currencyC1 = new MockERC20("Mock Token 1", "MT1", 18);

        // Comment out or remove these lines if not necessary
        // ccipLocalSimulator.supportNewTokenViaOwner(address(currencyC0));
        // ccipLocalSimulator.supportNewTokenViaOwner(address(currencyC1));

        // Mint tokens directly using MockERC20
        currencyC0.mint(address(this), 100_000_000 ether);
        currencyC1.mint(address(this), 100_000_000 ether);
        //currencyC0.mint(address(alice), 100_000_000 ether);
        //currencyC1.mint(address(alice), 100_000_000 ether);

        // Wrap for usage with v4
        (Currency currencyC0W, Currency currencyC1W) = SortTokens.sort(
            MockERC20(address(currencyC0)),
            MockERC20(address(currencyC1))
        );

        // creates the pool manager, utility routers
        deployFreshManagerAndRouters();
        //deployMintAndApprove2Currencies();

       // Approve routers with type(uint256).max for maximum flexibility
    address modifyLiqRouter = address(modifyLiquidityRouter);
    currencyC0.approve(modifyLiqRouter, type(uint256).max);
    currencyC1.approve(modifyLiqRouter, type(uint256).max);
    currencyC0.approve(address(swapRouter), type(uint256).max);
    currencyC1.approve(address(swapRouter), type(uint256).max);
    currencyC0.approve(address(manager), type(uint256).max);
    currencyC1.approve(address(manager), type(uint256).max);

        // mint some ccip tokens to hook
        // Note: (internal function is modified to mint
        // many tokens in one go)
       /*
               function drip(address to, uint256 amount) external {
                    _mint(to, amount);
                }
        */
        // alternative is run the internal function in a loop
       // currencyC0.drip(address(this));
       // currencyC1.drip(address(this));
       // currencyC0.drip(address(alice));
       // currencyC1.drip(address(alice));

       // MockERC20(address(currencyC0)).mint(address(this), 100_000_000 ether);
       // MockERC20(address(currencyC1)).mint(address(this), 100_000_000 ether);

        // Approve the PoolManager to spend the tokens


    

       // currencyC0.drip(address(alice));

        // Deploy the hook to an address with the correct flags
        address flags = address(
            uint160(
                Hooks.AFTER_SWAP_FLAG | Hooks.AFTER_SWAP_RETURNS_DELTA_FLAG
            ) ^ (0x4441 << 144) // Namespace the hook to avoid collisions
        );

        deployCodeTo(
            "uniStakeV1.sol:uniStakeV1",
            abi.encode(manager, address(ccipRouter), address(linkToken)),
            flags
        );
        hook = uniStakeV1(payable(flags));

        // Create the pool
        key = PoolKey(currencyC0W, currencyC1W, 3000, 60, IHooks(hook));
        poolId = key.toId();
        manager.initialize(key, SQRT_PRICE_1_1, ZERO_BYTES);

        modifyLiquidityRouter.modifyLiquidity(
            key,
            IPoolManager.ModifyLiquidityParams(
                TickMath.minUsableTick(60),
                TickMath.maxUsableTick(60),
                1000000 ether,
                0
            ),
            ZERO_BYTES
        );
    }

    // not used
  
    function test_SwapZeroForOneExactInput_noBridge() public {
        // positions were created in setup()

        uint256 balanceOfC1AliceBefore = currencyC1.balanceOf(address(alice));
        assertEq(balanceOfC1AliceBefore, 0);

        // Perform a test swap //

        // pass alice address to receive bridge funds & set bridging to false
        bytes memory hookData = abi.encode(
            address(alice),
            false,
            0 // selector for testing
        );

        bool zeroForOne = true;
        int256 amountSpecified = -1e18; // negative number indicates exact input swap!
        BalanceDelta swapDelta = swap(
            key,
            zeroForOne,
            amountSpecified,
            hookData
        );

        // ------------------- //

        assertEq(int256(swapDelta.amount0()), amountSpecified);

        // alice balance should be zero
        uint256 balanceOfC1AliceAfter = currencyC1.balanceOf(address(alice));
        assertEq(balanceOfC1AliceAfter, 0);
    }

    function test_SwapOneForZeroExactInput_noBridge() public {
        // Check initial balance
        uint256 initialBalance = currencyC0.balanceOf(address(alice));
        assertEq(initialBalance, 0);

        // Perform swap operation
        bytes memory hookData = abi.encode(
            address(alice),
            false,
            0 // selector for testing
        );

        bool zeroForOne = false;
        int256 amountSpecified = -1e18; // negative number indicates exact input swap!
        BalanceDelta swapDelta = swap(
            key,
            zeroForOne,
            amountSpecified,
            hookData
        );

        assertEq(int256(swapDelta.amount1()), amountSpecified);

        // alice should receive bridged funds
        uint256 balanceC0AliceAfter = currencyC0.balanceOf(address(alice));
        assertEq(balanceC0AliceAfter, 0);
    }

   

    function test_SwapAndBridge_oneForZero() public {
    // Get Alice's initial balance of token0 (the output token for oneForZero swap)
    uint256 balanceC0AliceBefore = currencyC0.balanceOf(alice);
    console.log("Alice's balance before swap:", balanceC0AliceBefore);

    // Perform swap with bridging enabled
    bytes memory hookData = abi.encode(
        alice,
        true,
        16015286601757825753 // selector for testing
    );
    
    bool zeroForOne = false;  // oneForZero swap
    int256 amountSpecified = -1e18; // exact input of 1 token1
    BalanceDelta swapDelta = swap(
        key,
        zeroForOne,
        amountSpecified,
        hookData
    );

    // Get Alice's final balance
    uint256 balanceC0AliceAfter = currencyC0.balanceOf(alice);
   
    console.log("Change in balance:", balanceC0AliceAfter);

    // Verify the swap input amount
   // assertEq(int256(swapDelta.amount1()), 996900609009281774);
}
}