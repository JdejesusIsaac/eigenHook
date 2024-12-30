// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/mocks/ERC1271WalletMock.sol";
import "../src/EigenLayer/StrategyManager.sol";

import "../src/EigenLayer/StrategyBase.sol";

import "../src/EigenLayer/PauserRegistry.sol";
import "../test/mocks/ERC20Mock.sol";
import "../test/mocks/ERC20_SetTransferReverting_Mock.sol";
import "../test/mocks/Reverter.sol";
import "../test/mocks/Reenterer.sol";
import "../test/mocks/MockDecimals.sol";
import "../test/interfaces/IStrategyManagerEvents.sol";
import "./EigenLayerUnitTestSetup.sol";

import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {TickMath} from "v4-core/src/libraries/TickMath.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";
import {CurrencyLibrary, Currency} from "v4-core/src/types/Currency.sol";
import {PoolSwapTest} from "v4-core/src/test/PoolSwapTest.sol";

import {StateLibrary} from "v4-core/src/libraries/StateLibrary.sol";
import {PositionConfig} from "v4-periphery/src/libraries/PositionConfig.sol";
import {SortTokens} from "v4-core/test/utils/SortTokens.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";
import {IPositionManager} from "v4-periphery/src/interfaces/IPositionManager.sol";
import {EasyPosm} from "./utils/EasyPosm.sol";
import {Fixtures} from "./utils/Fixtures.sol";
import {LiquidityAmounts} from "v4-core/test/utils/LiquidityAmounts.sol";

import {CCIPLocalSimulator, IRouterClient, LinkToken, BurnMintERC677Helper} from   "chainlink-local/src/ccip/CCIPLocalSimulator.sol";


import {swapHookRouter} from "../src/swapRouter.sol";


import {uniStakeV1} from "../src/uniStakeV1.sol";
import {StateLibrary} from "v4-core/src/libraries/StateLibrary.sol";



/**
 * @notice Unit testing of the StrategyManager contract, entire withdrawal tests related to the
 * DelegationManager are not tested here but callable functions by the DelegationManager are mocked and tested here.
 * Contracts tested: StrategyManager.sol
 * Contracts not mocked: StrategyBase, PauserRegistry
 */
contract swapRouterUnitTests is EigenLayerUnitTestSetup, IStrategyManagerEvents, Fixtures {
    using EasyPosm for IPositionManager;
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using StateLibrary for IPoolManager;
  

        uint256 constant INITIAL_LIQUIDITY = 100e18;
   
    uint256 constant SWAP_AMOUNT = 1e18 * 32;

    

    address depositer = address(0x123);

    address alice = address(0x124);

    address initialOwner = address(this);

    address aliceCrossChain = vm.addr(1);
    
    address bobCrossChain;
    
  
    address constant dummyAdmin = address(uint160(uint256(keccak256("DummyAdmin"))));

   //ccip

     CCIPLocalSimulator public ccipLocalSimulator;
    
    
    IRouterClient ccipRouter;
    uint64 destinationChainSelector;
    
    BurnMintERC677Helper ccipBnMToken;

    LinkToken linkToken;


///UniStakeV1 Hook setup/ swapAndRestakeEigenRouter setup

     uniStakeV1  hook;
     swapHookRouter router;

     PoolId poolId;
    
    uint256 tokenId;
    
    PositionConfig config;
    
    
    int24 tickLower;
    int24 tickUpper;

     
     

     


     //EigenLayer Core Contract setup

    IERC20 public dummyToken;
    

    

     



    
    
   

    function setUp() public override {
        vm.deal(address(this), 500 ether);
        vm.deal(alice, 500 ether);
        
        uint256 initialBalance = 32 * 1e18;
        // Mint a reasonable amount of tokens


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
  
    
         // Deploy base contracts
        deployFreshManagerAndRouters();
        deployMintAndApprove2Currencies();
        deployAndApprovePosm(manager);
       
        dummyToken =  IERC20(Currency.unwrap(currency1));


       
       //  MockERC20(Currency.unwrap(currency1)).mint(address(this), initialBalance);
      //   MockERC20(Currency.unwrap(currency1)).approve(address(manager), initialBalance);

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



        
       

        router = new swapHookRouter(manager);
       




         // Mint tokens to the test contract itself
    MockERC20(Currency.unwrap(currency0)).mint(address(this), SWAP_AMOUNT);
    MockERC20(Currency.unwrap(currency0)).mint(alice, SWAP_AMOUNT);
    
    // Important: Also mint tokens to the pool for liquidity
    MockERC20(Currency.unwrap(currency0)).mint(address(manager), INITIAL_LIQUIDITY);
    MockERC20(Currency.unwrap(currency1)).mint(address(manager), INITIAL_LIQUIDITY);

    // Approve tokens for the pool manager
    MockERC20(Currency.unwrap(currency0)).approve(address(manager), type(uint256).max);
    MockERC20(Currency.unwrap(currency1)).approve(address(manager), type(uint256).max);

      //was address(0)
      
      key = PoolKey(currency0, currency1, 3000, 60, IHooks(address(hook)));
        poolId = key.toId();
        manager.initialize(key, SQRT_PRICE_1_1, ZERO_BYTES);

    
    
    // Add initial liquidity to the pool
     (key, ) = initPool(
            
             
            Currency.wrap(address(0)),
             
            Currency.wrap(address(dummyToken)),
            IHooks(address(hook)),
            3000,
            SQRT_PRICE_1_1,
            ZERO_BYTES
        );

       

        modifyLiquidityRouter.modifyLiquidity{value: 32 ether}(
            key,
            IPoolManager.ModifyLiquidityParams({
                tickLower: -60,
                tickUpper: 60,
                liquidityDelta: 32 ether,
                salt: bytes32(0)
            }),
            ZERO_BYTES
        );

    
        
        
        IERC20(Currency.unwrap(currency1)).approve(address(router), type(uint256).max);
      //allowance for strategy manager
        IERC20(Currency.unwrap(currency1)).approve(address(this), type(uint256).max);

      




       
        
      


    }

       function testSwapWithUniStakePoolSuccess() public {
    uint256 swapAmount = 0.1 ether;

      // Perform swap with bridging enabled
    bytes memory hookData = abi.encode(
        alice,
        false,
        
        16015286601757825753 // selector for testing
    );
    
    // Set the specific pool that should be used
    router.setSpecificPool(
        Currency.wrap(address(0)),  // ETH
        Currency.wrap(address(dummyToken)),  // MockERC20
        3000,       // fee
        60,         // tickSpacing
        IHooks(address(hook))
    );

    // Create swap settings
    swapHookRouter.SwapSettings memory settings = swapHookRouter.SwapSettings({
        recipientAddress: address(alice)
    });

     IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
        zeroForOne: true,
        amountSpecified: -int256(swapAmount),
        sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
    });


    router.swap{value: swapAmount}(
        key,
        params,
        settings,
        hookData
    );


}

function testSwapNoDepositWithUniStakePoolSuccessBridgeCcip() public {
    uint256 swapAmount = 0.1 ether;

      // Perform swap with bridging enabled
    bytes memory hookData = abi.encode(
        alice,
        true,
        16015286601757825753 // selector for testing
    );
    
    // Set the specific pool that should be used
    router.setSpecificPool(
        Currency.wrap(address(0)),  // ETH
        Currency.wrap(address(dummyToken)),  // MockERC20
        3000,       // fee
        60,         // tickSpacing
        IHooks(address(hook))
    );

    // Create swap settings
    swapHookRouter.SwapSettings memory settings = swapHookRouter.SwapSettings({
        recipientAddress: address(alice)
    });

    // Create swap params
    IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
        zeroForOne: true,
        amountSpecified: -int256(swapAmount),
        sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
    });

    // This should succeed as we're using the correct pool
    router.swap{value: swapAmount}(
        key,        // This matches our specific pool
        params,
        settings,
        hookData
    );
}

}