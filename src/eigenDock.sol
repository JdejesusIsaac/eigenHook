// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {Currency} from "v4-core/src/types/Currency.sol";
import {CurrencySettler} from "v4-core/test/utils/CurrencySettler.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

//import { IPermit2 } from "@uniswap/permit2/contracts/interfaces/IPermit2.sol";









import "../src/interfaces/IDelegationManager.sol";
import "../src/interfaces/IStrategyManager.sol";
import "../src/interfaces/IStrategy.sol";
import "../src/EigenLayer/StrategyManager.sol";



contract EigenDock is BaseHook {
    IPoolManager public manager;

 
   
    using PoolIdLibrary for PoolKey;
    using CurrencySettler for Currency;

    //iERC20 INTERFACE
   


    // Immutable state variables
     StrategyManager public strategyManager;

   struct EigenDockSwapParams {
    PoolKey key;
    address staker;        // Original user doing the swap
    IPoolManager.SwapParams params;
    bytes signature;       // Signature for strategy deposit
    IStrategy strategy; 
    bytes hookData;   // Target strategy
}
    // Events
    event Deposited(
        address indexed staker,
        address indexed strategy,
        IERC20 token,
        uint256 amount,
        uint256 shares
    );

    // Custom errors
    error InvalidOutputAmount();
    error DepositFailed();

    constructor(
        IPoolManager _manager,
        address _strategyManager
      

    ) BaseHook(_manager) {
        
        strategyManager = StrategyManager(_strategyManager);
        manager = _manager;
    }

    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: false,
            afterSwap: true,
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: false,
            afterSwapReturnDelta: true,
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }



 function afterSwap(
    address,  // Unused sender parameter
    PoolKey calldata key,
    IPoolManager.SwapParams calldata params,
    BalanceDelta delta,
    bytes calldata hookData
) external override onlyPoolManager returns (bytes4, int128) {
    // Decode the strategy and staker (original sender) from hookData
    (IStrategy eigenLayerStrategy, address staker) = abi.decode(hookData, (IStrategy, address));

    // Determine the amount of stETH received based on swap direction
    int128 outputAmount = depositLstIntoStrategy(
        key,
        delta,
        eigenLayerStrategy,
        staker,  // Use original sender here
        params.zeroForOne
    );

    return (BaseHook.afterSwap.selector, outputAmount);
}


 function _unlockCallback(
    bytes calldata rawData
) internal virtual override onlyPoolManager returns (bytes memory) {
    EigenDockSwapParams memory data = abi.decode(
        rawData,
        (EigenDockSwapParams)
    );

    // 1. Execute the swap
    BalanceDelta delta = poolManager.swap(data.key, data.params, data.hookData);

    // 2. Handle input token settlement (negative delta)
    if (delta.amount0() < 0) {
        data.key.currency0.settle(
            poolManager,
            data.staker,  // Original user pays
            uint128(-delta.amount0()),
            false
        );
    }
    if (delta.amount1() < 0) {
        data.key.currency1.settle(
            poolManager,
            data.staker,  // Original user pays
            uint128(-delta.amount1()),
            false
        );
    }

    // 3. Return delta for afterSwap hook to handle output tokens
    return abi.encode(delta);
}


   function depositLstIntoStrategy(
    PoolKey memory key,
    BalanceDelta delta,
    IStrategy eigenLayerStrategy,
    address staker,
      // Explicitly pass the original sender
    bool zeroForOne
) internal returns (int128) {
    // Determine the amount based on the swap direction
    int128 outputAmount = zeroForOne ? delta.amount1() : delta.amount0();
    if (outputAmount <= 0) {
        return 0;  // No output amount, return early
    }

    Currency outputCurrency = zeroForOne ? key.currency1 : key.currency0;

    // Transfer stETH from the pool to this contract
   // poolManager.take(outputCurrency, address(this), uint128(outputAmount));
   outputCurrency.take(manager, address(this), uint128(outputAmount), false);

   // outputCurrency.settle(poolManager, originalSender, uint128(outputAmount), false);
   
    IERC20 outputToken = IERC20(Currency.unwrap(outputCurrency));

    uint256 amount = uint256(uint128(outputAmount));


        // Transfer the tokens from Hook to the original sender
   

    // outputToken.transfer(staker, amount);

    outputToken.approve(address(strategyManager), amount);

    
    
    
   


  

    // Approve the strategy manager for the output token
    

    // Deposit stETH into the EigenLayer strategy on behalf of the original sender
    uint256 shares = strategyManager.depositIntoStrategy(
        eigenLayerStrategy,
        outputToken,
        uint128(outputAmount)
    );

    emit Deposited(staker, address(strategyManager), outputToken, uint128(outputAmount), shares);

    return outputAmount;
}











}
