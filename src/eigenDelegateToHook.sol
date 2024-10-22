// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";

import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "v4-core/src/types/BeforeSwapDelta.sol";
import {Currency} from "v4-core/src/types/Currency.sol";
import {CurrencySettler} from "v4-core/test/utils/CurrencySettler.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import "../src/interfaces/IDelegationManager.sol";
import "../src/interfaces/IStrategyManager.sol";


contract delegateToHook is BaseHook {
    using PoolIdLibrary for PoolKey;
    using CurrencySettler for Currency;

   
   // wstETH addresses on different chains

    IDelegationManager public delegationManager; // 0x1784BE6401339Fc0Fedf7E9379409f5c1BfE9dda
    IStrategyManager public strategyManager = IStrategyManager(address(0x858646372CC42E1A627fcE94aa7A7033e7CF075A));
    address constant STETH = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;

    address public strategyManagerAddress = address(0);

    event Deposited(address indexed staker, address strategy, IERC20 token, uint256 amount, uint256 shares);
   


   

    constructor(
        IPoolManager _poolManager,
        address _delegationManager
        
    ) BaseHook(_poolManager) {
         delegationManager = IDelegationManager(_delegationManager);
       
        
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
         IStrategy eigenLayerStrategy,
       // IERC20 steth ,
        uint256 amount
      //  bytes calldata hookData
    ) external  returns (bytes4, int128) {

         int128 outputAmount = depositStETHIntoStrategy(key, delta, params.zeroForOne, eigenLayerStrategy, amount);

         return (BaseHook.afterSwap.selector, outputAmount);
        
            

            // TODO add more validations
            
                 // bool zeroForOne = params.zeroForOne;
                // TODO handle ETH
                // handle zeroForOne trades
         
            
        

        
    }
               

    

     function depositStETHIntoStrategy(

         PoolKey memory key,
        BalanceDelta delta,
        bool zeroForOne,
        IStrategy eigenLayerStrategy,
       // IERC20 steth ,
        uint256 amount
    ) internal returns (int128) {
        int128 outputAmount = zeroForOne ? delta.amount1() : delta.amount0();
        Currency outputCurrency = zeroForOne ? key.currency1 : key.currency0;

        poolManager.take(outputCurrency, address(this), uint128(outputAmount));
        IERC20 outputToken = IERC20(Currency.unwrap(outputCurrency));
        IERC20(outputToken).approve(strategyManagerAddress, uint128(outputAmount));

        // Call the depositIntoStrategy function to deposit the stETH into the strategy
        uint256 shares = strategyManager.depositIntoStrategy(eigenLayerStrategy, outputToken, amount);

        

        // Emit an event or handle the shares if needed
        emit Deposited(msg.sender, strategyManagerAddress,  outputToken, amount, shares);

        return outputAmount;
    }

        function delegateToOperator(
        address operator,
        bytes memory signature,
        uint256 expiry,
        bytes32 salt
    ) external {
        
        ISignatureUtils.SignatureWithExpiry memory approverSignatureAndExpiry = ISignatureUtils.SignatureWithExpiry({
            signature: signature,
            expiry: expiry
        });

        // Call the delegateTo function from the DelegationManager contract
        delegationManager.delegateTo(operator, approverSignatureAndExpiry, salt);
    }




   

   

   
   
}

