// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";

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


contract delegateToHook is BaseHook, ERC1155 {
    using PoolIdLibrary for PoolKey;
    using CurrencySettler for Currency;

   
   // wstETH addresses on different chains

    IDelegationManager public delegationManager; // 0x1784BE6401339Fc0Fedf7E9379409f5c1BfE9dda
    IStrategyManager public strategyManager = IStrategyManager(address(0x858646372CC42E1A627fcE94aa7A7033e7CF075A));
    address constant STETH = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;

    address public strategyManagerAddress = address(0x858646372CC42E1A627fcE94aa7A7033e7CF075A);

    event Deposited(address indexed staker, address strategy, IERC20 token, uint256 amount, uint256 shares);

    mapping(uint256 positionId => uint256 claimsSupply) public claimTokensSupply;
        

// Constructor
    
   



    constructor(
        IPoolManager _poolManager,
        address _delegationManager,
        string memory _uri
        
    ) BaseHook(_poolManager) ERC1155(_uri){
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
    address,  // Unused sender parameter
    PoolKey calldata key,
    IPoolManager.SwapParams calldata params,
    BalanceDelta delta,
    bytes calldata hookData
) external override onlyPoolManager returns (bytes4, int128) { 
    // Ensure that the swap involves ETH to stETH (or lstETH)
    if (Currency.unwrap(key.currency0) != address(0) || Currency.unwrap(key.currency1) != STETH) {
        // If not swapping ETH for stETH, skip further processing
        return (this.afterSwap.selector, 0);
    }

    // Decode strategy from hookData, if available
    IStrategy eigenLayerStrategy;
    if (hookData.length > 0) {
        (eigenLayerStrategy) = abi.decode(hookData, (IStrategy));
    } else {
        return (this.afterSwap.selector, 0);  // No strategy provided, return early
    }

    // Determine the amount of stETH received based on swap direction
    int128 outputAmount = depositLstIntoStrategy(key, delta, eigenLayerStrategy, params.zeroForOne);

    return (this.afterSwap.selector, outputAmount);
}


    function updateIStrategyManager(address _strategyManager) external {
        strategyManager = IStrategyManager(_strategyManager);
    }

    function depositLstIntoStrategy(
    PoolKey memory key,
    BalanceDelta delta,
    IStrategy eigenLayerStrategy,
    bool zeroForOne
   
) internal returns (int128) {
    // Determine the amount based on the swap direction
    int128 outputAmount = zeroForOne ? delta.amount1() : delta.amount0();
    if (outputAmount <= 0) {
        return 0;  // No output amount, return early
    }

    Currency outputCurrency = zeroForOne ? key.currency1 : key.currency0;

    // Transfer stETH from the pool to this contract
    poolManager.take(outputCurrency, address(this), uint128(outputAmount));
    IERC20 outputToken = IERC20(Currency.unwrap(outputCurrency));

    
        outputToken.approve(address(strategyManager), type(uint256).max);  // Set max approval to save gas
    

    // Deposit stETH into the EigenLayer strategy
    uint256 shares = strategyManager.depositIntoStrategy(eigenLayerStrategy, outputToken, uint128(outputAmount));
 
    // Emit event for the deposit
    emit Deposited(msg.sender, address(strategyManager), outputToken, uint128(outputAmount), shares);

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

