
// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {Currency} from "v4-core/src/types/Currency.sol";
import {CurrencySettler} from "v4-core/test/utils/CurrencySettler.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {TickMath} from "v4-core/src/libraries/TickMath.sol";
import "../test/mocks/StrategyManagerMock.sol";

contract DelegateToMock is BaseHook {
    using PoolIdLibrary for PoolKey;
    using CurrencySettler for Currency;

    // Immutable state variables
    StrategyManagerMock public immutable strategyManager;

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
        IPoolManager _poolManager,
        address _strategyManager
    ) BaseHook(_poolManager) {
        strategyManager = StrategyManagerMock(_strategyManager);
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
        // Verify that the swap is ETH -> stETH and a valid strategy is provided in hookData
       
        address eigenLayerStrategy = abi.decode(hookData, (address));
        if (address(eigenLayerStrategy) == address(0)) {
            revert("Invalid strategy provided");  // Ensure a valid strategy
        }

        // Deposit stETH into the strategy and return the output amount
        int128 outputAmount = _depositStETHToStrategy(key, delta, eigenLayerStrategy, params.zeroForOne);
        return (this.afterSwap.selector, outputAmount);
    }

    function _depositStETHToStrategy(
        PoolKey memory key,
        BalanceDelta  delta,
        address staker,
        bool zeroForOne
    ) internal returns (int128) {

        // Determine the output amount based on swap direction
        int128 outputAmount = zeroForOne ? delta.amount1() : delta.amount0();
        if (outputAmount <= 0) revert InvalidOutputAmount(); // Ensure a valid output amount

        Currency outputCurrency = zeroForOne ? key.currency1 : key.currency0;

        // Transfer stETH from the pool to this contract
        poolManager.take(outputCurrency, address(this), uint128(outputAmount));
        IERC20 outputToken = IERC20(Currency.unwrap(outputCurrency));

        // Check and set allowance for strategy manager if needed
        
            outputToken.approve(address(strategyManager), type(uint256).max);
          //  outputToken.approve(staker, type(uint256).max);
        

        // Deposit stETH into the EigenLayer strategy
        uint256 shares = strategyManager.depositToStrategy(staker, outputToken, uint128(outputAmount));
        if (shares == 0) revert DepositFailed();

        // Emit event for successful deposit
        emit Deposited(msg.sender, address(strategyManager), outputToken, uint128(outputAmount), shares);

        return outputAmount;
    }

    // Owner-only function to update the strategy manager address
    

}