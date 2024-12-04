// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {Currency, CurrencyLibrary} from "v4-core/src/types/Currency.sol";
import {CurrencySettler} from "v4-core/test/utils/CurrencySettler.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {TransientStateLibrary} from "v4-core/src/libraries/TransientStateLibrary.sol";



import "../src/interfaces/IDelegationManager.sol";
import "../src/interfaces/IStrategyManager.sol";
import "../src/interfaces/IStrategy.sol";
import "../src/EigenLayer/StrategyManager.sol";
import "../src/EigenLayer/StrategyBase.sol";


contract swapAndRestakeEigenRouter  {
      using CurrencyLibrary for Currency;
    using CurrencySettler for Currency;
    using TransientStateLibrary for IPoolManager;

    IPoolManager public immutable manager;
     // Immutable state variables
     StrategyManager public strategyManager;


     struct CallbackData {
        address sender;
        SwapSettings settings;
        PoolKey key;
        IPoolManager.SwapParams params;
        bytes hookData;
     }

     struct SwapSettings {
        bool depositTokens;
        address recipientAddress;  
        address eigenLayerStrategy; 
     }

     
      error CallerNotManager();
    error TokenCannotBeDeposited();


     event Deposited(
        address indexed staker,
        address indexed strategy,
        IERC20 token,
        uint256 amount,
        uint256 shares
    );

     mapping(address => IStrategy) public tokenToStrategy;
     

     constructor(
        IPoolManager _manager,
        address _strategyManager
    )  {
        manager = _manager;
        strategyManager = StrategyManager(_strategyManager);
    }

    /**
     * @notice Adds a mapping from an ERC-20 token to its corresponding strategy.
     * @param token The ERC-20 token address on L1.
     * @param strategy The strategy contract on EigenLayer.
     */
    function addTokenStrategyMapping(address token, IStrategy strategy) external  {
        tokenToStrategy[token] = strategy;
    }


   function swap(
    PoolKey memory key,
    IPoolManager.SwapParams memory params,
    SwapSettings memory settings,
    bytes memory hookData
) external payable returns (BalanceDelta delta) {
    // Add input validation
    if (settings.depositTokens) {
        Currency outputToken = params.zeroForOne ? key.currency1 : key.currency0;
        // Fix: Use Currency.unwrap() to check if it's native ETH
        address tokenAddress = Currency.unwrap(outputToken);
        if (tokenAddress != address(0)) { // address(0) represents native ETH
            IStrategy strategy = tokenToStrategy[tokenAddress];
            if (address(strategy) == address(0)) revert TokenCannotBeDeposited();
        }
    }

    // Rest of implementation
    delta = abi.decode(
        manager.unlock(
            abi.encode(
                CallbackData(msg.sender, settings, key, params, hookData)
            )
        ),
        (BalanceDelta)
    );

    
}


    
     function unlockCallback(
        bytes calldata rawData
    ) external returns (bytes memory) {
        if (msg.sender != address(manager)) revert CallerNotManager();

        CallbackData memory data = abi.decode(rawData, (CallbackData));

        BalanceDelta delta = manager.swap(data.key, data.params, data.hookData);

        int256 deltaAfter0 = manager.currencyDelta(
            address(this),
            data.key.currency0
        );
        int256 deltaAfter1 = manager.currencyDelta(
            address(this),
            data.key.currency1
        );

        if (deltaAfter0 < 0) {
            data.key.currency0.settle(
                manager,
                data.sender,
                uint256(-deltaAfter0),
                false
            );
        }

        if (deltaAfter1 < 0) {
            data.key.currency1.settle(
                manager,
                data.sender,
                uint256(-deltaAfter1),
                false
            );
        }

        if (deltaAfter0 > 0) {
            _take(
                data.key.currency0,
                data.settings.recipientAddress,
                uint256(deltaAfter0),
                data.settings.eigenLayerStrategy,
                data.settings.depositTokens
            );
        }

        if (deltaAfter1 > 0) {
            _take(
                data.key.currency1,
                data.settings.recipientAddress,
                uint256(deltaAfter1),
                data.settings.eigenLayerStrategy,
                data.settings.depositTokens
            );
        }

        return abi.encode(delta);
    }

    function _take(
        Currency currency,
        address recipient,
        uint256 amount,
       address eigenLayerStrategy,
        bool depositToEigenLayer
    ) internal {

        
        if(!depositToEigenLayer){
             currency.take(manager, recipient, amount, false);
        } else {
             currency.take(manager, address(this), amount, false);

             //approve the strategy manager for the output token
            IERC20(Currency.unwrap(currency)).approve(address(strategyManager), amount);

             // Deposit stETH into the EigenLayer strategy on behalf of the original sender
            uint256 shares = strategyManager.depositIntoStrategy(
                IStrategy(eigenLayerStrategy),
                IERC20(Currency.unwrap(currency)),
                uint128(amount)
            );

            emit Deposited(recipient, address(strategyManager), IERC20(Currency.unwrap(currency)), amount, shares);

        }
    }



}
       

