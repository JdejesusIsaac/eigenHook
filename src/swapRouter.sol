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
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {TickMath} from "v4-core/src/libraries/TickMath.sol";
import {PoolSwapTest} from "v4-core/src/test/PoolSwapTest.sol";

import "../src/interfaces/IDelegationManager.sol";
import "../src/interfaces/IStrategyManager.sol";
import "../src/interfaces/IStrategy.sol";
import "../src/EigenLayer/StrategyManager.sol";
import "../src/EigenLayer/StrategyBase.sol";

contract swapHookRouter {
    using CurrencyLibrary for Currency;
    using CurrencySettler for Currency;
    using TransientStateLibrary for IPoolManager;

    IPoolManager public immutable manager;


    struct CallbackData {
        address sender;
        SwapSettings settings;
        PoolKey key;
        IPoolManager.SwapParams params;
        bytes hookData;
    }

    struct SwapSettings {
        address recipientAddress;
    }

    error CallerNotManager();
    error TokenCannotBeDeposited();

    PoolKey public specificPoolKey;

    constructor(IPoolManager _manager) {
        manager = _manager;
    }

    function setSpecificPool(
        Currency _currency0,
        Currency _currency1,
        uint24 _fee,
        int24 _tickSpacing,
        IHooks _hooks
    ) external {
        require(
            Currency.unwrap(_currency0) < Currency.unwrap(_currency1),
            "Currencies must be sorted"
        );

        specificPoolKey = PoolKey({
            currency0: _currency0,
            currency1: _currency1,
            fee: _fee,
            tickSpacing: _tickSpacing,
            hooks: _hooks
        });
    }

    function swap(
        PoolKey memory key,
        IPoolManager.SwapParams memory params,
        SwapSettings memory settings,
        bytes memory hookData
    ) external payable returns (BalanceDelta delta) {
        require(
            keccak256(abi.encode(key)) == keccak256(abi.encode(specificPoolKey)),
            "Invalid pool key"
        );

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
        take(
            data.key.currency0,
            data.settings.recipientAddress,
            uint256(deltaAfter0)
        );
    }

    if (deltaAfter1 > 0) {
        take(
            data.key.currency1,
            data.settings.recipientAddress,
            uint256(deltaAfter1)
        );
    }


        return abi.encode(delta);
    }

    function take(
        Currency currency,
        address recipient,
        uint256 amount
      
        
    ) internal {

        
       
             currency.take(manager, recipient, amount, false);
       
    }
}