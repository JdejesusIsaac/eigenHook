// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;



import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {FixedPointMathLib} from "solmate/src/utils/FixedPointMathLib.sol";
import {PoolId, PoolIdLibrary} from "v4-core/src/types/PoolId.sol";
import {StateLibrary} from "v4-core/src/libraries/StateLibrary.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {TickMath} from "v4-core/src/libraries/TickMath.sol";
import {Currency, CurrencyLibrary} from "v4-core/src/types/Currency.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";


import {PoolKey} from "v4-core/src/types/PoolKey.sol";

contract TakeProfitsHook is BaseHook, ERC1155 {
	// StateLibrary is new here and we haven't seen that before
	// It's used to add helper functions to the PoolManager to read
	// storage values.
	// In this case, we use it for accessing `currentTick` values
	// from the pool manager
	using StateLibrary for IPoolManager;

	// PoolIdLibrary used to convert PoolKeys to IDs
	using PoolIdLibrary for PoolKey;
	// Used to represent Currency types and helper functions like `.isNative()`
    using CurrencyLibrary for Currency;
	// Used for helpful math operations like `mulDiv`
    using FixedPointMathLib for uint256;

	// Errors
	error InvalidOrder();
	error NothingToClaim();
	error NotEnoughToClaim();

    mapping(PoolId poolId => int24 lastTick) public lastTicks;
    mapping(PoolId poolId => mapping(int24 tickToSellAt => mapping(bool zeroForOne => uint256 inputAmount)))
        public pendingOrders;

    mapping(uint256 positionId => uint256 outputClaimable) public claimableOutputTokens;
        
    mapping(uint256 positionId => uint256 claimsSupply) public claimTokensSupply;
        
	
	// Constructor
    constructor(
        IPoolManager _manager,
        string memory _uri
    ) BaseHook(_manager) ERC1155(_uri) {}

	// BaseHook Functions
    function getHookPermissions()
        public
        pure
        override
        returns (Hooks.Permissions memory)
    {
        return
            Hooks.Permissions({
                beforeInitialize: false,
                afterInitialize: true,
                beforeAddLiquidity: false,
                afterAddLiquidity: false,
                beforeRemoveLiquidity: false,
                afterRemoveLiquidity: false,
                beforeSwap: false,
                afterSwap: true,
                beforeDonate: false,
                afterDonate: false,
                beforeSwapReturnDelta: false,
                afterSwapReturnDelta: false,
                afterAddLiquidityReturnDelta: false,
                afterRemoveLiquidityReturnDelta: false
            });
    }

	

	function afterSwap(
        address sender,
        PoolKey calldata key,
        IPoolManager.SwapParams calldata params,
        BalanceDelta,
        bytes calldata
    ) external override onlyPoolManager returns (bytes4, int128) {
		// TODO
        return (this.afterSwap.selector, 0);
    }

     function getLowerUsableTick(
        int24 tick,
        int24 tickSpacing
    ) private pure returns (int24) {
        // E.g. tickSpacing = 60, tick = -100
        // closest usable tick rounded-down will be -120

        // intervals = -100/60 = -1 (integer division)
        int24 intervals = tick / tickSpacing;

        // since tick < 0, we round `intervals` down to -2
        // if tick > 0, `intervals` is fine as it is
        if (tick < 0 && tick % tickSpacing != 0) intervals--; // round towards negative infinity

        // actual usable tick, then, is intervals * tickSpacing
        // i.e. -2 * 60 = -120
        return intervals * tickSpacing;
    }
}