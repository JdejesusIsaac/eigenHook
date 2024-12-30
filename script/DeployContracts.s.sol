// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {IHooks} from "v4-core/src/interfaces/IHooks.sol";
import {Currency, CurrencyLibrary} from "v4-core/src/types/Currency.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {PoolModifyLiquidityTest} from "v4-core/src/test/PoolModifyLiquidityTest.sol";

import {swapAndRestakeEigenRouter} from "../src/swapandRestake.sol";
import {Deployers} from "v4-core/test/utils/Deployers.sol";

import {TickMath} from "v4-core/src/libraries/TickMath.sol";



import "forge-std/Script.sol";