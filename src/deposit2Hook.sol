// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import {BaseHook} from "v4-periphery/src/base/hooks/BaseHook.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {Hooks} from "v4-core/src/libraries/Hooks.sol";
import {IPoolManager} from "v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "v4-core/src/types/PoolKey.sol";
import {BalanceDelta} from "v4-core/src/types/BalanceDelta.sol";
import {Currency} from "v4-core/src/types/Currency.sol";
import {CurrencySettler} from "v4-core/test/utils/CurrencySettler.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "../src/interfaces/IDelegationManager.sol";
import "../src/interfaces/IStrategyManager.sol";
import "../src/interfaces/IStrategy.sol";
import "../src/EigenLayer/StrategyManager.sol";



contract Deposit2Hook is BaseHook {
    using SafeERC20 for IERC20Permit;
    using CurrencySettler for Currency;

    bytes4 private constant MAGICVALUE = 0x1626ba7e;
    address private constant STETH = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;

     

    IDelegationManager public immutable delegationManager;
    StrategyManager public strategyManager;
    
    IStrategy public strategy;
    mapping(address => uint256) public nonces;

    uint256 private immutable ORIGINAL_CHAIN_ID;

    bytes32 public constant DEPOSIT_TYPEHASH = keccak256(
        "Deposit(address staker,address strategy,address token,uint256 amount,uint256 nonce,uint256 expiry)"
    );
    

    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,uint256 chainId,address verifyingContract)"
    );

    event DepositedWithSignature(
        address indexed staker,
        address indexed strategy,
        IERC20 indexed token,
        uint256 amount,
        uint256 shares,
        uint256 expiry
    );

    

    error SignatureExpired();
    error InvalidSignature();
    error OutputAmountNotPositive();
    error StrategyManagerNotSet();
    error InvalidStrategy();
    error PermitFailed(string reason);
    error DepositFailed();
    error InvalidStaker();
    
    struct EigenDockSwapParams {
    PoolKey key;
    address staker;        // Original user doing the swap
    IPoolManager.SwapParams params;
    bytes signature;       // Signature for strategy deposit
    IStrategy strategy;    // Target strategy
}



     string public constant DOMAIN_NAME = "Deposit2Hook";
    bytes32 public immutable DOMAIN_SEPARATOR;

    constructor(IPoolManager _poolManager, address _strategyManager) BaseHook(_poolManager) {
        strategyManager = StrategyManager(_strategyManager);
        ORIGINAL_CHAIN_ID = block.chainid;
        
        // Initialize domain separator
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(DOMAIN_NAME)),
                ORIGINAL_CHAIN_ID,
                address(this)
            )
        );
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
    address, // Unused sender parameter
    PoolKey calldata key,
    IPoolManager.SwapParams calldata params,
    BalanceDelta delta,
    bytes calldata hookData
) external override onlyPoolManager returns (bytes4, int128) {
    // Decode hookData to get the strategy, staker, expiry, and signature
    (IStrategy eigenLayerStrategy, address staker, uint256 expiry, bytes memory signature) = abi.decode(
        hookData,
        (IStrategy, address, uint256, bytes)
    );

    // Deposit LST into the strategy using the decoded values
    int128 outputAmount = depositLstIntoStrategy(
        key,
        delta,
        eigenLayerStrategy,
        staker,
        expiry,
        signature,
        params.zeroForOne
    );

    return (BaseHook.afterSwap.selector, outputAmount);
}


     function _unlockCallback(bytes calldata rawData) internal virtual override onlyPoolManager returns (bytes memory) {
        EigenDockSwapParams memory data = abi.decode(rawData, (EigenDockSwapParams));

        // Execute swap and get delta
        BalanceDelta delta = poolManager.swap(data.key, data.params, "");

        // Handle settlements for both tokens if needed
        if (delta.amount0() < 0) {
            data.key.currency0.settle(poolManager, data.staker, uint128(-delta.amount0()), false);
        }
        if (delta.amount1() < 0) {
            data.key.currency1.settle(poolManager, data.staker, uint128(-delta.amount1()), false);
        }

        // Return delta for afterSwap hook processing
        return abi.encode(delta);
    }


    function depositLstIntoStrategy(
    PoolKey memory key,
    BalanceDelta delta,
    IStrategy eigenLayerStrategy,
    address staker,
    uint256 expiry,
    bytes memory signature,
    bool zeroForOne
) internal returns (int128) {
    // Determine the amount of stETH received based on swap direction
    int128 outputAmount = zeroForOne ? delta.amount1() : delta.amount0();
    if (outputAmount <= 0) {
        return 0; // No output amount, return early
    }

    Currency outputCurrency = zeroForOne ? key.currency1 : key.currency0;

    // Transfer stETH from the pool to this contract
    poolManager.take(outputCurrency, address(this), uint128(outputAmount));
    IERC20 outputToken = IERC20(Currency.unwrap(outputCurrency));

    uint256 amount = uint256(uint128(outputAmount));

  //  _verifyDepositSignature(staker, address(eigenLayerStrategy), address(outputToken), amount, expiry, signature);

    // Approve the StrategyManager for the output token
    outputToken.approve(address(strategyManager), amount);

  
    
   

    // Deposit into strategy
    uint256 shares = strategyManager.depositIntoStrategyWithSignature(
        eigenLayerStrategy,
        outputToken,
        amount,
        staker,
        expiry,
        signature
    );

    // Emit an event for transparency
    emit DepositedWithSignature(staker, address(eigenLayerStrategy), outputToken, amount, shares, expiry);

    return outputAmount;
}

function _verifyDepositSignature(
    address staker,
    address strategys,
    address token,
    uint256 amount,
    uint256 expiry,
    bytes memory signature
) internal view {
    if (block.timestamp > expiry) {
        revert SignatureExpired();
    }

    // Get the nonce from strategy manager
    uint256 nonce = strategyManager.nonces(staker);
    
    // Create the EIP-712 compliant hash using StrategyManager's DEPOSIT_TYPEHASH
    bytes32 structHash = keccak256(
        abi.encode(
            strategyManager.DEPOSIT_TYPEHASH(),
            staker,
            strategys,
            token,
            amount,
            nonce,
            expiry
        )
    );
    
    // Create the final digest using StrategyManager's domain separator
    bytes32 digest = keccak256(
        abi.encodePacked("\x19\x01", strategyManager.domainSeparator(), structHash)
    );

    // Split signature into r, s, v components
    if (signature.length != 65) revert InvalidSignature();
    bytes32 r;
    bytes32 s;
    uint8 v;
    assembly {
        r := mload(add(signature, 32))
        s := mload(add(signature, 64))
        v := byte(0, mload(add(signature, 96)))
    }

    // Verify signature
    address recoveredSigner = ecrecover(digest, v, r, s);
    if (recoveredSigner == address(0) || recoveredSigner != staker) {
        revert InvalidSignature();
    }
}

 

     //Verify signature
   


   
      
    

       

    // Get initial shares
   

   


    
   function isContract(address account) internal view returns (bool) {
        return account.code.length > 0;
    }

   
}

