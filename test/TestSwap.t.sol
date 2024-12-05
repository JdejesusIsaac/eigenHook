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
import {swapAndRestakeEigenRouter} from "../src/swapandRestake.sol";



/**
 * @notice Unit testing of the StrategyManager contract, entire withdrawal tests related to the
 * DelegationManager are not tested here but callable functions by the DelegationManager are mocked and tested here.
 * Contracts tested: StrategyManager.sol
 * Contracts not mocked: StrategyBase, PauserRegistry
 */
contract stakeandRestakeRouterUnitTests is EigenLayerUnitTestSetup, IStrategyManagerEvents, Fixtures {
    using EasyPosm for IPositionManager;
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using StateLibrary for IPoolManager;
    StrategyManager public strategyManagerImplementation;
    StrategyManager public strategyManager;

    bytes4 private constant MAGICVALUE = 0x1626ba7e;

     uint256 public PRIVATE_KEY = 111111;

    address staker1 =  vm.addr(PRIVATE_KEY);

    address depositer = address(0x123);

     swapAndRestakeEigenRouter swapRestakeRouter;

    IERC20 public dummyToken;
    ERC20_SetTransferReverting_Mock public revertToken;
    StrategyBase public dummyStrat;
    StrategyBase public dummyStrat2;
    StrategyBase public dummyStrat3;

    Reenterer public reenterer;

     PoolId poolId;
    uint256 tokenId;
    PositionConfig config;
    int24 tickLower;
    int24 tickUpper;

    address initialOwner = address(this);
    uint256 public privateKey = 111111;
    address constant dummyAdmin = address(uint160(uint256(keccak256("DummyAdmin"))));
    
    uint256 constant INITIAL_LIQUIDITY = 100e18;
   
    uint256 constant SWAP_AMOUNT = 1e18 * 32;

    function setUp() public override {
        vm.deal(address(this), 500 ether);
        
        uint256 initialBalance = 32 * 1e18;
        // Mint a reasonable amount of tokens
  
    
         // Deploy base contracts
        deployFreshManagerAndRouters();
        deployMintAndApprove2Currencies();
        deployAndApprovePosm(manager);
        EigenLayerUnitTestSetup.setUp();
        strategyManagerImplementation = new StrategyManager(delegationManagerMock, eigenPodManagerMock, slasherMock);
        strategyManager = StrategyManager(
            address(
                new TransparentUpgradeableProxy(
                    address(strategyManagerImplementation),
                    address(eigenLayerProxyAdmin),
                    abi.encodeWithSelector(
                        StrategyManager.initialize.selector,
                        initialOwner,
                        initialOwner,
                        pauserRegistry,
                        0 /*initialPausedStatus*/
                    )
                )
            )
        );
        dummyToken =  IERC20(Currency.unwrap(currency1));
       
         MockERC20(Currency.unwrap(currency1)).mint(address(this), initialBalance);
         MockERC20(Currency.unwrap(currency1)).approve(address(manager), initialBalance);
        
        revertToken = new ERC20_SetTransferReverting_Mock(1000e18, address(this));
        revertToken.setTransfersRevert(true);
        dummyStrat = _deployNewStrategy(dummyToken, strategyManager, pauserRegistry, dummyAdmin);
        dummyStrat2 = _deployNewStrategy(dummyToken, strategyManager, pauserRegistry, dummyAdmin);
        dummyStrat3 = _deployNewStrategy(dummyToken, strategyManager, pauserRegistry, dummyAdmin);

        // whitelist the strategy for deposit
        cheats.prank(strategyManager.owner());
        IStrategy[] memory _strategies = new IStrategy[](3);
        _strategies[0] = dummyStrat;
        _strategies[1] = dummyStrat2;
        _strategies[2] = dummyStrat3;
        bool[] memory _thirdPartyTransfersForbiddenValues = new bool[](3);
        _thirdPartyTransfersForbiddenValues[0] = false;
        _thirdPartyTransfersForbiddenValues[1] = false;
        _thirdPartyTransfersForbiddenValues[2] = false;
        for (uint256 i = 0; i < _strategies.length; ++i) {
            cheats.expectEmit(true, true, true, true, address(strategyManager));
            emit StrategyAddedToDepositWhitelist(_strategies[i]);
            cheats.expectEmit(true, true, true, true, address(strategyManager));
            emit UpdatedThirdPartyTransfersForbidden(_strategies[i], _thirdPartyTransfersForbiddenValues[i]);
        }
        strategyManager.addStrategiesToDepositWhitelist(_strategies, _thirdPartyTransfersForbiddenValues);

        addressIsExcludedFromFuzzedInputs[address(reenterer)] = true;

        swapRestakeRouter = new swapAndRestakeEigenRouter(manager, address(strategyManager));
        swapRestakeRouter.addTokenStrategyMapping(address(dummyToken), IStrategy(dummyStrat));



         key = PoolKey(currency0, currency1, 3000, 60, IHooks(address(0)));
        poolId = key.toId();
        manager.initialize(key, SQRT_PRICE_1_1, ZERO_BYTES);

       

         // Setup liquidity position
        tickLower = TickMath.minUsableTick(key.tickSpacing);
        tickUpper = TickMath.maxUsableTick(key.tickSpacing);

        (uint256 amount0Expected, uint256 amount1Expected) = LiquidityAmounts.getAmountsForLiquidity(
            SQRT_PRICE_1_1,
            TickMath.getSqrtPriceAtTick(tickLower),
            TickMath.getSqrtPriceAtTick(tickUpper),
            uint128(INITIAL_LIQUIDITY)
        );

         (tokenId,) = posm.mint(
            key,
            tickLower,
            tickUpper,
            uint128(INITIAL_LIQUIDITY),
            amount0Expected + 1,
            amount1Expected + 1,
            address(this),
            block.timestamp,
            ZERO_BYTES
        );

         // Mint tokens to the test contract itself
    MockERC20(Currency.unwrap(currency0)).mint(address(this), SWAP_AMOUNT);
    
    // Important: Also mint tokens to the pool for liquidity
    MockERC20(Currency.unwrap(currency0)).mint(address(manager), INITIAL_LIQUIDITY);
    MockERC20(Currency.unwrap(currency1)).mint(address(manager), INITIAL_LIQUIDITY);

    // Approve tokens for the pool manager
    MockERC20(Currency.unwrap(currency0)).approve(address(manager), type(uint256).max);
    MockERC20(Currency.unwrap(currency1)).approve(address(manager), type(uint256).max);

    // Add initial liquidity to the pool
     (key, ) = initPool(
            
             
            Currency.wrap(address(0)),
             
            Currency.wrap(address(dummyToken)),
            IHooks(address(0)),
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

    






       
      

       
         // Setup pool
       
        

             // Approvals
      //  IERC20(Currency.unwrap(currency0)).approve(address(hook), type(uint256).max);
      //  IERC20(Currency.unwrap(currency1)).approve(address(hook), type(uint256).max);

        
       

          IERC20(Currency.unwrap(currency0)).approve(address(staker1), type(uint256).max);
         IERC20(Currency.unwrap(currency0)).approve(address(staker1), type(uint256).max);
        
        IERC20(Currency.unwrap(currency1)).approve(address(dummyStrat), SWAP_AMOUNT);
        IERC20(Currency.unwrap(currency1)).approve(address(swapRestakeRouter), type(uint256).max);
      //allowance for strategy manager
        IERC20(Currency.unwrap(currency1)).approve(address(this), type(uint256).max);
        IERC20(Currency.unwrap(currency1)).approve(address(strategyManager), SWAP_AMOUNT);




            console.log("Token Address:", address(dummyToken));
            console.log("Strategy Address:", address(dummyStrat));
   console.log("Is Strategy Whitelisted:", strategyManager.strategyIsWhitelistedForDeposit(dummyStrat));
        
      



    }

     function test_swapETHForOUtDepositToEigenLayer()
        public
    {
       
    
   

        swapRestakeRouter.swap{value: 1 ether}(
            key,
            IPoolManager.SwapParams({
                zeroForOne: true,
                amountSpecified: -1 ether,
                sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
            }),
            swapAndRestakeEigenRouter.SwapSettings({
                depositTokens: true,
                recipientAddress: address(this),
                eigenLayerStrategy: address(dummyStrat)


            }),
            ZERO_BYTES
        );
    }

    function test_swapETHForOUtDepositToEigen1() public {


    // Use smaller, more reasonable amounts for testing
    uint256 swapAmount = 0.1 ether; // 0.1 ETH

     // Verify strategy setup before swap
    address tokenAddress = Currency.unwrap(currency1);
    require(strategyManager.strategyIsWhitelistedForDeposit(dummyStrat), "Strategy not whitelisted");
    require(address(dummyStrat.underlyingToken()) == tokenAddress, "Wrong token in strategy");

    swapAndRestakeEigenRouter.SwapSettings memory settings = swapAndRestakeEigenRouter.SwapSettings({
        depositTokens: true,
        recipientAddress: address(this),
        eigenLayerStrategy: address(dummyStrat)
    });

    IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
        zeroForOne: true,
        amountSpecified: -int256(swapAmount), // Convert to negative for exact input
        sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
    });

    // Debug logs
     console.log("Initial ETH Balance:", address(this).balance);
    console.log("Swap Amount:", swapAmount);
    console.log("Strategy Address in Settings:", settings.eigenLayerStrategy);


    swapRestakeRouter.swap{value: swapAmount}(
        key,
        params,
        settings,
        ZERO_BYTES
    );

    // Debug logs after swap
    console.log("Token Balance After Swap:", IERC20(Currency.unwrap(currency1)).balanceOf(address(this)));
}

function test_SwapWithSpecificPool_Success() public {
    uint256 swapAmount = 0.1 ether;
    
    // Set the specific pool that should be used
    swapRestakeRouter.setSpecificPool(
        Currency.wrap(address(0)),  // ETH
        Currency.wrap(address(dummyToken)),  // MockERC20
        3000,       // fee
        60,         // tickSpacing
        IHooks(address(0))
    );

    // Create swap settings
    swapAndRestakeEigenRouter.SwapSettings memory settings = swapAndRestakeEigenRouter.SwapSettings({
        depositTokens: true,
        recipientAddress: address(this),
        eigenLayerStrategy: address(dummyStrat)
    });

    // Create swap params
    IPoolManager.SwapParams memory params = IPoolManager.SwapParams({
        zeroForOne: true,
        amountSpecified: -int256(swapAmount),
        sqrtPriceLimitX96: TickMath.MIN_SQRT_PRICE + 1
    });

    // This should succeed as we're using the correct pool
    swapRestakeRouter.swap{value: swapAmount}(
        key,        // This matches our specific pool
        params,
        settings,
        ZERO_BYTES
    );
}

// Add new test functions for specific pool functionality


function test_SwapWithWrongPool_Reverts() public {
    // ... test implementation
}

function test_SwapBeforePoolSet_Reverts() public {
    // ... test implementation
}




      


// ... existing imports and setup ...





// Helper function to extract `bytes32` from `bytes` at a specific index




        

    // INTERNAL / HELPER FUNCTIONS
    function _deployNewStrategy(
        IERC20 _token,
        IStrategyManager _strategyManager,
        IPauserRegistry _pauserRegistry,
        address admin
    ) public returns (StrategyBase) {
        StrategyBase newStrategy = new StrategyBase(_strategyManager);
        newStrategy = StrategyBase(address(new TransparentUpgradeableProxy(address(newStrategy), address(admin), "")));
        newStrategy.initialize(_token, _pauserRegistry);
        return newStrategy;
    }

    function _depositIntoStrategySuccessfully(
        IStrategy strategy,
        address staker,
        uint256 amount
    ) internal filterFuzzedAddressInputs(staker) {
        IERC20 token = dummyToken;

        // filter out zero case since it will revert with "StrategyManager._addShares: shares should not be zero!"
        cheats.assume(amount != 0);
        // filter out zero address because the mock ERC20 we are using will revert on using it
        cheats.assume(staker != address(0));
        // sanity check / filter
        cheats.assume(amount <= token.balanceOf(address(this)));

        uint256 sharesBefore = strategyManager.stakerStrategyShares(staker, strategy);
        uint256 stakerStrategyListLengthBefore = strategyManager.stakerStrategyListLength(staker);

        // needed for expecting an event with the right parameters
        uint256 expectedShares = amount;

        cheats.prank(staker);
        cheats.expectEmit(true, true, true, true, address(strategyManager));
        emit Deposit(staker, token, strategy, expectedShares);
        uint256 shares = strategyManager.depositIntoStrategy(strategy, token, amount);

        uint256 sharesAfter = strategyManager.stakerStrategyShares(staker, strategy);
        uint256 stakerStrategyListLengthAfter = strategyManager.stakerStrategyListLength(staker);

        assertEq(sharesAfter, sharesBefore + shares, "sharesAfter != sharesBefore + shares");
        if (sharesBefore == 0) {
            assertEq(
                stakerStrategyListLengthAfter,
                stakerStrategyListLengthBefore + 1,
                "stakerStrategyListLengthAfter != stakerStrategyListLengthBefore + 1"
            );
            assertEq(
                address(strategyManager.stakerStrategyList(staker, stakerStrategyListLengthAfter - 1)),
                address(strategy),
                "strategyManager.stakerStrategyList(staker, stakerStrategyListLengthAfter - 1) != strategy"
            );
        }
    }

    // internal function for de-duping code. expects success if `expectedRevertMessage` is empty and expiry is valid.
    function _depositIntoStrategyWithSignature(
        address staker,
        uint256 amount,
        uint256 expiry,
        string memory expectedRevertMessage
    ) internal returns (bytes memory) {
        // filter out zero case since it will revert with "StrategyManager._addShares: shares should not be zero!"
        cheats.assume(amount != 0);
        // sanity check / filter
        cheats.assume(amount <= dummyToken.balanceOf(address(this)));

        uint256 nonceBefore = strategyManager.nonces(staker);
        bytes memory signature;

        {
            bytes32 structHash = keccak256(
                abi.encode(strategyManager.DEPOSIT_TYPEHASH(), staker, dummyStrat, dummyToken, amount, nonceBefore, expiry)
            );
            bytes32 digestHash = keccak256(abi.encodePacked("\x19\x01", strategyManager.domainSeparator(), structHash));

            (uint8 v, bytes32 r, bytes32 s) = cheats.sign(privateKey, digestHash);

            signature = abi.encodePacked(r, s, v);
        }

        uint256 sharesBefore = strategyManager.stakerStrategyShares(staker, dummyStrat);

        bool expectedRevertMessageIsempty;
        {
            string memory emptyString;
            expectedRevertMessageIsempty =
                keccak256(abi.encodePacked(expectedRevertMessage)) == keccak256(abi.encodePacked(emptyString));
        }
        if (!expectedRevertMessageIsempty) {
            cheats.expectRevert(bytes(expectedRevertMessage));
        } else if (expiry < block.timestamp) {
            cheats.expectRevert("StrategyManager.depositIntoStrategyWithSignature: signature expired");
        } else {
            // needed for expecting an event with the right parameters
            uint256 expectedShares = amount;
            cheats.expectEmit(true, true, true, true, address(strategyManager));
            emit Deposit(staker, dummyToken, dummyStrat, expectedShares);
        }
        uint256 shares = strategyManager.depositIntoStrategyWithSignature(
            dummyStrat,
            dummyToken,
            amount,
            staker,
            expiry,
            signature
        );

        uint256 sharesAfter = strategyManager.stakerStrategyShares(staker, dummyStrat);
        uint256 nonceAfter = strategyManager.nonces(staker);

        if (expiry >= block.timestamp && expectedRevertMessageIsempty) {
            assertEq(sharesAfter, sharesBefore + shares, "sharesAfter != sharesBefore + shares");
            assertEq(nonceAfter, nonceBefore + 1, "nonceAfter != nonceBefore + 1");
        }
        return signature;
    }

    /**
     * @notice internal function to help check if a strategy is part of list of deposited strategies for a staker
     * Used to check if removed correctly after withdrawing all shares for a given strategy
     */
    function _isDepositedStrategy(address staker, IStrategy strategy) internal view returns (bool) {
        uint256 stakerStrategyListLength = strategyManager.stakerStrategyListLength(staker);
        for (uint256 i = 0; i < stakerStrategyListLength; ++i) {
            if (strategyManager.stakerStrategyList(staker, i) == strategy) {
                return true;
            }
        }
        return false;
    }

    /**
     * @notice Deploys numberOfStrategiesToAdd new strategies and adds them to the whitelist
     */
    function _addStrategiesToWhitelist(uint8 numberOfStrategiesToAdd) internal returns (IStrategy[] memory) {
        IStrategy[] memory strategyArray = new IStrategy[](numberOfStrategiesToAdd);
        bool[] memory thirdPartyTransfersForbiddenValues = new bool[](numberOfStrategiesToAdd);
        // loop that deploys a new strategy and adds it to the array
        for (uint256 i = 0; i < numberOfStrategiesToAdd; ++i) {
            IStrategy _strategy = _deployNewStrategy(dummyToken, strategyManager, pauserRegistry, dummyAdmin);
            strategyArray[i] = _strategy;
            assertFalse(strategyManager.strategyIsWhitelistedForDeposit(_strategy), "strategy improperly whitelisted?");
        }

        cheats.prank(strategyManager.strategyWhitelister());
        for (uint256 i = 0; i < numberOfStrategiesToAdd; ++i) {
            cheats.expectEmit(true, true, true, true, address(strategyManager));
            emit StrategyAddedToDepositWhitelist(strategyArray[i]);
        }
        strategyManager.addStrategiesToDepositWhitelist(strategyArray, thirdPartyTransfersForbiddenValues);

        for (uint256 i = 0; i < numberOfStrategiesToAdd; ++i) {
            assertTrue(strategyManager.strategyIsWhitelistedForDeposit(strategyArray[i]), "strategy not whitelisted");
        }

        return strategyArray;
    }

    function _verifySignature(
        address staker,
        bytes32 digestHash,
        bytes memory signature
    ) internal view {
        if (isContract(staker)) {
            require(
                IERC1271(staker).isValidSignature(digestHash, signature) == MAGICVALUE,
                "DepositToHook: ERC1271 signature verification failed"
            );
        } else {
            require(
                ECDSA.recover(digestHash, signature) == staker,
                "DepositToHook: signature not from staker"
            );
        }
    }

    function isContract(address account) internal view returns (bool) {
        uint256 size;
        // XXX Currently there is no better way to check if there is a contract in an address
        // than to check the size of the code at that address.
        // See https://ethereum.stackexchange.com/a/14016/36603
        // for more details about how this works.
        // TODO Check this again before the Serenity release, because all addresses will be
        // contracts then.
        // solhint-disable-next-line no-inline-assembly
        assembly { size := extcodesize(account) }
        return size > 0;
    }
}



contract StrategyManagerUnitTests_depositIntoStrategyWithSignatures is stakeandRestakeRouterUnitTests {
    function test_Revert_WhenSignatureInvalid() public {
        address staker = cheats.addr(privateKey);
        IStrategy strategy = dummyStrat;
        IERC20 token = dummyToken;
        uint256 amount = 1e18;

        uint256 nonceBefore = strategyManager.nonces(staker);
        uint256 expiry = block.timestamp;
        bytes memory signature;

        {
            bytes32 structHash = keccak256(
                abi.encode(strategyManager.DEPOSIT_TYPEHASH(), staker, strategy, token, amount, nonceBefore, expiry)
            );
            bytes32 digestHash = keccak256(abi.encodePacked("\x19\x01", strategyManager.domainSeparator(), structHash));

            (uint8 v, bytes32 r, bytes32 s) = cheats.sign(privateKey, digestHash);

            signature = abi.encodePacked(r, s, v);
        }

        uint256 sharesBefore = strategyManager.stakerStrategyShares(staker, strategy);

        cheats.expectRevert("EIP1271SignatureUtils.checkSignature_EIP1271: signature not from signer");
        // call with `notStaker` as input instead of `staker` address
        address notStaker = address(3333);
        strategyManager.depositIntoStrategyWithSignature(strategy, token, amount, notStaker, expiry, signature);

        uint256 sharesAfter = strategyManager.stakerStrategyShares(staker, strategy);
        uint256 nonceAfter = strategyManager.nonces(staker);

        assertEq(sharesAfter, sharesBefore, "sharesAfter != sharesBefore");
        assertEq(nonceAfter, nonceBefore, "nonceAfter != nonceBefore");
    }

    function testFuzz_DepositSuccess10(uint256 amount, uint256 expiry) public {
        // min shares must be minted on strategy
        cheats.assume(amount >= 1);

        address staker = cheats.addr(privateKey);
        // not expecting a revert, so input an empty string
        string memory expectedRevertMessage;
        _depositIntoStrategyWithSignature(staker, amount, expiry, expectedRevertMessage);
    }

    function testFuzz_Revert_SignatureReplay(uint256 amount, uint256 expiry) public {
        // min shares must be minted on strategy
        cheats.assume(amount >= 1);
        cheats.assume(expiry > block.timestamp);

        address staker = cheats.addr(privateKey);
        // not expecting a revert, so input an empty string
        bytes memory signature = _depositIntoStrategyWithSignature(staker, amount, expiry, "");

        cheats.expectRevert("EIP1271SignatureUtils.checkSignature_EIP1271: signature not from signer");
        strategyManager.depositIntoStrategyWithSignature(dummyStrat, dummyToken, amount, staker, expiry, signature);
    }

    // tries depositing using a signature and an EIP 1271 compliant wallet, *but* providing a bad signature
    function testFuzz_Revert_WithContractWallet_BadSignature(uint256 amount) public {
        // min shares must be minted on strategy
        cheats.assume(amount >= 1);

        address staker = cheats.addr(privateKey);
        IStrategy strategy = dummyStrat;
        IERC20 token = dummyToken;

        // deploy ERC1271WalletMock for staker to use
        cheats.prank(staker);
        ERC1271WalletMock wallet = new ERC1271WalletMock(staker);
        staker = address(wallet);

        // filter out zero case since it will revert with "StrategyManager._addShares: shares should not be zero!"
        cheats.assume(amount != 0);
        // sanity check / filter
        cheats.assume(amount <= token.balanceOf(address(this)));

        uint256 nonceBefore = strategyManager.nonces(staker);
        uint256 expiry = type(uint256).max;
        bytes memory signature;

        {
            bytes32 structHash = keccak256(
                abi.encode(strategyManager.DEPOSIT_TYPEHASH(), staker, strategy, token, amount, nonceBefore, expiry)
            );
            bytes32 digestHash = keccak256(abi.encodePacked("\x19\x01", strategyManager.domainSeparator(), structHash));

            (uint8 v, bytes32 r, bytes32 s) = cheats.sign(privateKey, digestHash);
            // mess up the signature by flipping v's parity
            v = (v == 27 ? 28 : 27);

            signature = abi.encodePacked(r, s, v);
        }

        cheats.expectRevert("EIP1271SignatureUtils.checkSignature_EIP1271: ERC1271 signature verification failed");
        strategyManager.depositIntoStrategyWithSignature(strategy, token, amount, staker, expiry, signature);
    }

    // tries depositing using a wallet that does not comply with EIP 1271
    function testFuzz_Revert_WithContractWallet_NonconformingWallet(
        uint256 amount,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        // min shares must be minted on strategy
        cheats.assume(amount >= 1);

        address staker = cheats.addr(privateKey);
        IStrategy strategy = dummyStrat;
        IERC20 token = dummyToken;

        // deploy ERC1271WalletMock for staker to use
        cheats.prank(staker);
        ERC1271MaliciousMock wallet = new ERC1271MaliciousMock();
        staker = address(wallet);

        // filter out zero case since it will revert with "StrategyManager._addShares: shares should not be zero!"
        cheats.assume(amount != 0);
        // sanity check / filter
        cheats.assume(amount <= token.balanceOf(address(this)));

        uint256 expiry = type(uint256).max;
        bytes memory signature = abi.encodePacked(r, s, v);

        cheats.expectRevert();
        strategyManager.depositIntoStrategyWithSignature(strategy, token, amount, staker, expiry, signature);
    }

    // Tries depositing without token approval and transfer fails. deposit function should also revert
    function test_Revert_WithContractWallet_TokenTransferFails() external {
        address staker = cheats.addr(privateKey);
        uint256 amount = 1e18;
        uint256 nonceBefore = strategyManager.nonces(staker);
        uint256 expiry = block.timestamp + 100;
        bytes memory signature;

        {
            bytes32 structHash = keccak256(
                abi.encode(strategyManager.DEPOSIT_TYPEHASH(), staker, dummyStrat, revertToken, amount, nonceBefore, expiry)
            );
            bytes32 digestHash = keccak256(abi.encodePacked("\x19\x01", strategyManager.domainSeparator(), structHash));

            (uint8 v, bytes32 r, bytes32 s) = cheats.sign(privateKey, digestHash);

            signature = abi.encodePacked(r, s, v);
        }

        cheats.expectRevert("ERC20: insufficient allowance");
        strategyManager.depositIntoStrategyWithSignature(dummyStrat, revertToken, amount, staker, expiry, signature);
    }

    // tries depositing using a signature and an EIP 1271 compliant wallet
    function testFuzz_WithContractWallet_Success(uint256 amount, uint256 expiry) public {
        // min shares must be minted on strategy
        cheats.assume(amount >= 1);

        address staker = cheats.addr(privateKey);

        // deploy ERC1271WalletMock for staker to use
        cheats.prank(staker);
        ERC1271WalletMock wallet = new ERC1271WalletMock(staker);
        staker = address(wallet);

        // not expecting a revert, so input an empty string
        string memory expectedRevertMessage;
        _depositIntoStrategyWithSignature(staker, amount, expiry, expectedRevertMessage);
    }

    function test_Revert_WhenDepositsPaused() public {
        address staker = cheats.addr(privateKey);

        // pause deposits
        cheats.prank(pauser);
        strategyManager.pause(1);

        string memory expectedRevertMessage = "Pausable: index is paused";
        _depositIntoStrategyWithSignature(staker, 1e18, type(uint256).max, expectedRevertMessage);
    }

    /**
     * @notice reenterer contract which is configured as the strategy contract
     * is configured to call depositIntoStrategy after reenterer.deposit() is called from the
     * depositIntoStrategyWithSignature() is called from the StrategyManager. Situation is not likely to occur given
     * the strategy has to be whitelisted but it at least protects from reentrant attacks
     */
    function test_Revert_WhenReentering() public {
        reenterer = new Reenterer();

        // whitelist the strategy for deposit
        cheats.startPrank(strategyManager.owner());
        IStrategy[] memory _strategy = new IStrategy[](1);
        bool[] memory _thirdPartyTransfersForbiddenValues = new bool[](1);

        
        _strategy[0] = IStrategy(address(reenterer));
        for (uint256 i = 0; i < _strategy.length; ++i) {
            cheats.expectEmit(true, true, true, true, address(strategyManager));
            emit StrategyAddedToDepositWhitelist(_strategy[i]);
        }
        strategyManager.addStrategiesToDepositWhitelist(_strategy, _thirdPartyTransfersForbiddenValues);
        cheats.stopPrank();

        address staker = cheats.addr(privateKey);
        IStrategy strategy = IStrategy(address(reenterer));
        IERC20 token = dummyToken;
        uint256 amount = 1e18;

        uint256 nonceBefore = strategyManager.nonces(staker);
        uint256 expiry = type(uint256).max;
        bytes memory signature;

        {
            bytes32 structHash = keccak256(
                abi.encode(strategyManager.DEPOSIT_TYPEHASH(), staker, strategy, token, amount, nonceBefore, expiry)
            );
            bytes32 digestHash = keccak256(abi.encodePacked("\x19\x01", strategyManager.domainSeparator(), structHash));

            (uint8 v, bytes32 r, bytes32 s) = cheats.sign(privateKey, digestHash);

            signature = abi.encodePacked(r, s, v);
        }

        uint256 shareAmountToReturn = amount;
        reenterer.prepareReturnData(abi.encode(shareAmountToReturn));

        {
            address targetToUse = address(strategyManager);
            uint256 msgValueToUse = 0;
            bytes memory calldataToUse = abi.encodeWithSelector(
                StrategyManager.depositIntoStrategy.selector,
                address(reenterer),
                dummyToken,
                amount
            );
            reenterer.prepare(targetToUse, msgValueToUse, calldataToUse, bytes("ReentrancyGuard: reentrant call"));
        }
        strategyManager.depositIntoStrategyWithSignature(strategy, token, amount, staker, expiry, signature);
    }

    function test_Revert_WhenSignatureExpired() public {
        address staker = cheats.addr(privateKey);
        IStrategy strategy = dummyStrat;
        IERC20 token = dummyToken;
        uint256 amount = 1e18;

        uint256 nonceBefore = strategyManager.nonces(staker);
        uint256 expiry = 5555;
        // warp to 1 second after expiry
        cheats.warp(expiry + 1);
        bytes memory signature;

        {
            bytes32 structHash = keccak256(
                abi.encode(strategyManager.DEPOSIT_TYPEHASH(), staker, strategy, token, amount, nonceBefore, expiry)
            );
            bytes32 digestHash = keccak256(abi.encodePacked("\x19\x01", strategyManager.domainSeparator(), structHash));

            (uint8 v, bytes32 r, bytes32 s) = cheats.sign(privateKey, digestHash);

            signature = abi.encodePacked(r, s, v);
        }

        uint256 sharesBefore = strategyManager.stakerStrategyShares(staker, strategy);

        cheats.expectRevert("StrategyManager.depositIntoStrategyWithSignature: signature expired");
        strategyManager.depositIntoStrategyWithSignature(strategy, token, amount, staker, expiry, signature);

        uint256 sharesAfter = strategyManager.stakerStrategyShares(staker, strategy);
        uint256 nonceAfter = strategyManager.nonces(staker);

        assertEq(sharesAfter, sharesBefore, "sharesAfter != sharesBefore");
        assertEq(nonceAfter, nonceBefore, "nonceAfter != nonceBefore");
    }

    function test_Revert_WhenStrategyNotWhitelisted() external {
        // replace 'dummyStrat' with one that is not whitelisted
        dummyStrat = _deployNewStrategy(dummyToken, strategyManager, pauserRegistry, dummyAdmin);
        dummyToken = dummyStrat.underlyingToken();
        address staker = cheats.addr(privateKey);
        uint256 amount = 1e18;

        string
            memory expectedRevertMessage = "StrategyManager.onlyStrategiesWhitelistedForDeposit: strategy not whitelisted";
        _depositIntoStrategyWithSignature(staker, amount, type(uint256).max, expectedRevertMessage);
    }
    
    function testFuzz_Revert_WhenThirdPartyTransfersForbidden(uint256 amount, uint256 expiry) public {
        // min shares must be minted on strategy
        cheats.assume(amount >= 1);

        cheats.prank(strategyManager.strategyWhitelister());
        strategyManager.setThirdPartyTransfersForbidden(dummyStrat, true);

        address staker = cheats.addr(privateKey);
        // not expecting a revert, so input an empty string
        string memory expectedRevertMessage = "StrategyManager.depositIntoStrategyWithSignature: third transfers disabled";
        _depositIntoStrategyWithSignature(staker, amount, expiry, expectedRevertMessage);
    }
}