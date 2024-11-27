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
//import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";

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
import {LiquidityAmounts} from "v4-core/test/utils/LiquidityAmounts.sol";
import {EasyPosm} from "./utils/EasyPosm.sol";
import {Fixtures} from "./utils/Fixtures.sol";

import {Deposit2Hook} from "../src/deposit2Hook.sol";



/**
 * @notice Unit testing of the StrategyManager contract, entire withdrawal tests related to the
 * DelegationManager are not tested here but callable functions by the DelegationManager are mocked and tested here.
 * Contracts tested: StrategyManager.sol
 * Contracts not mocked: StrategyBase, PauserRegistry
 */
contract StrategyManagerUnitTests is EigenLayerUnitTestSetup, IStrategyManagerEvents, Fixtures {

    using EasyPosm for IPositionManager;
    using PoolIdLibrary for PoolKey;
    using CurrencyLibrary for Currency;
    using StateLibrary for IPoolManager;

    Deposit2Hook hook;


    StrategyManager public strategyManagerImplementation;
    StrategyManager public strategyManager;

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

       //cheats.addr(PRIVATE_KEY);

    uint256 constant INITIAL_LIQUIDITY = 100e18;
    uint256 constant SWAP_AMOUNT = 1e18 * 32;



    address initialOwner = address(this);
    uint256 public privateKey = 111111;

    address depositor = cheats.addr(privateKey);
   
    address constant dummyAdmin = address(uint160(uint256(keccak256("DummyAdmin"))));

    function setUp() public override {

         deployFreshManagerAndRouters();
        deployMintAndApprove2Currencies();
        deployAndApprovePosm(manager);

         // Deploy base contracts
       
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
        dummyToken =  new ERC20Mock(); //IERC20(Currency.unwrap(currency1));    
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

         key = PoolKey(currency0, currency1, 3000, 60, IHooks(address(0)));

        // Deploy hook with correct flags
        address flags = address(
            uint160(
                Hooks.AFTER_SWAP_FLAG | Hooks.AFTER_SWAP_RETURNS_DELTA_FLAG
            ) ^ (0x4441 << 144)
        );

// Deploy hook with strategy manager// fix this
        deployCodeTo(
            "deposit2Hook.sol:Deposit2Hook",
            abi.encode(manager, address(strategyManager)), 
            flags        
        );
        hook = Deposit2Hook(payable(flags));

         // Setup pool
        key = PoolKey(currency0, currency1, 3000, 60, IHooks(address(hook)));
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

        // Mint position
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

         vm.prank(depositor);
    dummyToken.approve(address(strategyManager), type(uint256).max);
    vm.prank(depositor);
    dummyToken.approve(address(hook), type(uint256).max);

          // Approvals
       // Approvals
IERC20(Currency.unwrap(currency0)).approve(address(hook), type(uint256).max);
IERC20(Currency.unwrap(currency1)).approve(address(hook), type(uint256).max);
IERC20(Currency.unwrap(currency1)).approve(address(dummyStrat), SWAP_AMOUNT);
IERC20(Currency.unwrap(currency1)).approve(address(strategyManager), SWAP_AMOUNT);
    }

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
        address stakers,
        uint256 amount
    ) internal filterFuzzedAddressInputs(stakers) {
        IERC20 token = dummyToken;

        // filter out zero case since it will revert with "StrategyManager._addShares: shares should not be zero!"
        cheats.assume(amount != 0);
        // filter out zero address because the mock ERC20 we are using will revert on using it
        cheats.assume(stakers != address(0));
        // sanity check / filter
        cheats.assume(amount <= token.balanceOf(address(this)));

        uint256 sharesBefore = strategyManager.stakerStrategyShares(stakers, strategy);
        uint256 stakerStrategyListLengthBefore = strategyManager.stakerStrategyListLength(stakers);

        // needed for expecting an event with the right parameters
        uint256 expectedShares = amount;

        cheats.prank(stakers);
        cheats.expectEmit(true, true, true, true, address(strategyManager));
        emit Deposit(stakers, token, strategy, expectedShares);
        uint256 shares = strategyManager.depositIntoStrategy(strategy, token, amount);

        uint256 sharesAfter = strategyManager.stakerStrategyShares(stakers, strategy);
        uint256 stakerStrategyListLengthAfter = strategyManager.stakerStrategyListLength(stakers);

        assertEq(sharesAfter, sharesBefore + shares, "sharesAfter != sharesBefore + shares");
        if (sharesBefore == 0) {
            assertEq(
                stakerStrategyListLengthAfter,
                stakerStrategyListLengthBefore + 1,
                "stakerStrategyListLengthAfter != stakerStrategyListLengthBefore + 1"
            );
            assertEq(
                address(strategyManager.stakerStrategyList(stakers, stakerStrategyListLengthAfter - 1)),
                address(strategy),
                "strategyManager.stakerStrategyList(staker, stakerStrategyListLengthAfter - 1) != strategy"
            );
        }
    }

    // internal function for de-duping code. expects success if `expectedRevertMessage` is empty and expiry is valid.
    function _depositIntoStrategyWithSignature(
        address stakers,
        uint256 amount,
        uint256 expiry,
        string memory expectedRevertMessage
    ) internal returns (bytes memory) {
        // filter out zero case since it will revert with "StrategyManager._addShares: shares should not be zero!"
        cheats.assume(amount != 0);
        // sanity check / filter
        cheats.assume(amount <= dummyToken.balanceOf(address(this)));

        uint256 nonceBefore = strategyManager.nonces(stakers);
        bytes memory signature;

        {
            bytes32 structHash = keccak256(
                abi.encode(strategyManager.DEPOSIT_TYPEHASH(), stakers, dummyStrat, dummyToken, amount, nonceBefore, expiry)
            );
            bytes32 digestHash = keccak256(abi.encodePacked("\x19\x01", strategyManager.domainSeparator(), structHash));

            (uint8 v, bytes32 r, bytes32 s) = cheats.sign(privateKey, digestHash);

            signature = abi.encodePacked(r, s, v);
        }

        uint256 sharesBefore = strategyManager.stakerStrategyShares(stakers, dummyStrat);

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
            emit Deposit(stakers, dummyToken, dummyStrat, expectedShares);
        }
        uint256 shares = strategyManager.depositIntoStrategyWithSignature(
            dummyStrat,
            dummyToken,
            amount,
            stakers,
            expiry,
            signature
        );

        uint256 sharesAfter = strategyManager.stakerStrategyShares(stakers, dummyStrat);
        uint256 nonceAfter = strategyManager.nonces(stakers);

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
    function _isDepositedStrategy(address stakers, IStrategy strategy) internal view returns (bool) {
        uint256 stakerStrategyListLength = strategyManager.stakerStrategyListLength(stakers);
        for (uint256 i = 0; i < stakerStrategyListLength; ++i) {
            if (strategyManager.stakerStrategyList(stakers, i) == strategy) {
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


     function testBasicDepositWithSignature11() public {
   uint256 amount = 1e18;
    bool zeroForOne = true;
    int256 amountSpecified = -int256(amount);
    uint256 expirys = block.timestamp + 1 days;
    uint256 amountToDeposit = 987158034397061298;

     cheats.prank(depositor);
        ERC1271WalletMock wallet = new ERC1271WalletMock(depositor);
        depositor = address(wallet);

    // uint256 amountToDeposit = 987158034397061298;
    
    // Get initial states
    uint256 nonceBefore = strategyManager.nonces(depositor);
    uint256 initialShares = strategyManager.stakerStrategyShares(depositor, dummyStrat);    
    
    // Create the exact same digest that StrategyManager will verify
    bytes32 structHash = keccak256(
        abi.encode(
            // Make sure this matches StrategyManager's DEPOSIT_TYPEHASH exactly
            keccak256("Deposit(address staker,address strategy,address token,uint256 amount,uint256 nonce,uint256 expiry)"),
            depositor,
            address(dummyStrat),
            address(dummyToken),
            amountToDeposit,
            nonceBefore,
            expirys
        )
    );
    
    bytes32 domainSeparator = strategyManager.domainSeparator();
    bytes32 digestHash = keccak256(
        abi.encodePacked("\x19\x01", domainSeparator, structHash)
    );

    (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digestHash);

   // bytes memory signature = wallet.generateSignature(digestHash);
    bytes memory signature = abi.encodePacked(r, s, v);

    //       vm.prank(depositor);
    MockERC20(address(dummyToken)).mint(address(depositor), amount);
    
    dummyToken.approve(address(strategyManager), amount);
    // Encode hook data
    // Encode hookData with the strategy, depositer, expiry, and signature
    bytes memory hookData = abi.encode(dummyStrat, depositor, expirys, signature);
   

    // Perform swap
    BalanceDelta swapDelta = swap(
        key,
        zeroForOne,
        amountSpecified,
        hookData
    );

    // Verify results
    assertEq(
        int256(swapDelta.amount0()), 
        amountSpecified, 
        "Swap amount for token0 should match specified amount"
    );

    uint256 newShares = strategyManager.stakerStrategyShares(depositor, dummyStrat);
    assertGt(newShares, initialShares, "No shares were minted");
    assertEq(
        strategyManager.nonces(depositor),
        nonceBefore + 1,
        "Nonce not incremented"
    );
}





function testBasicDepositWithSignature() public {
    uint256 amount = 1e18;
    bool zeroForOne = true;
    int256 amountSpecified = -int256(amount);
    uint256 expirys = block.timestamp + 1 days;

    // Get initial states
    uint256 nonceBefore = strategyManager.nonces(depositor);
    
    // Create the exact digest that StrategyManager expects
    bytes32 DEPOSIT_TYPEHASH = keccak256(
        "Deposit(address staker,address strategy,address token,uint256 amount,uint256 nonce,uint256 expiry)"
    );

    bytes32 structHash = keccak256(
        abi.encode(
            DEPOSIT_TYPEHASH,
            depositor,
            address(dummyStrat),
            address(dummyToken),
            amount,
            nonceBefore,
            expirys
        )
    );

    // Get domain separator from contract
    bytes32 domainSeparator = strategyManager.domainSeparator();
    
    // Create digest according to EIP-712
    bytes32 digestHash = keccak256(
        abi.encodePacked(
            "\x19\x01",
            domainSeparator,
            structHash
        )
    );

    // Sign the digest with the depositor's private key
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digestHash);
    bytes memory signature = abi.encodePacked(r, s, v);

    // Setup token balances and approvals
    vm.prank(depositor);
    MockERC20(address(dummyToken)).mint(address(depositor), amount);
    
    vm.prank(depositor);
    dummyToken.approve(address(strategyManager), amount);

    // Encode hook data
    bytes memory hookData = abi.encode(
        dummyStrat,
        depositor,
        expirys,
        signature
    );

    // Perform swap
    BalanceDelta swapDelta = swap(
        key,
        zeroForOne,
        amountSpecified,
        hookData
    );

    // Verify results
    assertEq(
        int256(swapDelta.amount0()), 
        amountSpecified, 
        "Swap amount for token0 should match specified amount"
    );

    uint256 newShares = strategyManager.stakerStrategyShares(depositor, dummyStrat);
    assertGt(newShares, 0, "No shares were minted");
}



   
}

contract StrategyManagerUnitTests_initialize is StrategyManagerUnitTests {
    function test_CannotReinitialize() public {
        cheats.expectRevert("Initializable: contract is already initialized");
        strategyManager.initialize(initialOwner, initialOwner, pauserRegistry, 0);
    }

    function test_InitializedStorageProperly() public {
        assertEq(strategyManager.owner(), initialOwner, "strategyManager.owner() != initialOwner");
        assertEq(
            strategyManager.strategyWhitelister(),
            initialOwner,
            "strategyManager.strategyWhitelister() != initialOwner"
        );
        assertEq(
            address(strategyManager.pauserRegistry()),
            address(pauserRegistry),
            "strategyManager.pauserRegistry() != pauserRegistry"
        );
    }

    
}



contract StrategyManagerUnitTests_depositIntoStrategyWithSignature is StrategyManagerUnitTests {
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

    function testFuzz_DepositSuccessfully10(uint256 amount, uint256 expiry) public {
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
   
}





