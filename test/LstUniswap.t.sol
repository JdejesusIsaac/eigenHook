// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Test, console2} from "forge-std/Test.sol";
import {UniswapV3LiquidityBase} from "../src/LstUniswap.sol";

interface INonfungiblePositionManager {
    struct MintParams {
        address token0;
        address token1;
        uint24 fee;
        int24 tickLower;
        int24 tickUpper;
        uint256 amount0Desired;
        uint256 amount1Desired;
        uint256 amount0Min;
        uint256 amount1Min;
        address recipient;
        uint256 deadline;
    }

    function mint(MintParams calldata params)
        external
        payable
        returns (
            uint256 tokenId,
            uint128 liquidity,
            uint256 amount0,
            uint256 amount1
        );

    struct IncreaseLiquidityParams {
        uint256 tokenId;
        uint256 amount0Desired;
        uint256 amount1Desired;
        uint256 amount0Min;
        uint256 amount1Min;
        uint256 deadline;
    }

    function increaseLiquidity(IncreaseLiquidityParams calldata params)
        external
        payable
        returns (uint128 liquidity, uint256 amount0, uint256 amount1);

    struct DecreaseLiquidityParams {
        uint256 tokenId;
        uint128 liquidity;
        uint256 amount0Min;
        uint256 amount1Min;
        uint256 deadline;
    }

    function decreaseLiquidity(DecreaseLiquidityParams calldata params)
        external
        payable
        returns (uint256 amount0, uint256 amount1);

    struct CollectParams {
        uint256 tokenId;
        address recipient;
        uint128 amount0Max;
        uint128 amount1Max;
    }

    function collect(CollectParams calldata params)
        external
        payable
        returns (uint256 amount0, uint256 amount1);
}

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount)
        external
        returns (bool);
    function allowance(address owner, address spender)
        external
        view
        returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount)
        external
        returns (bool);
}

interface IWETH is IERC20 {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
}

interface ILido {
    function submit(address _referral) external payable returns (uint256);
    function sharesOf(address _owner) external view returns (uint256);
    function getPooledEthByShares(uint256 _sharesAmount) external view returns (uint256);
}

interface IwStEth {
    function unwrap(uint256 _stEthAmount) external returns (uint256);
    function wrap(uint256 _ethAmount) external returns (uint256);
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function tokensPerStEth() external view returns (uint256);



    


    

}

contract uniswapBaseTest is Test {
 INonfungiblePositionManager public nonfungiblePositionManager = INonfungiblePositionManager(0xC36442b4a4522E871399CD717aBDD847Ab11FE88);
   
    address private ethPriceFeed = 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;

     address private constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2; 
      address private constant STETH = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;

     address constant WSTETH = 0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0;
      UniswapV3LiquidityBase private uni = new UniswapV3LiquidityBase(ethPriceFeed);
      IERC20 private constant steth = IERC20(STETH);

        IWETH private constant weth = IWETH(WETH);
        IwStEth private constant wsteth = IwStEth(WSTETH);

         address stethWhale = 0xfFEFA70B6DEaAb975ef15A6474ce9C4214d82B02;
    //0x41318419CFa25396b47A94896FfA2C77c6434040; // Example whale address
    uint256 private mainnetFork;

     

 


     function setUp() public {
         uni = new UniswapV3LiquidityBase(ethPriceFeed );
           mainnetFork = vm.createSelectFork("wwww.alchemyapi.io");

            vm.deal(address(this), 30 ether);

   // submit 10 ether to lido
        ILido(STETH).submit{value: 10 * 1e18}(address(this));
        // approve stETH to be unwrapped
       steth.approve(WSTETH, 10 * 1e18);
       //wrap steth
       IwStEth(WSTETH).wrap(10 * 1e18);

       IwStEth(WSTETH).approve(address(uni), 10 * 1e18);

        weth.deposit{value: 10 * 1e18}();
  
   weth.approve(address(uni), 10 * 1e18);

    


    }

    



  

function testStakeEth() public {
    vm.deal(address(this), 30 ether);
    uint256 amount = 10 * 1e18; // Define how much ETH to stake
    // Call stakeETH() and send the specified amount of ETH
    uni.stakeETH{value: amount}(amount);


    // View the staking position for the current contract address
    uni.viewStakingPosition(address(this));
   // testcalculateStakingYieldInStETH(address(this));

   

    // Optionally, add assertions to verify the staking position
    // For example:
    // assert(position.ethDeposited == amount);
    // assert(position.stETHSharesReceived > 0);
    // assert(position.lastUpdateTimestamp > 0);
    // assert(position.lastKnownEthPrice > 0);
}

// test calculateYield
   // function calculateYield(address user) external view returns (uint256)
function testCalculateYield() public view {
    address user = address(0xfFEFA70B6DEaAb975ef15A6474ce9C4214d82B02); // Define the user address
    // Call calculateYield() and store the result
    uint256 yield = uni.calculateYield(user);
    console2.log("yield", yield);

}
function testcalculateStakingYieldInStETH() public view {
    address user = address(0xfFEFA70B6DEaAb975ef15A6474ce9C4214d82B02);
    // Call calculateStakingYieldInStETH() and store the result
    uint256 yield = uni.calculateStakingYieldInStETH(user);
    console2.log("yield", yield / 1e18);
}
    // Optionally, add assertions to verify the yield
    // For example:
    // assert(yield > 0);


// test wrapStEth function wrapStEth(uint256 _stEthAmount) external returns (uint256)
function testwrapStEth() public {

    testStakeEth();
    // prank as address(this) is the staker
    
  
    uint256 stEthAmount = 10 * 1e18; 
    // Define how much stETH to wrap
    // Call wrapStEth() and send the specified amount of stETH
    uni.wrapStEth(stEthAmount);

     

    // View the staking position for the current contract address
    //uni.viewStakingPosition(address(this));

    // Optionally, add assertions to verify the staking position
    // For example:
    // assert(position.stEthWrapped == stEthAmount);
    // assert(position.wstEthReceived > 0);
    // assert(position.lastUpdateTimestamp > 0);
    // assert(position.lastKnownEthPrice > 0);
}



function testViewStakingPosition() public view {
   uni.viewStakingPosition(address(this));

}

function WstETHRate(uint256 amount) internal view returns (uint256) {
        return amount * wsteth.tokensPerStEth() / 1e18;
    }











// check StakingPosition struct







     function testLiquidityBase() public {
     

    // Track total liquidity
    uint128 liquidity;

    uint256 wethAmount = 1e18;   //1 * 1e18;      // 10 WETH in wei (18 decimals)
    uint256 wstethAmount = 1e18;// 1 * 1e18;

    (
            uint256 tokenId,
            uint128 liquidityDelta,
            uint256 amount0,
            uint256 amount1
        ) = uni.mintNewPositionWsteth(wethAmount, wstethAmount);
        liquidity += liquidityDelta;

        console2.log("--- Mint new position ---");
        console2.log("token id", tokenId);
        console2.log("liquidity", liquidity);
        console2.log("amount 0", amount0);
        console2.log("amount 1", amount1);
    
    liquidity += liquidityDelta;

    console2.log("--- Mint new position ---");
    console2.log("token id", tokenId);
    console2.log("liquidity", liquidity);
    console2.log("amount 0", amount0);
    console2.log("amount 1", amount1);

    // Collect fees
    (uint256 fee0, uint256 fee1) = uni.collectAllFees(tokenId);

    console2.log("--- Collect fees ---");
    console2.log("fee 0", fee0);
    console2.log("fee 1", fee1);  

   

   

        




     }



}
