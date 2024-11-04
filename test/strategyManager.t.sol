// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;


import "forge-std/Test.sol";

import {StrategyManagerMock} from "../test/mocks/StrategyManagerMock.sol";
import {StrategyBaseMock} from "../test/mocks/StrategyBaseMock.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
// OPEN ZEPPLELIN mock ERC20 token

// Minimal ERC20 Mock for testing purposes
interface IWETH is IERC20 {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
}


contract strategyMangerTest is Test {

   StrategyManagerMock strategyManager;
    StrategyBaseMock strategy;
     address private constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2; 
     uint256 private mainnetFork;
    address staker;
     IWETH private constant weth = IWETH(WETH);

    function setUp() public {

        // Deploy the mock ERC20 token
       // token = new MockERC20();

         mainnetFork = vm.createSelectFork("https://eth-mainnet.g.alchemy.com/v2/czjGR6KFDr37NScDmUR7bY8u-aiB-OzF");
      strategyManager = new StrategyManagerMock(weth);

        // Mint tokens to the staker address
        vm.deal(address(this), 30 ether);
        staker = address(this);
        
        // Deposit ETH to WETH to get test WETH tokens
        weth.deposit{value: 10 * 1e18}();

        // Approve the strategy manager to spend staker's WETH
        weth.approve(address(strategyManager), 10 * 1e18);
        
        // Confirm approval
        uint256 allowance = weth.allowance(staker, address(strategyManager));
        console.log("Allowance for StrategyManagerMock:", allowance);
        assertEq(allowance, 10 * 1e18, "Allowance mismatch");
    }

    function testDepositToStrategy() public {
        // Deposit WETH to the strategy manager
        strategyManager.depositToStrategy(staker, weth, 1 * 1e18);
        
        // Check the staker's shares in the strategy
        uint256 shares = strategyManager.stakerShares(staker);
        console.log("Staker shares in the strategy:", shares);
        assertEq(shares, 1 * 1e18, "Shares mismatch");
    }

   
      
}