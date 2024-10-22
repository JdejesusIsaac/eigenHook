// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@chainlink/contracts/src/v0.8/shared/interfaces/AggregatorV3Interface.sol";

interface IUniswapV3Factory {
    event PoolCreated(address indexed token0, address indexed token1, uint24 indexed fee, int24 tickSpacing, address pool);
}

interface IERC721Receiver {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4);
}

contract UniswapV3LiquidityBase is IERC721Receiver {

    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant WSTETH = 0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0;
    address constant STETH = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;

    AggregatorV3Interface internal ethUsdPriceFeed;

    IERC20 private constant steth = IERC20(STETH);
    IWETH private constant weth = IWETH(WETH);
   IwStEth private constant wsteth = IwStEth(WSTETH);
   IERC20 private constant Wsteth = IERC20(WSTETH);

    struct StakingPosition {
        uint256 ethDeposited;
        uint256 stETHSharesReceived;
        uint256 lastUpdateTimestamp;
        uint256 lastKnownEthPrice;
    }

    mapping(address => StakingPosition) public stakingPositions;
    
    event Staked(address indexed user, uint256 amountETH, uint256 stETHShares, uint256 ethPrice, uint256 balance);
    event LiquidityProvided(address indexed user, uint256 tokenId, uint128 liquidity, uint256 amountETH, uint256 amountstETH);
    event PositionUpdated(address indexed user, uint256 stakingYield, uint256 lpYield);

    int24 private constant TICK_SPACING = 1;
    int24 private constant MIN_TICK = 1612; // Adjusted narrow range
    int24 private constant MAX_TICK = 1712;

    INonfungiblePositionManager public nonfungiblePositionManager = INonfungiblePositionManager(0xC36442b4a4522E871399CD717aBDD847Ab11FE88); // Mainnet address

    constructor(address _ethPriceFeed) {
        ethUsdPriceFeed = AggregatorV3Interface(_ethPriceFeed);
    }

    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }
    


    function getCurrentEthPrice() public view returns (uint256) {
        (, int256 price, , , ) = ethUsdPriceFeed.latestRoundData();
        return uint256(price);
    }

    // wrap eth
    function wrapEth(uint256 _amount) external {
        weth.deposit{value: _amount}();
        //approve address(this) to spend weth
        
        weth.approve(address(nonfungiblePositionManager), _amount);
        
    }

    function calculateYield(address user) external view returns (uint256) {
    StakingPosition memory position = stakingPositions[user];
    uint256 currentStethRate = ILido(STETH).getPooledEthByShares(position.stETHSharesReceived);
    uint256 currentEthValue = position.stETHSharesReceived * currentStethRate / 1 ether;
    
    // Calculate yield as the difference between current and initial ETH value
    return currentEthValue - position.ethDeposited;
}

function calculateStakingYieldInStETH(address user) public view returns (uint256) {
    StakingPosition memory position = stakingPositions[user];
    uint256 userShares = ILido(STETH).sharesOf(user);
    uint256 initialShares = position.ethDeposited; // Track this when they first stake

    // Yield in shares
    return userShares - initialShares;
}


 


    function stakeETH(uint256 _amount) external payable {
        require(msg.value > 0, "You must send ETH to stake.");

        // Track stETH shares before the deposit
        uint256 stETHSharesBefore = ILido(STETH).sharesOf(address(this));
         uint256 balanceBefore = IERC20(steth).balanceOf(address(this));

        // Submit ETH to Lido and receive stETH
        ILido(STETH).submit{value: _amount}(address(this));
        IERC20(steth).approve(address(wsteth), _amount);
        IERC20(steth).approve(address(nonfungiblePositionManager), _amount);
       

        // Calculate the number of stETH shares received from this deposit
    uint256 stETHSharesAfter = ILido(STETH).sharesOf(address(this));
    uint256 stETHShares = stETHSharesAfter - stETHSharesBefore;
    uint256 ethPrice = getCurrentEthPrice();

    // Cache the user's staking position in memory to reduce redundant storage access
    StakingPosition storage position = stakingPositions[msg.sender];


    // Update the user's staking position
    position.ethDeposited += msg.value;
    position.stETHSharesReceived += stETHShares;
    position.lastUpdateTimestamp = block.timestamp;
    position.lastKnownEthPrice = ethPrice;


    uint256 balance = IERC20(steth).balanceOf(address(this)) - balanceBefore;

        // Emit the Staked event
        emit Staked(msg.sender, msg.value, stETHShares, ethPrice, balance);

        // Emit the PositionUpdated event
        


    }


    //*** @notice Converts stETH to wstETH
    function wrapStEth(uint256 _stEthAmount) external returns (uint256) {
        
       uint256 deposit = wsteth.wrap(_stEthAmount);
      // wsteth.approve(address(this), deposit);
         //wsteth.approve(address(nonfungiblePositionManager), deposit);
     // IERC20(WSTETH).transferFrom(address(msg.sender), address(nonfungiblePositionManager), deposit);


           
        return deposit;
       
    }
    // Helper functions
    function StETHRate(uint256 amount) internal pure returns (uint256) {
        return amount / 1001 * 1000;
    }

    function WstETHRate(uint256 amount) internal view returns (uint256) {
        return amount * wsteth.tokensPerStEth() / 1e18;
    }

    
    





       
        

    // mintNewPosition for steth and weth
    function mintNewPositionWsteth(uint256 amount0ToAdd, uint256 amount1ToAdd)
        external
        returns (
            uint256 tokenId,
            uint128 liquidity,
            uint256 amount0,
            uint256 amount1
        )
    {
        weth.transferFrom(msg.sender, address(this), amount1ToAdd);
        Wsteth.transferFrom(msg.sender, address(this), amount0ToAdd);

        weth.approve(address(nonfungiblePositionManager), amount1ToAdd);
        Wsteth.approve(address(nonfungiblePositionManager), amount0ToAdd);

        INonfungiblePositionManager.MintParams memory params =
            INonfungiblePositionManager.MintParams({
                token0: WSTETH,
                token1: WETH,
                fee: 100,
                tickLower: MIN_TICK,
                tickUpper: MAX_TICK,
                amount0Desired: amount0ToAdd,
                amount1Desired: amount1ToAdd,
                amount0Min: 0,
                amount1Min: 0,
                recipient: address(this),
                deadline: block.timestamp
            });

        (tokenId, liquidity, amount0, amount1) = nonfungiblePositionManager.mint(params);

        if (amount1 < amount1ToAdd) {
            weth.approve(address(nonfungiblePositionManager), 0);
            uint256 refund1 = amount1ToAdd - amount1;
            weth.transfer(msg.sender, refund1);
        }

        if (amount0 < amount0ToAdd) {
            Wsteth.approve(address(nonfungiblePositionManager), 0);
            uint256 refund0 = amount0ToAdd - amount0;
            Wsteth.transfer(msg.sender, refund0);
        }

        emit LiquidityProvided(msg.sender, tokenId, liquidity, amount1ToAdd, amount0ToAdd);
    }

    function collectAllFees(uint256 tokenId) external returns (uint256 amount0, uint256 amount1) {
        INonfungiblePositionManager.CollectParams memory params =
            INonfungiblePositionManager.CollectParams({
                tokenId: tokenId,
                recipient: address(this),
                amount0Max: type(uint128).max,
                amount1Max: type(uint128).max
            });

        (amount0, amount1) = nonfungiblePositionManager.collect(params);
    }

    function increaseLiquidityCurrentRange(uint256 tokenId, uint256 amount0ToAdd, uint256 amount1ToAdd)
        external
        returns (uint128 liquidity, uint256 amount0, uint256 amount1)
    {
        weth.transferFrom(msg.sender, address(this), amount1ToAdd);
        Wsteth.transferFrom(msg.sender, address(this), amount0ToAdd);

        weth.approve(address(nonfungiblePositionManager), amount1ToAdd);
        Wsteth.approve(address(nonfungiblePositionManager), amount0ToAdd);

        INonfungiblePositionManager.IncreaseLiquidityParams memory params =
            INonfungiblePositionManager.IncreaseLiquidityParams({
                tokenId: tokenId,
                amount0Desired: amount0ToAdd,
                amount1Desired: amount1ToAdd,
                amount0Min: 0,
                amount1Min: 0,
                deadline: block.timestamp
            });

        (liquidity, amount0, amount1) = nonfungiblePositionManager.increaseLiquidity(params);
    }

    function decreaseLiquidityCurrentRange(uint256 tokenId, uint128 liquidity)
        external
        returns (uint256 amount0, uint256 amount1)
    {
        INonfungiblePositionManager.DecreaseLiquidityParams memory params =
            INonfungiblePositionManager.DecreaseLiquidityParams({
                tokenId: tokenId,
                liquidity: liquidity,
                amount0Min: 0,
                amount1Min: 0,
                deadline: block.timestamp
            });

        (amount0, amount1) = nonfungiblePositionManager.decreaseLiquidity(params);
    }

    // view stakingPositions
    function viewStakingPosition(address user) external view returns (StakingPosition memory) {
        return stakingPositions[user];
    }

// sends message to L2
     function sendStakeMessageL1() external payable {
    StakingPosition storage position = stakingPositions[msg.sender];
    bytes memory data = abi.encodeWithSignature(
        "stakeETH(address,uint256,uint256,uint256)",
        msg.sender,
        position.ethDeposited,
        position.stETHSharesReceived,
        position.lastKnownEthPrice
    );
  // IL1ScrollMessenger(scrollL1Messenger).sendMessage{value: msg.value}(
  //      address(this), msg.value, data, GAS_LIMIT
   // );
}



    

    // send message to L2

       function sendMessageToL2(bytes calldata _data) external payable {
    // Assuming IL2ScrollMessenger is set up in your environment
  //  IL2ScrollMessenger(scrollL2Messenger).sendMessage{value: msg.value}(
  //      address(this), msg.value, _data, GAS_LIMIT
  //  );
}
}

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
        returns (uint256 tokenId, uint128 liquidity, uint256 amount0, uint256 amount1);

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

    function collect(CollectParams calldata params) external payable returns (uint256 amount0, uint256 amount1);
}

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
}

interface IwStEth {
    function unwrap(uint256 _stEthAmount) external returns (uint256);
    function wrap(uint256 _ethAmount) external returns (uint256);
    function increaseAllowance(address spender, uint256 addedValue) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
     function tokensPerStEth() external view returns (uint256);
}

interface ILido {
    function submit(address _referral) external payable returns (uint256);
    function sharesOf(address _owner) external view returns (uint256);
    function getPooledEthByShares(uint256 _sharesAmount) external view returns (uint256);
}

interface IWETH is IERC20 {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
}