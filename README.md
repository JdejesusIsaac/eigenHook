
### ** DelegateToHook 🦄**



1. The example hook [Counter.sol](src/Counter.sol) demonstrates the `beforeSwap()` and `afterSwap()` hooks
2. The test template [Counter.t.sol](test/Counter.t.sol) preconfigures the v4 pool manager, test tokens, and test liquidity.

<details>
<summary>Updating to v4-template:latest</summary>

The delegateToHook project is a smart contract designed to integrate with Uniswap v4 hooks, facilitating the automatic deposit of stETH into a strategy and delegating staked assets to operators within the EigenLayer ecosystem. This contract aims to streamline the process of managing stETH assets by automating key operations post-swap.




</details>

---
### Features
* after a swap.
* Delegation: Allows users to delegate staked assets to operators using a signature-based authorization.
* Event Emission: Emits events to track deposits and delegations.



### Key Components
* DelegationManager: Manages the delegation of staked assets.
* StrategyManager: Handles deposits into various strategies.
* STETH: Utilizes a hardcoded address for the stETH token.



### Contract Functions

afterSwap()
* Triggered after a swap operation.
* Calls depositStETHIntoStrategy to deposit stETH into a strategy.
* Returns the function selector and output amount.


depositStETHIntoStrategy()
* Deposits stETH into a specified strategy.
* Calculates the output amount based on swap direction.
* Approves and deposits the output token into the strategy.
* Emits a Deposited event.


delegateToOperator()
* Delegates staked assets to a specified operator.
* Requires the operator's address, a signature, expiry, and a salt value.
* Constructs a SignatureWithExpiry structure to authorize the delegation.
* Utilizes the DelegationManager to finalize the delegation process.


### User Flow

1. Swap Execution:
    * Users initiate a swap on Uniswap v4.
    * If the swap involves ETH to stETH, the afterSwap hook is triggered.
      
2. Deposit into Strategy:
    * The afterSwap function calls depositStETHIntoStrategy.
    * The contract calculates the amount of stETH received and deposits it into a strategy using the StrategyManager.
    * A Deposited event is emitted to log the transaction details.
      
3. Delegation to Operator:
    * Users can call delegateToOperator to delegate their staked assets.
    * This requires providing the necessary authorization details, including a valid signature.





### Check Forge Installation
*Ensure that you have correctly installed Foundry (Forge) and that it's up to date. You can update Foundry by running:*

```
foundryup
```

## Set up

*requires [foundry](https://book.getfoundry.sh)*

```
forge install
forge test
```

### Local Development (Anvil)

Other than writing unit tests (recommended!), you can only deploy & test hooks on [anvil](https://book.getfoundry.sh/anvil/)

```bash
# start anvil, a local EVM chain
anvil

# in a new terminal
forge script script/Anvil.s.sol \
    --rpc-url http://localhost:8545 \
    --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
    --broadcast
```

See [script/](script/) for hook deployment, pool creation, liquidity provision, and swapping.

---

<details>
<summary><h2>Troubleshooting</h2></summary>



### *Permission Denied*

When installing dependencies with `forge install`, Github may throw a `Permission Denied` error

Typically caused by missing Github SSH keys, and can be resolved by following the steps [here](https://docs.github.com/en/github/authenticating-to-github/connecting-to-github-with-ssh) 

Or [adding the keys to your ssh-agent](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent#adding-your-ssh-key-to-the-ssh-agent), if you have already uploaded SSH keys

### Hook deployment failures

Hook deployment failures are caused by incorrect flags or incorrect salt mining

1. Verify the flags are in agreement:
    * `getHookCalls()` returns the correct flags
    * `flags` provided to `HookMiner.find(...)`
2. Verify salt mining is correct:
    * In **forge test**: the *deployer* for: `new Hook{salt: salt}(...)` and `HookMiner.find(deployer, ...)` are the same. This will be `address(this)`. If using `vm.prank`, the deployer will be the pranking address
    * In **forge script**: the deployer must be the CREATE2 Proxy: `0x4e59b44847b379578588920cA78FbF26c0B4956C`
        * If anvil does not have the CREATE2 deployer, your foundry may be out of date. You can update it with `foundryup`

</details>

---

Additional resources:

[Uniswap v4 docs](https://docs.uniswap.org/contracts/v4/overview)

[v4-periphery](https://github.com/uniswap/v4-periphery) contains advanced hook implementations that serve as a great reference

[v4-core](https://github.com/uniswap/v4-core)

[v4-by-example](https://v4-by-example.org)

