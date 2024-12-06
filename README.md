
###  EigenDock🦄


EigenDock is a smart contract protocol that seamlessly integrates Uniswap v4 with EigenLayer, enabling automated cross-chain LST (Liquid Staking Token) deposits and staking. The protocol leverages Uniswap v4 Hooks and Chainlink CCIP for a streamlined cross-chain staking experience.




### Architecture/Key Components

 **SwapAndRestakeEigenRouter**


 1. Manages Uniswap v4 swaps
 
2. Handles direct deposits into EigenLayer strategies

3. Enforces specific pool requirements

4. Manages token-to-strategy mappings



 


 
  **UniStakeV1 Hook**
  

1. Implements Uniswap v4 Hook interface

2. Manages cross-chain bridging via CCIP

3.Handles post-swap operations

4.Processes bridge transactions





### Key Features

1. Unified Swap & Stake
Single-transaction swaps and deposits
Automatic strategy integration
Configurable deposit settings



2. Cross-Chain Capabilities
CCIP-powered token bridging
Native and LINK fee support
Secure message passing



3. Flexible Strategy Management
Dynamic token-to-strategy mapping
Support for multiple LSTs
Automated share calculation

 
   



### User Flow

**Local Staking Flow**


1. User initiates swap with depositTokens: true

2. Swap executes through Uniswap v4

3. Output tokens automatically deposited into EigenLayer

4. User receives strategy shares






**Cross-Chain Staking Flow**


1. User initiates swap with isBridgeTx: true

2. Swap executes through Uniswap v4

3. Hook captures output tokens

4. Tokens bridged via CCIP to destination chain

5. User receives tokens on target chain




      






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

