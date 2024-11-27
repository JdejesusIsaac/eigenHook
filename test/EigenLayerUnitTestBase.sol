// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/proxy/transparent/ProxyAdmin.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "../src/EigenLayer/PauserRegistry.sol";
import "forge-std/Test.sol";

abstract contract EigenLayerUnitTestBase is Test {
    Vm cheats = Vm(VM_ADDRESS);

    PauserRegistry public pauserRegistry;
    ProxyAdmin public eigenLayerProxyAdmin;

    mapping(address => bool) public addressIsExcludedFromFuzzedInputs;

    address public constant pauser = address(555);
    address public constant unpauser = address(556);

    // Helper Functions/Modifiers
    modifier filterFuzzedAddressInputs(address fuzzedAddress) {
        cheats.assume(!addressIsExcludedFromFuzzedInputs[fuzzedAddress]);
        _;
    }

    function setUp() public virtual {
        address[] memory pausers = new address[](1);
        pausers[0] = pauser;
        pauserRegistry = new PauserRegistry(pausers, unpauser);
        eigenLayerProxyAdmin = new ProxyAdmin(msg.sender);

        addressIsExcludedFromFuzzedInputs[address(pauserRegistry)] = true;
        addressIsExcludedFromFuzzedInputs[address(eigenLayerProxyAdmin)] = true;
    }
}