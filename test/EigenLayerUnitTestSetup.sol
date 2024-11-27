// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;


import "../test/EigenLayerMocks/StrategyManagerMock.sol";
import "../test/EigenLayerMocks/DelegationManagerMock.sol";
import "../test/EigenLayerMocks/SlasherMock.sol";
import "../test/EigenLayerMocks/EigenPodManagerMock.sol";
import "../test/EigenLayerUnitTestBase.sol";

abstract contract EigenLayerUnitTestSetup is EigenLayerUnitTestBase {
    // Declare Mocks
    StrategyManagerMock public strategyManagerMock;
    DelegationManagerMock public delegationManagerMock;
    SlasherMock public slasherMock;
    EigenPodManagerMock public eigenPodManagerMock;

    function setUp() public virtual override {
        EigenLayerUnitTestBase.setUp();
        strategyManagerMock = new StrategyManagerMock();
        delegationManagerMock = new DelegationManagerMock();
        slasherMock = new SlasherMock();
        eigenPodManagerMock = new EigenPodManagerMock(pauserRegistry);

        addressIsExcludedFromFuzzedInputs[address(0)] = true;
        addressIsExcludedFromFuzzedInputs[address(strategyManagerMock)] = true;
        addressIsExcludedFromFuzzedInputs[address(delegationManagerMock)] = true;
        addressIsExcludedFromFuzzedInputs[address(slasherMock)] = true;
        addressIsExcludedFromFuzzedInputs[address(eigenPodManagerMock)] = true;
    }
}