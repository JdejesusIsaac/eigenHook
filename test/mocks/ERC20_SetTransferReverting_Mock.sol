// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.24;

import "./ERC20PresetFixedSupply.sol";

contract ERC20_SetTransferReverting_Mock is ERC20PresetFixedSupply {

    bool public transfersRevert;

    constructor(uint256 initSupply, address initOwner) 
        ERC20PresetFixedSupply("ERC20_SetTransferReverting_Mock", "ERC20_SetTransferReverting_Mock", initSupply, initOwner)
        {}

    function setTransfersRevert(bool _transfersRevert) public {
        transfersRevert = _transfersRevert;
    }

    function _beforeTokenTransfer(address, address, uint256) internal view {
        if (transfersRevert) {
            // revert without message
            revert();
            // revert("ERC20_SetTransferReverting_Mock._beforeTokenTransfer: transfersRevert set");
        }
    }

}