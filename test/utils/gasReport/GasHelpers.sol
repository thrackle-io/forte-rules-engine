/// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

contract GasHelpers {
    string private checkpointLabel;
    uint256 private checkpointGasLeft = 1; // Start the slot warm.

    event Gas_Log(string _label, uint256 _gasDelta);

    function startMeasuringGas(string memory label) internal virtual {
        checkpointLabel = label;

        checkpointGasLeft = gasleft();
    }

    function stopMeasuringGas() internal virtual returns(uint256){
        uint256 checkpointGasLeft2 = gasleft();

        // Subtract 100 to account for the warm SLOAD in startMeasuringGas.
        uint256 gasDelta = checkpointGasLeft - checkpointGasLeft2 - 100;

        emit Gas_Log(string(abi.encodePacked(checkpointLabel, " Gas")), gasDelta);
        return gasDelta;
    }
}
