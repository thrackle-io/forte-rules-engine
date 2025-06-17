pragma solidity ^0.8.0;

import {RulesEngineClient} from "src/client/RulesEngineClient.sol";
import {IRulesEngine} from "src/client/IRulesEngine.sol";

contract RulesEngine7702ExampleWallet is RulesEngineClient {
    constructor(address _rulesEngine) {
        rulesEngineAddress = _rulesEngine;
    }

    struct Call {
        address to;
        uint256 value;
        bytes data;
    }

    function executeTransaction(Call[] calldata calls) public {
        for (uint256 i = 0; i < calls.length; i++) {
            Call memory _call = calls[i];
            try IRulesEngine(rulesEngineAddress).checkPolicies(_call.data) returns (uint256) {
                (bool success, ) = _call.to.call{value: _call.value}(_call.data);
                require(success, "Transaction failed");
            } catch {
                revert("Transaction failed");
            }
        }
    }
}