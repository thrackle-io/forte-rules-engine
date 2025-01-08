// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "src/client/RulesEngineClient.sol";

/**
 * @title Example contract for testing the Rules Engine
 * @dev This contract provides the ability to test the rules engine with an external contract
 * @author @mpetersoCode55
 */
contract ExampleUserContract is RulesEngineClient {
    /**
     @dev This is a generic function that showcases custom arguments being sent to the Rules Engine
     */
    function transfer(address to, uint256 value) public returns (bool) {
        Arguments memory args;
        args.values = new bytes[](2);
        args.values[0] = abi.encode(address(to));
        args.values[1] = abi.encode(uint256(value));
        args.argumentTypes = new IRulesEngine.PT[](2);
        args.argumentTypes[0] = IRulesEngine.PT.ADDR;
        args.argumentTypes[1] = IRulesEngine.PT.UINT;
        bytes memory encoded = abi.encode(args);
        uint256 retval = _invokeRulesEngine(bytes4(keccak256("transfer(address,uint256)")), encoded);
        if (retval > 0) return true;
    }

}
