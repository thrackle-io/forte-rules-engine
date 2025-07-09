/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "src/engine/facets/RulesEngineComponentFacet.sol";
import "src/engine/facets/RulesEngineForeignCallFacet.sol";

contract BasicBatchTest is RulesEngineCommon {
    function setUp() public {
        red = createRulesEngineDiamond(address(this));
    }

    function test_basicBatching() public {
        bytes[] memory calls = new bytes[](3);

        bytes4[] memory blankCallingFunctions = new bytes4[](0);
        uint256[] memory blankCallingFunctionIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        calls[0] = abi.encodeWithSelector(RulesEnginePolicyFacet.createPolicy.selector, PolicyType.CLOSED_POLICY);
        address _address = address(22);
        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.UINT;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 1;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = _address;
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 1;
        calls[1] = abi.encodeWithSelector(RulesEngineForeignCallFacet.createForeignCall.selector, 1, fc, "simpleCheck(uint256)");
        calls[2] = abi.encodeWithSelector(
            RulesEnginePolicyFacet.updatePolicy.selector,
            1,
            blankCallingFunctions,
            blankCallingFunctionIds,
            blankRuleIds,
            PolicyType.CLOSED_POLICY
        );
        RulesEngineDiamond(red).batch(calls, true);
    }
}
