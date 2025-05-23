pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "src/engine/facets/RulesEngineComponentFacet.sol";

contract BasicBatchTest is RulesEngineCommon {

    function setUp() public {
        red = _createRulesEngineDiamond(address(this));
    }

    function test_basicBatching() public {
        bytes[] memory calls = new bytes[](3);

        FunctionSignatureStorageSet[] memory blankSignatureSets = new FunctionSignatureStorageSet[](0);
        bytes4[] memory blankSignatures = new bytes4[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        Rule[] memory blankRules = new Rule[](0);
        calls[0] = abi.encodeWithSelector(RulesEnginePolicyFacet.createPolicy.selector, blankSignatureSets, blankRules, PolicyType.CLOSED_POLICY);
        address _address = address(22);
        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        uint8[] memory typeSpecificIndices = new uint8[](1);
        typeSpecificIndices[0] = 1;
        ForeignCall memory fc;
        fc.typeSpecificIndices = typeSpecificIndices;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = _address;
        fc.signature = bytes4(keccak256(bytes("simpleCheck(uint256)")));
        fc.returnType = PT.UINT;
        fc.foreignCallIndex = 1;
        calls[1] = abi.encodeWithSelector(RulesEngineComponentFacet.createForeignCall.selector, 1, fc, "simpleCheck(uint256)");
        calls[2] = abi.encodeWithSelector(RulesEnginePolicyFacet.updatePolicy.selector, 1, blankSignatures, blankFunctionSignatureIds, blankRuleIds, PolicyType.CLOSED_POLICY);
        RulesEngineDiamond(red).batch(calls, true);
    }
}
