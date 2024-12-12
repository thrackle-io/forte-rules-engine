pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

contract BasicBatchTest is RulesEngineCommon {

    function setUp() public {
        red = _createRulesEngineDiamond(address(this));
    }

    function test_basicBatching() public {
        bytes[] memory calls = new bytes[](3);

        bytes[] memory blankSignatures = new bytes[](0);
        uint256[] memory blankFunctionSignatureIds = new uint256[](0);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        calls[0] = abi.encodeWithSelector(RulesEngineDataFacet.updatePolicy.selector, 0, blankSignatures, blankFunctionSignatureIds, blankRuleIds);
        address _address = address(22);
        PT[] memory fcArgs = new PT[](1);
        fcArgs[0] = PT.UINT;
        calls[1] = abi.encodeWithSelector(RulesEngineDataFacet.updateForeignCall.selector, 1, _address, "simpleCheck(uint256)", PT.UINT, fcArgs);
        calls[2] = abi.encodeWithSelector(RulesEngineDataFacet.updatePolicy.selector, 0, blankSignatures, blankFunctionSignatureIds, blankRuleIds);
        RulesEngineDiamond(red).batch(calls, true);
    }
}