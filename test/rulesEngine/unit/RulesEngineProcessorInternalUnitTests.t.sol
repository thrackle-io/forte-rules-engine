// /// SPDX-License-Identifier: UNLICENSED
// pragma solidity ^0.8.24;

// import "lib/forge-std/src/Test.sol";
// import "src/engine/facets/RulesEngineProcessorFacet.sol";

// contract RulesEngineUnitTestsCommon is Test, RulesEngineProcessorFacet {


//   function testRulesEngine_Unit_RetrieveRawStringFromInstructionSet()
//         public
//         ifDeploymentTestsEnabled
//         endWithStopPrank
//     {
//         uint256 ruleId = setupRuleWithStringComparison();
//         StringVerificationStruct memory retVal = RulesEngineProcessorFacet(address(red)).retrieveRawStringFromInstructionSet(1, ruleId, 3);
//         console2.log(retVal.instructionSetValue);
//         console2.log(retVal.rawData);
//         assertEq(
//             retVal.instructionSetValue,
//             uint256(keccak256(abi.encode(retVal.rawData)))
//         );
//     }

//      function testRulesEngine_Unit_RetrieveRawStringFromInstructionSet()
//         public
//         ifDeploymentTestsEnabled
//         endWithStopPrank
//     {
//         uint256 ruleId = setupRuleWithStringComparison();
//         StringVerificationStruct memory retVal = RulesEngineProcessorFacet(address(red)).retrieveRawStringFromInstructionSet(1, ruleId, 3);
//         console2.log(retVal.instructionSetValue);
//         console2.log(retVal.rawData);
//         assertEq(
//             retVal.instructionSetValue,
//             uint256(keccak256(abi.encode(retVal.rawData)))
//         );
//     }

// }