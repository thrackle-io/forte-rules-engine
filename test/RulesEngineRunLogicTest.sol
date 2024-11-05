/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "src/RulesEngineRunLogic.sol";
import "src/ExampleUserContract.sol";
import "forge-std/console2.sol";
import "forge-std/StdAssertions.sol";
import "test/ForeignCallTestContract.sol";

/**
 * @title Test the functionality of the RulesEngineRunLogic contract
 * @author @mpetersoCode55 
 */
contract RulesEngineRunLogicTest is StdAssertions {

    RulesEngineRunLogic logic;
    ExampleUserContract userContract;
    ForeignCallTestContract testContract;

    address contractAddress = address(0x1234567);
    string functionSignature = "transfer(address,uint256) returns (bool)";

    function setUp() public{
        logic = new RulesEngineRunLogic();
        userContract = new ExampleUserContract();
        userContract.setRulesEngineAddress(address(logic));
        testContract = new ForeignCallTestContract();
    }

    function setupRuleWithoutForeignCall() public {
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.Rule memory rule;
        // Instruction set: LC.PLH, 1, 0, LC.NUM, 4, LC.GT, 0, 1
        rule.instructionSet = new uint256[](8);
        rule.instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = 0;
        rule.instructionSet[3] = uint(RulesStorageStructure.LC.NUM);
        rule.instructionSet[4] = 4;
        rule.instructionSet[5] = uint(RulesStorageStructure.LC.GT);
        rule.instructionSet[6] = 0;
        rule.instructionSet[7] = 1;
        rule.placeHolders = new RulesStorageStructure.Placeholder[](1);
        rule.placeHolders[0].pType = RulesStorageStructure.PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 0;
        logic.addRule(contractAddress, bytes(functionSignature), rule);

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;

        logic.addFunctionSignature(contractAddress, bytes(functionSignature), pTypes);
    }

    function setupRuleWithForeignCall() public {
        // Rule: FC:simpleCheck(amount) > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        RulesStorageStructure.PT[] memory fcArgs = new RulesStorageStructure.PT[](1);
        fcArgs[0] = RulesStorageStructure.PT.UINT;
        RulesStorageStructure.ForeignCall memory fc = logic.buildForeignCall(address(userContract), address(testContract), "simpleCheck(uint256)", RulesStorageStructure.PT.UINT, fcArgs);
        RulesStorageStructure.Rule memory rule;
        rule.placeHolders = new RulesStorageStructure.Placeholder[](1); 
        rule.placeHolders[0].foreignCall = true;
        rule.placeHolders[0].typeSpecificIndex = fc.foreignCallIndex;
        rule.instructionSet = new uint256[](8);
        rule.instructionSet[0] = uint(RulesStorageStructure.LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = 0;
        rule.instructionSet[3] = uint(RulesStorageStructure.LC.NUM);
        rule.instructionSet[4] = 4;
        rule.instructionSet[5] = uint(RulesStorageStructure.LC.GT);
        rule.instructionSet[6] = 0;
        rule.instructionSet[7] = 1;
        rule.fcArgumentMappings = new RulesStorageStructure.FCArgToRuleArgMappings[](1);
        rule.fcArgumentMappings[0].mappings = new RulesStorageStructure.FCArgToRuleArg[](1);
        rule.fcArgumentMappings[0].mappings[0].fcArgType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappings[0].mappings[0].functionSignatureArg.foreignCall = false;
        rule.fcArgumentMappings[0].mappings[0].functionSignatureArg.pType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappings[0].mappings[0].functionSignatureArg.typeSpecificIndex = 0;
        logic.addRule(address(userContract), bytes(functionSignature), rule);

        RulesStorageStructure.PT[] memory pTypes = new RulesStorageStructure.PT[](2);
        pTypes[0] = RulesStorageStructure.PT.ADDR;
        pTypes[1] = RulesStorageStructure.PT.UINT;
        logic.addFunctionSignature(address(userContract), bytes(functionSignature), pTypes);
    }

    function testCheckRulesExplicit() public {
        setupRuleWithoutForeignCall();
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        arguments.addresses = new address[](1);
        arguments.addresses[0] = address(0x7654321);
        arguments.ints = new uint256[](1);
        arguments.ints[0] = 5;
        bytes memory retVal = RuleEncodingLibrary.customEncoder(arguments);
        bool response = logic.checkRules(contractAddress, bytes(functionSignature), retVal);
        assertTrue(response);
    }

    function testCheckRulesExplicitWithForeignCall() public {
        setupRuleWithForeignCall();
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        arguments.addresses = new address[](1);
        arguments.addresses[0] = address(0x7654321);
        arguments.ints = new uint256[](1);
        arguments.ints[0] = 5;
        bytes memory retVal = RuleEncodingLibrary.customEncoder(arguments);

        bool response = logic.checkRules(address(userContract), bytes(functionSignature), retVal);
        assertTrue(response);
    }

    function testCheckRulesWithExampleContract() public {
        setupRuleWithoutForeignCall();
        bool retVal = userContract.transfer(address(0x7654321), 3);
        assertFalse(retVal);
    }

    function testEncodingForeignCall() public {
        string memory functionSig = "testSig(uint256,string,uint256,string,address)";

        uint256[] memory vals = new uint256[](3);
        vals[0] = 1;
        vals[1] = 2;
        vals[2] = 3;

        uint256[] memory params = new uint256[](5);
        params[0] = 0;
        params[1] = 2;
        params[2] = 0;
        params[3] = 2;
        params[4] = 1;

        address[] memory addresses = new address[](1);
        addresses[0] = address(0x1234567);

        string[] memory strings = new string[](2);
        strings[0] = "test";
        strings[1] = "otherTest";
        bytes memory argsEncoded = logic.assemblyEncode(params, vals, addresses, strings);
        bytes4 FUNC_SELECTOR = bytes4(keccak256(bytes(functionSig)));
        bytes memory encoded;
        encoded = bytes.concat(encoded, FUNC_SELECTOR);
        encoded = bytes.concat(encoded, argsEncoded);
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();

        (bool response, bytes memory data) = address(foreignCall).call(encoded);
        assertEq(foreignCall.getDecodedIntOne(), 1);
        assertEq(foreignCall.getDecodedIntTwo(), 2);
        assertEq(foreignCall.getDecodedStrOne(), "test");
        assertEq(foreignCall.getDecodedStrTwo(), "otherTest");
        assertEq(foreignCall.getDecodedAddr(), address(0x1234567));
    }

    function testEvaluateForeignCallForRule() public {
        RulesStorageStructure.ForeignCall memory fc;
        ForeignCallTestContract foreignCall = new ForeignCallTestContract();
        string memory functionSig = "testSig(uint256,string,uint256,string,address)";

        fc.foreignCallAddress = address(foreignCall);
        fc.signature = bytes4(keccak256(bytes(functionSig)));
        fc.foreignCallIndex = 0;
        fc.returnType = RulesStorageStructure.PT.BOOL;

        fc.parameterTypes = new RulesStorageStructure.PT[](5);
        fc.parameterTypes[0] = RulesStorageStructure.PT.UINT;
        fc.parameterTypes[1] = RulesStorageStructure.PT.STR;
        fc.parameterTypes[2] = RulesStorageStructure.PT.UINT;
        fc.parameterTypes[3] = RulesStorageStructure.PT.STR;
        fc.parameterTypes[4] = RulesStorageStructure.PT.ADDR;

        RulesStorageStructure.Arguments memory functionArguments;
        // rule signature function arguments (RS): string, uint256, uint256, string, uint256, string, address
        // foreign call function arguments (FC): uint256, string, uint256, string, address
        //
        // Mapping:
        // FC index: 0 1 2 3 4
        // RS index: 1 3 4 5 6

        functionArguments.argumentTypes = new RulesStorageStructure.PT[](7);
        functionArguments.argumentTypes[0] = RulesStorageStructure.PT.STR;
        functionArguments.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        functionArguments.argumentTypes[2] = RulesStorageStructure.PT.UINT;
        functionArguments.argumentTypes[3] = RulesStorageStructure.PT.STR;
        functionArguments.argumentTypes[4] = RulesStorageStructure.PT.UINT;
        functionArguments.argumentTypes[5] = RulesStorageStructure.PT.STR;
        functionArguments.argumentTypes[6] = RulesStorageStructure.PT.ADDR;

        functionArguments.addresses = new address[](1);
        functionArguments.addresses[0] = address(0x12345678);

        functionArguments.strings = new string[](3);
        functionArguments.strings[0] = "one";
        functionArguments.strings[1] = "two";
        functionArguments.strings[2] = "three";

        functionArguments.ints = new uint256[](3);
        functionArguments.ints[0] = 1;
        functionArguments.ints[1] = 2;
        functionArguments.ints[2] = 3;

        RulesStorageStructure.Rule memory rule;
        rule.fcArgumentMappings = new RulesStorageStructure.FCArgToRuleArgMappings[](1);
        rule.fcArgumentMappings[0].foreignCallIndex = 0;
        rule.fcArgumentMappings[0].mappings = new RulesStorageStructure.FCArgToRuleArg[](5);

        rule.fcArgumentMappings[0].mappings[0].fcArgType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappings[0].mappings[0].functionSignatureArg.pType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappings[0].mappings[0].functionSignatureArg.typeSpecificIndex = 0;

        rule.fcArgumentMappings[0].mappings[1].fcArgType = RulesStorageStructure.PT.STR;
        rule.fcArgumentMappings[0].mappings[1].functionSignatureArg.pType = RulesStorageStructure.PT.STR;
        rule.fcArgumentMappings[0].mappings[1].functionSignatureArg.typeSpecificIndex = 1;

        rule.fcArgumentMappings[0].mappings[2].fcArgType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappings[0].mappings[2].functionSignatureArg.pType = RulesStorageStructure.PT.UINT;
        rule.fcArgumentMappings[0].mappings[2].functionSignatureArg.typeSpecificIndex = 2;

        rule.fcArgumentMappings[0].mappings[3].fcArgType = RulesStorageStructure.PT.STR;
        rule.fcArgumentMappings[0].mappings[3].functionSignatureArg.pType = RulesStorageStructure.PT.STR;
        rule.fcArgumentMappings[0].mappings[3].functionSignatureArg.typeSpecificIndex = 2;

        rule.fcArgumentMappings[0].mappings[4].fcArgType = RulesStorageStructure.PT.ADDR;
        rule.fcArgumentMappings[0].mappings[4].functionSignatureArg.pType = RulesStorageStructure.PT.ADDR;
        rule.fcArgumentMappings[0].mappings[4].functionSignatureArg.typeSpecificIndex = 0;

        RulesStorageStructure.ForeignCallReturnValue memory retVal = logic.evaluateForeignCallForRule(fc, rule, functionArguments);
        console2.log(retVal.boolValue);
    }
}