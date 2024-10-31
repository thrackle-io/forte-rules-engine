/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "src/RulesEngineRunLogic.sol";
import "src/ExampleUserContract.sol";
import "forge-std/console2.sol";
import "forge-std/StdAssertions.sol";

/**
 * @title Test the functionality of the RulesEngineRunLogic contract
 * @author @mpetersoCode55 
 */
contract RulesEngineRunLogicTest is StdAssertions {

    RulesEngineRunLogic logic;
    ExampleUserContract userContract;
    address contractAddress = address(0x1234567);
    string functionSignature = "transfer(address,uint256) returns (bool)";

    function setUp() public{
        logic = new RulesEngineRunLogic();
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
        userContract = new ExampleUserContract();
        userContract.setRulesEngineAddress(address(logic));
    }

    function testCheckRulesExplicit() public {
        RulesStorageStructure.Arguments memory arguments;
        arguments.argumentTypes = new RulesStorageStructure.PT[](2);
        arguments.argumentTypes[0] = RulesStorageStructure.PT.ADDR;
        arguments.argumentTypes[1] = RulesStorageStructure.PT.UINT;
        arguments.addresses = new address[](1);
        arguments.addresses[0] = address(0x7654321);
        arguments.ints = new uint256[](1);
        arguments.ints[0] = 5;
        bytes memory retVal = customEncoder(arguments);
        bool response = logic.checkRules(contractAddress, bytes(functionSignature), retVal);
        assertTrue(response);
    }

    function testCheckRulesWithExampleContract() public {
        bool retVal = userContract.transfer(address(0x7654321), 3);
        assertFalse(retVal);
    }

    function customEncoder(RulesStorageStructure.Arguments memory arguments) public pure returns (bytes memory retVal) {
        uint256 addressIter = 0;
        uint256 intIter = 0;
        uint256 stringIter = 0;

        for(uint256 i = 0; i < arguments.argumentTypes.length; i++) {
            if(arguments.argumentTypes[i] == RulesStorageStructure.PT.ADDR) {
                retVal = bytes.concat(retVal, abi.encode(arguments.addresses[addressIter]));
                addressIter += 1;
            } else if(arguments.argumentTypes[i] == RulesStorageStructure.PT.UINT) {
                retVal = bytes.concat(retVal, abi.encode(arguments.ints[intIter]));
                intIter += 1;
            } else if(arguments.argumentTypes[i] == RulesStorageStructure.PT.STR) {
                retVal = bytes.concat(retVal, abi.encode(arguments.strings[stringIter]));
                stringIter += 1;
            }
        }
    }

}