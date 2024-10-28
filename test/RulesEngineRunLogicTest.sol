/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "src/RulesEngineRunLogic.sol";
import "forge-std/console2.sol";

/**
 * @title Test the functionality of the RulesEngineRunLogic contract
 * @author @mpetersoCode55 
 */
contract RulesEngineRunLogicTest {

    RulesEngineRunLogic logic;
    address contractAddress = address(0x1234567);
    string functionSignature = "transfer(address,uint256) returns (bool)";

    function setUp() public{
        logic = new RulesEngineRunLogic();
        // Rule: amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        Rule memory rule;
        // Instruction set: LC.PLH, 1, 0, LC.NUM, 4, LC.GT, 0, 1
        rule.instructionSet = new uint256[](8);
        rule.instructionSet[0] = uint(LC.PLH);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = 0;
        rule.instructionSet[3] = uint(LC.NUM);
        rule.instructionSet[4] = 4;
        rule.instructionSet[5] = uint(LC.GT);
        rule.instructionSet[6] = 0;
        rule.instructionSet[7] = 1;
        rule.placeHolders = new Placeholder[](1);
        rule.placeHolders[0].pType = PT.UINT;
        rule.placeHolders[0].typeSpecificIndex = 0;
        logic.addRule(contractAddress, functionSignature, rule);

        PT[] memory pTypes = new PT[](2);
        pTypes[0] = PT.ADDR;
        pTypes[1] = PT.UINT;

        logic.addFunctionSignature(contractAddress, functionSignature, pTypes);
    }

    function testCheckRules() public {
        Arguments memory arguments;
        arguments.argumentTypes = new PT[](2);
        arguments.argumentTypes[0] = PT.ADDR;
        arguments.argumentTypes[1] = PT.UINT;
        arguments.addresses = new address[](1);
        arguments.addresses[0] = address(0x7654321);
        arguments.ints = new uint256[](1);
        arguments.ints[0] = 5;
        bytes memory retVal = customEncoder(arguments);
        bool reponse = logic.checkRules(contractAddress, functionSignature, retVal);
        
    }

    function customEncoder(Arguments memory arguments) public pure returns (bytes memory retVal) {
        uint256 addressIter = 0;
        uint256 intIter = 0;
        uint256 stringIter = 0;

        for(uint256 i = 0; i < arguments.argumentTypes.length; i++) {
            if(arguments.argumentTypes[i] == PT.ADDR) {
                retVal = bytes.concat(retVal, abi.encode(arguments.addresses[addressIter]));
                addressIter += 1;
            } else if(arguments.argumentTypes[i] == PT.UINT) {
                retVal = bytes.concat(retVal, abi.encode(arguments.ints[intIter]));
                intIter += 1;
            } else if(arguments.argumentTypes[i] == PT.STR) {
                retVal = bytes.concat(retVal, abi.encode(arguments.strings[stringIter]));
                stringIter += 1;
            }
        }
    }

}