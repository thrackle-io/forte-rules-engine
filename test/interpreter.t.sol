/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "src/interpreter.sol";
import "forge-std/console2.sol";

contract InterpreterTest  {
    Interpreter testVal;

    function setUp() public {
        testVal = new Interpreter();
    }

    function testInterpretSytaxRule() public {
        string memory toParse = "[FC:tag(receiverAddress) == 'access level 0' OR FC:tag(receiverAddress) == 'no access level set'] AND FC:WorthInUSD(receiverBalance) > 100 --> revert --> 'transfer(address, uint256) returns bool'";
        testVal.interpretSyntaxRule(toParse, address(0x12345678));
        string memory toParseTwo = "FC:tag(receiverAddress) == 'SECOND TEST' --> revert --> 'transfer(address, uint256) returns bool'";
        testVal.interpretSyntaxRule(toParseTwo, address(0x12345678));

        Rule[] memory setRules = testVal.getRules(address(0x12345678), "'transfer(address, uint256) returns bool'");
        console2.log(setRules.length);

        for(uint256 i = 0; i < setRules.length; i++) {
            Rule retVal = setRules[i];
            console2.log("Rule ", i);
            for(uint256 j = 0; j < retVal.getExpressions().length; j++) {
                console2.log(retVal.getExpressions()[j].lhs);
                console2.log(retVal.getExpressions()[j].comparator);
                console2.log(retVal.getExpressions()[j].rhs);
            }
        }
    }

    function testCheckRule() public {
        string memory toParse = "1 + 12 - 3 * 4 - 4 / 4 + 2 == 11 AND 2 == 2 --> revert --> 'transfer(address, uint256) returns bool'";
        testVal.interpretSyntaxRule(toParse, address(0x12345678));
        TransactionInfo memory tInfo;
        tInfo.tokenAddress = address(0x12345678);
        tInfo.functionSignature = "'transfer(address, uint256) returns bool'";
        bool retVal = testVal.checkRule(tInfo);
        console2.log(retVal);
    }
}