/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "src/interpreter.sol";
import "forge-std/console2.sol";
import "lib/solady/src/utils/LibString.sol";
import "src/testContract.sol";

contract InterpreterTest  {
    using LibString for *;
    Interpreter testVal;
    testContract testC;
    function setUp() public {
        testVal = new Interpreter();
        testC = new testContract();
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
        string memory toParse = "[ 1 + 12 - 3 * 4 - 4 / 4 + 2 == 11 AND [ 2 == 2 AND 4 == 4 ]] OR [ 7 == 7 AND 7 == 8 ] --> revert --> 'transfer(address, uint256) returns bool'";
        testVal.interpretSyntaxRule(toParse, address(0x12345678));
        TransactionInfo memory tInfo;
        tInfo.tokenAddress = address(0x12345678);
        tInfo.functionSignature = "'transfer(address, uint256) returns bool'";
        bool retVal = testVal.checkRule(tInfo);
        console2.log(retVal);
    }

    function testEncodingForeignCall() public {
        string[] memory args = new string[](2);
        args[0] = "test";
        args[1] = "otherTest";
        string memory functionSignature = "testSig(string,string)";
        ForeignCall memory fc;
        fc.functionSignature = functionSignature;
        fc.argumentTypes = new string[](2);
        fc.argumentTypes[0] = "string";
        fc.argumentTypes[1] = "string";
        bytes memory encoded = RuleLib.encodeBasedOnArgumentCount(fc, args);
        bytes memory referenceEncoding = encodingReference();
        if(keccak256(encoded) == keccak256(referenceEncoding)) {
            console2.log("Match");
        } else {
            console2.log("No match");
        }
    }

    function encodingReference() public returns (bytes memory) {
        bytes memory encodedTest = abi.encodeWithSignature("testSig(string,string)", "test", "otherTest");
        return encodedTest;
    }

    function testEvaluatingForeignCall() public {
        ForeignCall memory fc;
        fc.argumentTypes = new string[](2);
        fc.argumentTypes[0] = "string";
        fc.argumentTypes[1] = "string";
        fc.contractAddress = address(testC);
        fc.functionName = "testSig";
        fc.functionSignature = "testSig(string,string)";
        ForeignCall[] memory calls = new ForeignCall[](1);
        calls[0] = fc;
        uint256 retVal = RuleLib.evaluateForeignCall("FC:testSig(string,string)", calls);
        console2.log(retVal);
    }
}