// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// This program is a conversion of ../main.py:run

enum LC { NUM, ADD, SUB, MUL, DIV, LT, GT, EQ, AND, OR, NOT, PLH }
enum parameterType { ADDR, STR, UINT, BOOL }

struct placeholder {
    parameterType pType;
    uint256 index;
}

struct argumentHolder {
        parameterType[] arguments;
        address[] addresses;
        uint256[] ints;
        string[] strings;
    }

struct rule {
    uint256[] prog;
    
    // List of all placeholders used in the rule in order
    // Needs to contain the type, and index (zero based) of the particular type in the function signature 
    // For example if the argument in question is the 2nd address in the function signature the placeHolder would be:
    // pType = parameterType.ADDR index = 1
    placeholder[] placeHolders;
}

contract exampleUserContract {
    address rulesEngineAddress;

    function transfer(address _to, uint256 _amount) public view returns (bool success) {
        argumentHolder memory args;
        args.addresses = new address[](1);
        args.addresses[0] = _to;
        args.ints = new uint256[](1);
        args.arguments = new parameterType[](2);
        args.arguments[0] = parameterType.ADDR;
        args.arguments[1] = parameterType.UINT;
        bytes memory encoded = customEncoder(args);
        checkRulesCall(encoded);
        // This is where the overriden transfer would be called 

        return true;
    }

    function checkRulesCall(bytes memory arguments) public view {
        RulesEngineRunLogic rulesEngine = RulesEngineRunLogic(rulesEngineAddress);
        rulesEngine.checkRules(address(0x1234567), "transfer(address, uint256)", arguments);
    }

    function customEncoder(argumentHolder memory arguments) public pure returns (bytes memory retVal) {
        uint256 addressIter = 0;
        uint256 intIter = 0;
        uint256 stringIter = 0;

        for(uint256 i = 0; i < arguments.arguments.length; i++) {
            if(arguments.arguments[i] == parameterType.ADDR) {
                bytes.concat(retVal, abi.encode(arguments.addresses[addressIter]));
                addressIter += 1;
            } else if(arguments.arguments[i] == parameterType.UINT) {
                bytes.concat(retVal, abi.encode(arguments.ints[i]));
                intIter += 1;
            }
        }
    }
}

contract RulesEngineRunLogic {
    function ui2bool(uint256 x) public pure returns (bool ans) {
        return x == 1;
    }
    function bool2ui(bool x) public pure returns (uint256 ans) {
        return x ? 1 : 0;
    }

    parameterType[] functionSignaturePlaceholders;

    function checkRules(address tokenAddress, string calldata functionSignature, bytes calldata arguments) public view returns (uint256[] memory responses) {
        uint256 placeIter = 32;
        uint256 addressIter = 0;
        uint256 intIter = 0;
        uint256 stringIter = 0;
        uint256 overallIter = 0;

        // Decode arguments from function signature
        //-----------------------------------------------------------------------------------------------------------------
        argumentHolder memory functionSignatureArgs;
        functionSignatureArgs.arguments = new parameterType[](functionSignaturePlaceholders.length);
        // Initializing each to the max size to avoid the cost of iterating through to determine how many of each type exist
        functionSignatureArgs.addresses = new address[](functionSignaturePlaceholders.length);
        functionSignatureArgs.ints = new uint256[](functionSignaturePlaceholders.length);
        functionSignatureArgs.strings = new string[](functionSignaturePlaceholders.length);

        for(uint256 i = 0; i < functionSignaturePlaceholders.length; i++) {
            if(functionSignaturePlaceholders[i] == parameterType.ADDR) {
                address data = i == 0 ? abi.decode(arguments[:32], (address)) : abi.decode(arguments[placeIter:32], (address));
                if(i != 0) {
                    placeIter += 32;
                }
                functionSignatureArgs.arguments[overallIter] = parameterType.ADDR;
                functionSignatureArgs.addresses[addressIter] = data;
                overallIter += 1;
                addressIter += 1;
            } else if(functionSignaturePlaceholders[i] == parameterType.UINT) {
                uint256 data = i == 0 ? abi.decode(arguments[:32], (uint256)) : abi.decode(arguments[placeIter:32], (uint256));
                if(i != 0) {
                    placeIter += 32;
                }
                functionSignatureArgs.arguments[overallIter] = parameterType.UINT;
                functionSignatureArgs.ints[intIter] = data;
                overallIter += 1;
                intIter += 1;
            } else if(functionSignaturePlaceholders[i] == parameterType.STR) {
                string memory data = i == 0 ? abi.decode(arguments[:32], (string)) : abi.decode(arguments[placeIter:32], (string));
                if(i != 0) {
                    placeIter += 32;
                }
                functionSignatureArgs.arguments[overallIter] = parameterType.STR;
                functionSignatureArgs.strings[stringIter] = data;
                overallIter += 1;
                stringIter += 1;
            }
        }
        //-----------------------------------------------------------------------------------------------------------------

        // TODO: poll mapping for applicable rules based on token address and function signature
        // Loop through the below logic for each rule (each having it's own rulePlaceholders structure pulled from storage) 
        rule memory applicableRule;

        // TODO: determine amount of applicable rules
        uint256 ruleCount = 1;

        responses = new uint256[](ruleCount);
        uint256 responseIter = 0;

        // Retrieve placeHolder[] for specific rule to be evaluated and translate function signature argument array 
        // to rule specific argument array
        //-----------------------------------------------------------------------------------------------------------------

        argumentHolder memory ruleArgs;
        ruleArgs.arguments = new parameterType[](applicableRule.placeHolders.length);
        // Initializing each to the max size to avoid the cost of iterating through to determine how many of each type exist
        ruleArgs.addresses = new address[](applicableRule.placeHolders.length);
        ruleArgs.ints = new uint256[](applicableRule.placeHolders.length);
        ruleArgs.strings = new string[](applicableRule.placeHolders.length);
        overallIter = 0;
        addressIter = 0;
        intIter = 0;
        stringIter = 0;

        for(uint256 i = 0; i < applicableRule.placeHolders.length; i++) {
            if(applicableRule.placeHolders[i].pType == parameterType.ADDR) {
                ruleArgs.arguments[overallIter] = parameterType.ADDR;
                ruleArgs.addresses[addressIter] = functionSignatureArgs.addresses[applicableRule.placeHolders[i].index];
                overallIter += 1;
                addressIter += 1;
            } else if(applicableRule.placeHolders[i].pType == parameterType.UINT) {
                ruleArgs.arguments[overallIter] = parameterType.UINT;
                ruleArgs.ints[intIter] = functionSignatureArgs.ints[applicableRule.placeHolders[i].index];
                overallIter += 1;
                intIter += 1;
            } else if(applicableRule.placeHolders[i].pType == parameterType.STR) {
                ruleArgs.arguments[overallIter] = parameterType.STR;
                ruleArgs.strings[stringIter] = functionSignatureArgs.strings[applicableRule.placeHolders[i].index];
                overallIter += 1;
                stringIter += 1;
            }
        }

        responses[responseIter] = this.run(applicableRule.prog, ruleArgs);
        responseIter += 1;


        //-----------------------------------------------------------------------------------------------------------------
    }

    // This implementation is probably bad for two reasons:
    //
    // 1. We aren't limiting the size of programs, so some could submit a really big one.
    //    That seems wrong.
    // 
    // 2. We are using uint256 as the program data, but probably we could get away with u8,
    //    especially if there's a different place to store big values, like addresses and constant
    //    numbers that are large. 
    function run(uint256[] calldata prog, argumentHolder calldata arguments) public pure returns (uint256 ans) {
        uint256[64] memory mem;
        uint256 idx = 0;
        uint256 opi = 0;
        while (idx < prog.length) {
            uint256 v = 0;
            LC op = LC(prog[idx]);

            if(op == LC.PLH) {
                // Placeholder format will be:
                // PLH, arguments array index, argument type specific array index
                // For example if the Placeholder is the 3rd argument in the function signature, which is the first address type argument:
                // PLH, 2, 0
                uint256 pli = prog[idx+1];
                uint256 spci = prog[idx+2];
                parameterType typ = arguments.arguments[pli];
                if(typ == parameterType.ADDR) {
                    // Convert address to uint256 for direct comparison using == and != operations
                    v = uint256(uint160(arguments.addresses[spci])); idx += 3;
                } else if(typ == parameterType.UINT) {
                    v = arguments.ints[spci]; idx += 3;
                } else if(typ == parameterType.STR) {
                    // Convert string to uint256 for direct comparison using == and != operations
                    v = uint256(keccak256(abi.encode(arguments.strings[spci]))); idx += 3;
                }
            }

            if (op == LC.NUM) { v = prog[idx+1]; idx += 2; }
            else if (op == LC.ADD) { v = mem[prog[idx+1]] + mem[prog[idx+2]]; idx += 3; }
            else if (op == LC.SUB) { v = mem[prog[idx+1]] - mem[prog[idx+2]]; idx += 3; }
            else if (op == LC.MUL) { v = mem[prog[idx+1]] * mem[prog[idx+2]]; idx += 3; }
            else if (op == LC.DIV) { v = mem[prog[idx+1]] / mem[prog[idx+2]]; idx += 3; }
            else if (op == LC.LT ) { v = bool2ui(mem[prog[idx+1]] < mem[prog[idx+2]]); idx += 3; }
            else if (op == LC.GT ) { v = bool2ui(mem[prog[idx+1]] > mem[prog[idx+2]]); idx += 3; }
            else if (op == LC.EQ ) { v = bool2ui(mem[prog[idx+1]] == mem[prog[idx+2]]); idx += 3; }
            else if (op == LC.AND) { v = bool2ui(ui2bool(mem[prog[idx+1]]) && ui2bool(mem[prog[idx+2]])); idx += 3; }
            else if (op == LC.OR ) { v = bool2ui(ui2bool(mem[prog[idx+1]]) || ui2bool(mem[prog[idx+2]])); idx += 3; }
            else if (op == LC.NOT) { v = bool2ui(! ui2bool(mem[prog[idx+1]])); idx += 2; }
            else { revert("Illegal instruction"); }
            mem[opi] = v;
            opi += 1;
        }
        return mem[opi - 1];
    }
}