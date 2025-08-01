/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";

abstract contract rulesExecution is RulesEngineCommon {
    ExampleERC20 exampleERC20;
    ExampleUserContractExtraParams userContract2;
    ExampleUserContractEncoding encodingContract;
    /**
     *
     *
     * Execution tests for rules within the rules engine
     *
     *
     */
    function testRulesEngine_Unit_CheckRules_Explicit_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        setUpRuleSimple();
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 5);
        vm.startPrank(address(userContract));
        vm.startSnapshotGas("CheckRules_Explicit");
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_CheckRules_Explicit_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        vm.startPrank(policyAdmin);
        setUpRuleSimple();
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunction))), address(0x7654321), 0);
        vm.startPrank(address(userContract));
        vm.startSnapshotGas("CheckRules_Explicit");
        vm.expectRevert(abi.encodePacked(revert_text));
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);
        vm.stopSnapshotGas();
    }

    function testRulesEngine_Unit_checkRule_simple_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setUpRuleSimple();
        vm.startSnapshotGas("checkRule_simple_GT");
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        bool response = userContract.transfer(address(0x7654321), 47);
        vm.stopSnapshotGas();
        assertTrue(response);
    }

    function testRulesEngine_Unit_checkRule_simpleGTEQL_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setUpRuleSimpleGTEQL();
        vm.startSnapshotGas("checkRule_simpleGTEQL");
        // test that rule ( amount >= 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        bool response = userContract.transfer(address(0x7654321), 4);
        vm.stopSnapshotGas();
        assertTrue(response);
    }

    function testRulesEngine_Unit_checkRule_simpleLTEQL_Positive() public ifDeploymentTestsEnabled endWithStopPrank {
        setUpRuleSimpleLTEQL();
        vm.startSnapshotGas("checkRule_simpleLTEQL");
        // test that rule ( ruleValue <= amount -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        bool response = userContract.transfer(address(0x7654321), 3);

        vm.stopSnapshotGas();
        assertTrue(response);
    }

    function testRulesEngine_Unit_checkRule_simple_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setUpRuleSimple();
        // test that rule ( amount > 4 -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.transfer(address(0x7654321), 3);
    }

    function testRulesEngine_Unit_checkRule_simpleGTEQL_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setUpRuleSimpleGTEQL();
        // test that rule ( ruleValue >= amount -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.transfer(address(0x7654321), 3);
    }

    function testRulesEngine_Unit_checkRule_simpleLTEQL_Negative() public ifDeploymentTestsEnabled endWithStopPrank {
        setUpRuleSimpleLTEQL();
        // test that rule ( ruleValue <= amount -> revert -> transfer(address _to, uint256 amount) returns (bool)" ) processes correctly
        vm.expectRevert(abi.encodePacked(revert_text));
        userContract.transfer(address(0x7654321), 5);
    }

    /////////////////////////////// additional data encoding tests
    function testRulesEngine_Unit_TestContractEncoding_AdditionalParamsEncoded_UintRuleValue()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // encode additional datas with the calling contract call into rules engine
        //deploy ExampleUserContractEncoding
        encodingContract = new ExampleUserContractEncoding();
        encodingContract.setRulesEngineAddress(address(red));
        encodingContract.setCallingContractAdmin(callingContractAdmin);
        address encodingContractAddress = address(encodingContract);
        // write data to encode:
        encodingContract.writeNewUintData(74);
        // create rule that will handle additional params
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.UINT;
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes(callingFunction)))),
            pTypes,
            callingFunction,
            ""
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction))));
        callingFunctionIds.push(callingFunctionId);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            callingFunctionIds,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );

        // create Rule - cannot use existing helper functions since rule is unique to test scenario
        // Rule: amount > 100 -> OR -> transferDataValue > 75 -> revert -> transfer(address _to, uint256 amount) returns (bool)"
        // IF amount is greater than 100 or transfer value is greater than 75 -> checkPolicy returns false
        Rule memory rule;
        // Set up some effects.
        _setupEffectProcessor();

        rule.instructionSet = new uint256[](14);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 1; //0
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 100; // 1
        rule.instructionSet[4] = uint(LogicalOp.GT);
        rule.instructionSet[5] = 1;
        rule.instructionSet[6] = 0; // 2
        rule.instructionSet[7] = uint(LogicalOp.PLH);
        rule.instructionSet[8] = 2; // 3
        rule.instructionSet[9] = uint(LogicalOp.NUM);
        rule.instructionSet[10] = 75; // 4
        rule.instructionSet[11] = uint(LogicalOp.GT);
        rule.instructionSet[12] = 4;
        rule.instructionSet[13] = 3; // 5

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0; // to address
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount
        rule.placeHolders[2].pType = ParamTypes.UINT;
        rule.placeHolders[2].typeSpecificIndex = 2; // Additional uint

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);

        uint256 ruleID = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleID;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);
        // test rule processing
        vm.startSnapshotGas("Additional_Encoding_Uint_Value");
        bool response = encodingContract.transfer(address(0xacdc), 99);
        vm.stopSnapshotGas();
        assertTrue(response);
    }

    function testRulesEngine_Unit_TestContractEncoding_AdditionalParamsEncoded_AddressRuleValue()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // encode additional datas with the calling contract call into rules engine
        //deploy ExampleUserContractEncoding
        encodingContract = new ExampleUserContractEncoding();
        encodingContract.setRulesEngineAddress(address(red));
        encodingContract.setCallingContractAdmin(callingContractAdmin);
        address encodingContractAddress = address(encodingContract);

        encodingContract.writeNewAddressData(address(0x1234567));

        // create rule that will handle additional params
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Set up some effects.
        _setupEffectProcessor();
        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        pTypes[3] = ParamTypes.ADDR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(uint160(address(0x1234567)));
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.rawData.argumentTypes = new ParamTypes[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = ParamTypes.ADDR;
        rule.rawData.dataValues[0] = abi.encode(0x1234567);
        rule.rawData.instructionSetIndex[0] = 3;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0; // to address
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount
        rule.placeHolders[2].pType = ParamTypes.ADDR;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional address param

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes(callingFunction3)))),
            pTypes,
            callingFunction3,
            ""
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction3))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            callingFunctionIds,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);
        // // test rule processing
        vm.startSnapshotGas("Additional_Encoding_Address_Value");
        // transferFrom in this contract is transferFrom(address,amount) != transferFrom(from,to,amount)
        bool response1 = encodingContract.transferFrom(address(0x1234567), 99);
        vm.stopSnapshotGas();
        assertTrue(response1);

        bool response2 = encodingContract.transferFrom(address(0x31337), 75);
        assertTrue(response2);
    }

    function testRulesEngine_Unit_TestContractEncoding_AdditionalParamsEncoded_ForeignCallValue()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // encode additional datas with the calling contract call into rules engine
        //deploy ExampleUserContractEncoding
        encodingContract = new ExampleUserContractEncoding();
        encodingContract.setRulesEngineAddress(address(red));
        encodingContract.setCallingContractAdmin(callingContractAdmin);
        address encodingContractAddress = address(encodingContract);

        encodingContract.writeNewAddressData(address(0x1234567));
        testContract2 = new ForeignCallTestContractOFAC();
        testContract2.addToNaughtyList(address(0x1234567));

        // create rule that will handle additional params
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Set up some effects.
        _setupEffectProcessor();
        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        pTypes[3] = ParamTypes.ADDR;

        ParamTypes[] memory fcArgs = new ParamTypes[](1);
        fcArgs[0] = ParamTypes.ADDR;
        ForeignCall memory fc;
        fc.encodedIndices = new ForeignCallEncodedIndex[](1);
        fc.encodedIndices[0].index = 2;
        fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES;
        fc.parameterTypes = fcArgs;
        fc.foreignCallAddress = address(testContract2);
        fc.signature = bytes4(keccak256(bytes("getNaughty(address)")));
        fc.returnType = ParamTypes.UINT;
        fc.foreignCallIndex = 1;
        uint256 foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], fc, "getNaughty(address)");

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = 1;
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.rawData.argumentTypes = new ParamTypes[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = ParamTypes.ADDR;
        rule.rawData.dataValues[0] = abi.encode(0x1234567);
        rule.rawData.instructionSetIndex[0] = 3;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0; // to address
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount
        rule.placeHolders[2].pType = ParamTypes.ADDR;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional address param
        rule.placeHolders[2].flags = FLAG_FOREIGN_CALL;
        rule.placeHolders[2].typeSpecificIndex = uint128(foreignCallId);

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes(callingFunction3)))),
            pTypes,
            callingFunction3,
            ""
        );

        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunction3))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            callingFunctionIds,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);

        // // test rule processing
        vm.startSnapshotGas("Additional_Encoding_ForeignCall_Value");
        // transferFrom in this contract is transferFrom(address,amount) != transferFrom(from,to,amount)
        bool response3 = encodingContract.transferFrom(address(0x1234567), 99);
        vm.stopSnapshotGas();
        assertTrue(response3);

        bool response4 = encodingContract.transferFrom(address(0x31337), 75);
        assertTrue(response4);
    }

    /// Expanded Variable Tests
    // Test that and additional bool value will be processed by the rules engine
    function testRulesEngine_Unit_TestContractEncoding_AdditionalParamsEncoded_BoolRuleValue()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // encode additional datas with the calling contract call into rules engine
        //deploy ExampleUserContractEncoding
        encodingContract = new ExampleUserContractEncoding();
        encodingContract.setRulesEngineAddress(address(red));
        encodingContract.setCallingContractAdmin(callingContractAdmin);
        address encodingContractAddress = address(encodingContract);

        encodingContract.writeNewBoolData(true);

        // create rule that will handle additional params
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Set up some effects.
        _setupEffectProcessor();
        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.BOOL;
        pTypes[3] = ParamTypes.ADDR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(1);
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0; // to address
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount
        rule.placeHolders[2].pType = ParamTypes.BOOL;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional bytes32 param

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes(callingFunctionBool)))),
            pTypes,
            callingFunctionBool,
            ""
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunctionBool))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            callingFunctionIds,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);
        // test rule processing
        vm.startSnapshotGas("Additional_Encoding_Bool_Value");
        bool response = encodingContract.transferBool(address(0x1234567), 99);
        vm.stopSnapshotGas();
        assertTrue(response);
    }
    // Bytes param test
    // Test that the rules engine can accept bool params and process != and == operations
    function testRulesEngine_Unit_TestContractEncoding_BytesRuleValue() public ifDeploymentTestsEnabled endWithStopPrank {
        // encode additional datas with the calling contract call into rules engine
        //deploy ExampleUserContractEncoding
        encodingContract = new ExampleUserContractEncoding();
        encodingContract.setRulesEngineAddress(address(red));
        encodingContract.setCallingContractAdmin(callingContractAdmin);
        address encodingContractAddress = address(encodingContract);
        bytes memory TEST = bytes("TEST");
        // create rule that will handle additional params
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Set up some effects.
        _setupEffectProcessor();
        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.BYTES;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(keccak256(abi.encode(TEST)));
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0; // to address
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount
        rule.placeHolders[2].pType = ParamTypes.BYTES;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional bytes32 param

        rule.rawData.argumentTypes = new ParamTypes[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = ParamTypes.BYTES;
        rule.rawData.dataValues[0] = abi.encode(TEST);
        rule.rawData.instructionSetIndex[0] = 3;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes(callingFunctionWithBytes)))),
            pTypes,
            callingFunctionWithBytes,
            ""
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunctionWithBytes))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            callingFunctionIds,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);
        // test rule processing
        bytes memory arguments = abi.encodeWithSelector(bytes4(keccak256(bytes(callingFunctionWithBytes))), address(0x7654321), 99, TEST);
        RulesEngineProcessorFacet(address(red)).checkPolicies(arguments);

        vm.startSnapshotGas("Additional_Encoding_Bytes_Value");
        bool response = encodingContract.transferWithBytes(address(0x1234567), 99, TEST);
        vm.stopSnapshotGas();
        assertTrue(response);
        vm.expectRevert(abi.encodePacked(revert_text));
        response = encodingContract.transferWithBytes(address(0x1234567), 99, bytes("BAD TEST"));
    }

    function testRulesEngine_Unit_TestContractEncoding_AdditionalParamsEncoded_BytesRuleValue()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // encode additional datas with the calling contract call into rules engine
        //deploy ExampleUserContractEncoding
        encodingContract = new ExampleUserContractEncoding();
        encodingContract.setRulesEngineAddress(address(red));
        encodingContract.setCallingContractAdmin(callingContractAdmin);
        address encodingContractAddress = address(encodingContract);
        bytes memory TEST = bytes("TEST");

        encodingContract.writeNewBytesData(TEST);
        // create rule that will handle additional params
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Set up some effects.
        _setupEffectProcessor();
        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.BYTES;
        pTypes[3] = ParamTypes.ADDR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(keccak256(abi.encode(TEST)));
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0; // to address
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount
        rule.placeHolders[2].pType = ParamTypes.BYTES;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional bytes32 param

        rule.rawData.argumentTypes = new ParamTypes[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = ParamTypes.BYTES;
        rule.rawData.dataValues[0] = abi.encode(TEST);
        rule.rawData.instructionSetIndex[0] = 3;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes(callingFunctionBytes)))),
            pTypes,
            callingFunctionBytes,
            ""
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunctionBytes))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            callingFunctionIds,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);
        // test rule processing
        bool response = encodingContract.transferBytes(address(0x1234567), 99);
        assertTrue(response);

        encodingContract.writeNewBytesData(bytes("BAD TEST INFO"));
        vm.expectRevert(abi.encodePacked(revert_text));
        response = encodingContract.transferBytes(address(0x1234567), 99);
    }

    function testRulesEngine_Unit_TestContractEncoding_AdditionalParamsEncoded_StringRuleValue()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // encode additional datas with the calling contract call into rules engine
        //deploy ExampleUserContractEncoding
        encodingContract = new ExampleUserContractEncoding();
        encodingContract.setRulesEngineAddress(address(red));
        encodingContract.setCallingContractAdmin(callingContractAdmin);
        address encodingContractAddress = address(encodingContract);
        string memory testString = "TEST";

        // create rule that will handle additional params
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Set up some effects.
        _setupEffectProcessor();
        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](3);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.STR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(keccak256(abi.encode(testString)));
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0; // to address
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount
        rule.placeHolders[2].pType = ParamTypes.STR;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional string param

        rule.rawData.argumentTypes = new ParamTypes[](1);
        rule.rawData.dataValues = new bytes[](1);
        rule.rawData.instructionSetIndex = new uint256[](1);
        rule.rawData.argumentTypes[0] = ParamTypes.STR;
        rule.rawData.dataValues[0] = abi.encode(testString);
        rule.rawData.instructionSetIndex[0] = 3;

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes(callingFunctionWithString)))),
            pTypes,
            callingFunctionWithString,
            ""
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunctionWithString))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            callingFunctionIds,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);
        // test rule processing
        vm.startSnapshotGas("Additional_Encoding_String_Value");
        bool response = encodingContract.transferWithString(address(0x1234567), 99, testString);
        vm.stopSnapshotGas();
        assertTrue(response);
        vm.expectRevert(abi.encodePacked(revert_text));
        response = encodingContract.transferWithString(address(0x1234567), 99, "bad string");
    }

    // Bytes param test
    function testRulesEngine_Unit_TestContractEncoding_AdditionalParamsEncoded_StaticArrayRuleValue()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // encode additional datas with the calling contract call into rules engine
        //deploy ExampleUserContractEncoding
        encodingContract = new ExampleUserContractEncoding();
        encodingContract.setRulesEngineAddress(address(red));
        encodingContract.setCallingContractAdmin(callingContractAdmin);
        address encodingContractAddress = address(encodingContract);

        // create new uint array for transfer data
        uint256[] memory testUintArray = new uint256[](3);
        testUintArray[0] = 1;
        testUintArray[1] = 2;
        testUintArray[2] = 3;
        encodingContract.writeNewStaticArrayData(testUintArray);

        // create rule that will handle additional params
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Set up some effects.
        _setupEffectProcessor();
        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.STATIC_TYPE_ARRAY;
        pTypes[3] = ParamTypes.ADDR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(3); // uint length of array to test that rule retreives uint array length correctly
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0; // to address
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount
        rule.placeHolders[2].pType = ParamTypes.STATIC_TYPE_ARRAY;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional bytes32 param

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes(callingFunctionArrayStatic)))),
            pTypes,
            callingFunctionArrayStatic,
            ""
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunctionArrayStatic))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            callingFunctionIds,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);
        // test rule processing
        vm.startSnapshotGas("Additional_Encoding_StaticArray_Value");
        bool response = encodingContract.transferArray(address(0x1234567), 99);
        vm.stopSnapshotGas();
        assertTrue(response);
    }

    function testRulesEngine_Unit_TestContractEncoding_AdditionalParamsEncoded_DynamicArrayRuleValue()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // encode additional datas with the calling contract call into rules engine
        //deploy ExampleUserContractEncoding
        encodingContract = new ExampleUserContractEncoding();
        encodingContract.setRulesEngineAddress(address(red));
        encodingContract.setCallingContractAdmin(callingContractAdmin);
        address encodingContractAddress = address(encodingContract);

        // create new uint array for transfer data
        bytes[] memory array = new bytes[](5);
        array[0] = bytes("super");
        array[1] = bytes("superduper");
        array[2] = bytes("superduperduper");
        array[3] = bytes("superduperduperduper");
        array[4] = bytes("superduperduperduperduper");

        encodingContract.writeNewDynamicArrayData(array);
        // create rule that will handle additional params
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Set up some effects.
        _setupEffectProcessor();

        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.STATIC_TYPE_ARRAY;
        pTypes[3] = ParamTypes.ADDR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(5); // uint length of array to test that rule retreives uint array length correctly
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0; // to address
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount
        rule.placeHolders[2].pType = ParamTypes.DYNAMIC_TYPE_ARRAY;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional bytes32 param

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes(callingFunctionArrayDynamic)))),
            pTypes,
            callingFunctionArrayDynamic,
            ""
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunctionArrayDynamic))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            callingFunctionIds,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);
        // test rule processing
        vm.startSnapshotGas("Additional_Encoding_DynamicArray_Value");
        bool response = encodingContract.transferDynamicArray(address(0x1234567), 99);
        vm.stopSnapshotGas();
        assertTrue(response);
    }

    function testRulesEngine_Unit_TestContractEncoding_AdditionalParamsEncoded_DynamicArrayRuleValue_Negative()
        public
        ifDeploymentTestsEnabled
        endWithStopPrank
    {
        // encode additional datas with the calling contract call into rules engine
        //deploy ExampleUserContractEncoding
        encodingContract = new ExampleUserContractEncoding();
        encodingContract.setRulesEngineAddress(address(red));
        encodingContract.setCallingContractAdmin(callingContractAdmin);
        address encodingContractAddress = address(encodingContract);

        // create new uint array for transfer data
        bytes[] memory array = new bytes[](5);
        array[0] = bytes("super");
        array[1] = bytes("superduper");
        array[2] = bytes("superduperduper");
        array[3] = bytes("superduperduperduper");
        array[4] = bytes("superduperduperduperduper");

        encodingContract.writeNewDynamicArrayData(array);

        // create rule that will handle additional params
        Rule memory rule;
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();
        // Set up some effects.
        _setupEffectProcessor();

        /// Build the calling Function to include additional pTypes to match the data being passed in
        ParamTypes[] memory pTypes = new ParamTypes[](4);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.STATIC_TYPE_ARRAY;
        pTypes[3] = ParamTypes.ADDR;

        rule.instructionSet = new uint256[](7);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 2;
        rule.instructionSet[2] = uint(LogicalOp.NUM);
        rule.instructionSet[3] = uint256(3); // uint length of array to test that rule retreives uint array length correctly
        rule.instructionSet[4] = uint(LogicalOp.EQ);
        rule.instructionSet[5] = 0;
        rule.instructionSet[6] = 1;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.ADDR;
        rule.placeHolders[0].typeSpecificIndex = 0; // to address
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].typeSpecificIndex = 1; // amount
        rule.placeHolders[2].pType = ParamTypes.DYNAMIC_TYPE_ARRAY;
        rule.placeHolders[2].typeSpecificIndex = 2; // additional bytes32 param

        // Add a negative/positive effects
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.posEffects = new Effect[](1);
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);
        // Save the calling Function
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes(callingFunctionArrayDynamic)))),
            pTypes,
            callingFunctionArrayDynamic,
            ""
        );

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes(callingFunctionArrayDynamic))));
        callingFunctionIds.push(callingFunctionId);
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            callingFunctionIds,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );
        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(encodingContractAddress, policyIds);
        // test rule processing
        vm.expectRevert(abi.encodePacked(revert_text));
        encodingContract.transferDynamicArray(address(0x1234567), 99);
    }

    function testRulesEngine_Unit_Calling_Function_Validate_Name_Negative() public {
        uint256[] memory policyIds = new uint256[](1);
        ParamTypes[] memory pTypes = new ParamTypes[](6);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        pTypes[3] = ParamTypes.UINT;
        pTypes[4] = ParamTypes.UINT;
        pTypes[5] = ParamTypes.UINT;
        policyIds[0] = _createBlankPolicy();
        vm.expectRevert(abi.encodePacked(NAME_REQ));
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(keccak256(bytes("transfer()"))),
            pTypes,
            "",//name
            "address,uint256"
        );
    }

    function testRulesEngine_Unit_Calling_Function_Validate_Signature_Negative() public {
        uint256[] memory policyIds = new uint256[](1);
        ParamTypes[] memory pTypes = new ParamTypes[](1);
        pTypes[0] = ParamTypes.ADDR;
        policyIds[0] = _createBlankPolicy();
        vm.expectRevert(abi.encodePacked(SIG_REQ));
        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(keccak256(bytes(""))),// function signature
            pTypes,
            "transfer(address,uint256)",
            "address,uint256"
        );
    }
    

    function testRulesEngine_Unit_PauseRuleRecreation() public ifDeploymentTestsEnabled resetsGlobalVariables {
        exampleERC20 = new ExampleERC20("Token Name", "SYMB");
        exampleERC20.mint(callingContractAdmin, 1_000_000 * ATTO);
        exampleERC20.setRulesEngineAddress(address(red));
        exampleERC20.setCallingContractAdmin(callingContractAdmin);
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();

        ParamTypes[] memory pTypes = new ParamTypes[](6);
        pTypes[0] = ParamTypes.ADDR;
        pTypes[1] = ParamTypes.UINT;
        pTypes[2] = ParamTypes.ADDR;
        pTypes[3] = ParamTypes.UINT;
        pTypes[4] = ParamTypes.UINT;
        pTypes[5] = ParamTypes.UINT;

        uint256 callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
            policyIds[0],
            bytes4(bytes4(keccak256(bytes("transfer(address,uint256)")))),
            pTypes,
            "transfer(address,uint256)",
            "address,uint256"
        );
        // Save the Policy
        callingFunctions.push(bytes4(keccak256(bytes("transfer(address,uint256)"))));
        callingFunctionIds.push(callingFunctionId);
        uint256[][] memory blankRuleIds = new uint256[][](0);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            callingFunctions,
            callingFunctionIds,
            blankRuleIds,
            PolicyType.CLOSED_POLICY,
            policyName,
            policyDescription
        );

        // Rule:uintTracker BlockTime > currentBlockTime -> revert -> transfer(address _to, uint256 amount) returns (bool)
        Rule memory rule;
        rule.negEffects = new Effect[](1);
        rule.negEffects[0] = effectId_revert;
        rule.instructionSet = new uint256[](15);
        rule.instructionSet[0] = uint(LogicalOp.PLH);
        rule.instructionSet[1] = 0; //r0 tracker 1
        rule.instructionSet[2] = uint(LogicalOp.PLH);
        rule.instructionSet[3] = 2; //r1 blocktime
        rule.instructionSet[4] = uint(LogicalOp.LT);
        rule.instructionSet[5] = 1;
        rule.instructionSet[6] = 0; //r2 check that blocktime is less than tracker 1
        rule.instructionSet[7] = uint(LogicalOp.PLH);
        rule.instructionSet[8] = 1; //r3 second tracker
        rule.instructionSet[9] = uint(LogicalOp.GT);
        rule.instructionSet[10] = 1; // use register 1
        rule.instructionSet[11] = 3; //r4 check that blocktime is greater than second tracker
        rule.instructionSet[12] = uint(LogicalOp.OR);
        rule.instructionSet[13] = 2;
        rule.instructionSet[14] = 4;

        rule.placeHolders = new Placeholder[](3);
        rule.placeHolders[0].pType = ParamTypes.UINT;
        rule.placeHolders[0].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[0].typeSpecificIndex = 1;
        rule.placeHolders[1].pType = ParamTypes.UINT;
        rule.placeHolders[1].flags = FLAG_TRACKER_VALUE;
        rule.placeHolders[1].typeSpecificIndex = 2;
        rule.placeHolders[2].pType = ParamTypes.UINT;
        rule.placeHolders[2].typeSpecificIndex = 5;

        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        //build tracker
        Trackers memory tracker;
        /// build the members of the struct:
        tracker.pType = ParamTypes.UINT;
        tracker.trackerValue = abi.encode(1000000000);
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker, "trName");

        //build second tracker
        Trackers memory tracker2;
        /// build the members of the struct:
        tracker2.pType = ParamTypes.UINT;
        tracker2.trackerValue = abi.encode(2000000000);
        RulesEngineComponentFacet(address(red)).createTracker(policyIds[0], tracker2, "trName");

        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);

        vm.stopPrank();
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(address(exampleERC20), policyIds);
        vm.warp(1000000001);
        vm.expectRevert();
        exampleERC20.transfer(address(0x7654321), 3);
        //warp out of pause window
        vm.warp(2000000001);
        vm.startSnapshotGas("PauseRuleRecreation");
        bool response = exampleERC20.transfer(address(0x7654321), 7);
        vm.stopSnapshotGas();
        assertTrue(response);
    }
}
