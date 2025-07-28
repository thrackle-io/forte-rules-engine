/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "test/utils/RulesEngineCommon.t.sol";
import "src/example/ExampleERC721.sol";

contract NonCustodialMarketplaceTest is RulesEngineCommon {
    ExampleERC721 userContractFC;
    address marketplace = address(0x3a723491ace);
    string[3] tradeAddresses = ["from", "to", "operator"];
    mapping(string => uint) tradeAddressToIndex;

    function setUp() public {
        red = createRulesEngineDiamond(address(0xb0b));
        vm.startPrank(policyAdmin);
        userContractFC = new ExampleERC721("Token Name", "SYMB");
        userContractFC.safeMint(user1);
        userContractFC.setRulesEngineAddress(address(red));
        userContractFC.setCallingContractAdmin(callingContractAdmin);
        // 0: from,, 1: to,, 2: id,, 3: msg.sender
        /// @notice we ignore index 2 since we are not checking for the tokenId in the rule. We only check for the addresses involved in the trade:
        tradeAddressToIndex["from"] = 0;
        tradeAddressToIndex["to"] = 1;
        tradeAddressToIndex["operator"] = 3;
    }

    function test_nonCustodialMarketplace_allowlist(
        bool isBadMarketplace,
        bool isBadSender,
        bool isBadReciever,
        uint256 tradeAddressToCheckIndex
    ) public {
        testContract2 = new ForeignCallTestContractOFAC();
        vm.startPrank(policyAdmin);
        tradeAddressToCheckIndex = tradeAddressToCheckIndex % 3; // ensure the index is within bounds
        string memory tradeAddressToCheck = tradeAddresses[tradeAddressToCheckIndex]; // this will make sure that "tradeAddressToCheck" is either "from", "to", or "operator"
        _setupNaughtyListRuleForOperator(address(userContractFC), address(testContract2), tradeAddressToCheck); // we setup the rule with the fuzzed account to check
        if (isBadMarketplace) testContract2.addToNaughtyList(marketplace); // we fuzz if the marketplace is naughtylisted or not
        if (isBadSender) testContract2.addToNaughtyList(user1); // we fuzz if the sender is naughtylisted or not
        if (isBadReciever) testContract2.addToNaughtyList(address(0xdead)); // we fuzz if the recipient is naughtylisted or not
        uint tokenId = userContractFC.counter() - 1;
        // we simulate the non-custodial marketplace by simply transeferring the NFT throught the approval-for-all mechanism that they use
        vm.startPrank(user1);
        userContractFC.setApprovalForAll(marketplace, true);
        vm.startPrank(marketplace); // we start the prank as the marketplace to simulate the trade
        // we check that the transfer reverts depending on the fuzzed case
        bool willRevert = (isBadMarketplace && tradeAddressToCheckIndex == 2) || // we only expect a revert if the marketplace is a bad one and we are checking for the marketplace in the rule, or...
            (isBadSender && tradeAddressToCheckIndex == 0) || // ...if the sender is a bad one and we are checking for the sender in the rule, or...
            (isBadReciever && tradeAddressToCheckIndex == 1); // ...if the recipient is a bad one and we are checking for the recipient in the rule.
        if (willRevert) vm.expectRevert("Rules Engine Revert");
        userContractFC.transferFrom(user1, address(0xdead), tokenId); /// @notice the transfer here is executed by the marketplace and not the owner of the NFT
        /// we check that the transfer failed or happened correctly depending on the fuzzed case
        if (willRevert) {
            assertEq(userContractFC.ownerOf(0), user1, "The NFT should have stayed with the user1");
            assertEq(userContractFC.balanceOf(user1), 1, "balace of user1 should be 1");
            assertEq(userContractFC.balanceOf(address(0xdead)), 0, "balace of 0xdead should be 0");
        } else {
            assertEq(userContractFC.ownerOf(0), address(0xdead), "The NFT should have been transferred to the dead address");
            assertEq(userContractFC.balanceOf(address(0xdead)), 1, "balace of 0xdead should be 1");
            assertEq(userContractFC.balanceOf(user1), 0, "balace of user1 should be 0");
        }
    }

    function _setupNaughtyListRuleForOperator(
        address callingContract,
        address _contractAddress,
        string memory _tradeAddressToCheck // it can be either "from", "to", or "operator"
    ) public ifDeploymentTestsEnabled resetsGlobalVariables {
        // we create the policy
        uint256[] memory policyIds = new uint256[](1);
        policyIds[0] = _createBlankPolicy();

        // we create the foreign call to the naugthy list
        uint256 foreignCallId;
        {
            ParamTypes[] memory fcArgs = new ParamTypes[](1);
            fcArgs[0] = ParamTypes.ADDR;
            ForeignCall memory fc;
            fc.encodedIndices = new ForeignCallEncodedIndex[](1);
            fc.encodedIndices[0].index = tradeAddressToIndex[_tradeAddressToCheck];
            fc.encodedIndices[0].eType = EncodedIndexType.ENCODED_VALUES; // the from, to, and msg.sender are all part of the regular encoded values (calldata)
            fc.parameterTypes = fcArgs;
            fc.foreignCallAddress = _contractAddress;
            fc.signature = bytes4(keccak256(bytes("getNaughty(address)")));
            fc.returnType = ParamTypes.UINT;
            fc.foreignCallIndex = 1;
            foreignCallId = RulesEngineForeignCallFacet(address(red)).createForeignCall(policyIds[0], fc, "getNaughty(address)");
        }

        // we define the calling function that the policy will be attached to
        vm.startPrank(policyAdmin);
        uint256 callingFunctionId;
        {
            ParamTypes[] memory callingFunctionTypes = new ParamTypes[](3);
            callingFunctionTypes[0] = ParamTypes.ADDR; // from
            callingFunctionTypes[1] = ParamTypes.ADDR; // to
            callingFunctionTypes[2] = ParamTypes.UINT; // tokenId
            callingFunctionId = RulesEngineComponentFacet(address(red)).createCallingFunction(
                policyIds[0],
                bytes4(keccak256("transferFrom(address,address,uint256)")),
                callingFunctionTypes,
                "transferFrom(address,address,uint256)",
                ""
            );
        }

        // we then create the rule itself
        Rule memory rule;
        {
            // Build the foreign call placeholder
            rule.placeHolders = new Placeholder[](2);
            rule.placeHolders[0].flags = FLAG_FOREIGN_CALL;
            rule.placeHolders[0].typeSpecificIndex = uint128(foreignCallId);
            rule.placeHolders[1].pType = ParamTypes.UINT;
            rule.placeHolders[1].typeSpecificIndex = 1;

            // Build the instruction set for the rule (including placeholders)
            rule.instructionSet = new uint256[](7);
            rule.instructionSet[0] = uint(LogicalOp.PLH); // foreign call will return boolean that will be store at 0 address in memory
            rule.instructionSet[1] = 0;
            rule.instructionSet[2] = uint(LogicalOp.NUM); // we save zero at address 1 in memory
            rule.instructionSet[3] = 0;
            rule.instructionSet[4] = uint(LogicalOp.EQ); // we check that the foreign call returned false by checking equality between memory addresses 0 and 1
            rule.instructionSet[5] = 0;
            rule.instructionSet[6] = 1;

            // we set the negative effect as a simple revert
            rule.negEffects = new Effect[](1);
            rule.negEffects[0] = _createEffectRevert(revert_text);
        }
        // Save the rule
        uint256 ruleId = RulesEngineRuleFacet(address(red)).createRule(policyIds[0], rule, ruleName, ruleDescription);

        bytes4[] memory functions = new bytes4[](1);
        functions[0] = bytes4(keccak256("transferFrom(address,address,uint256)"));
        uint256[] memory functionIds = new uint256[](1);
        functionIds[0] = callingFunctionId;
        ruleIds.push(new uint256[](1));
        ruleIds[0][0] = ruleId;
        _addRuleIdsToPolicy(policyIds[0], ruleIds);
        RulesEnginePolicyFacet(address(red)).updatePolicy(
            policyIds[0],
            functions,
            functionIds,
            ruleIds,
            PolicyType.CLOSED_POLICY,
            "policyName",
            "policyDescription"
        );

        // finally, we apply the policy to the calling contract
        vm.startPrank(callingContractAdmin);
        RulesEnginePolicyFacet(address(red)).applyPolicy(callingContract, policyIds);
    }
}
