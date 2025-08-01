/// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

// validation tests
import "test/validation/adminRoles/adminRoles.t.sol";
import "test/validation/adminRoles/adminRolesFuzz.t.sol";
import "test/validation/components/components.t.sol";
import "test/validation/rules/rules.t.sol";
import "test/validation/rules/rulesFuzz.t.sol";
import "test/validation/policy/policies.t.sol";
// execution tests
import "test/execution/diamondInternalFunctions/diamondInternalFunctions.t.sol";
import "test/execution/rulesEngineInternalFunctions/rulesEngineInternalFunctions.t.sol";
import "test/execution/effects/rulesEngineEffects.t.sol";
import "test/execution/runFunction/runFunction.t.sol";
import "test/execution/rulesExecution/rulesExecution.t.sol";
import "test/execution/instructionSet/instructionSet.t.sol";
import "test/execution/foreignCalls/foreignCalls.t.sol";
import "test/execution/trackers/trackers.t.sol";
import "test/execution/storage/storage.t.sol";

contract RulesEngineUnitTests is
    adminRoles,
    adminRolesFuzz,
    components,
    rules,
    rulesFuzz,
    policies,
    diamondInternalFunctions,
    rulesEngineInternalFunctions,
    effects,
    runFunction,
    rulesExecution,
    instructionSet,
    foreignCalls,
    trackers,
    storageTest
{
    function setUp() public {
        // Start test as the policyAdmin account
        vm.startPrank(policyAdmin);
        // Deploy Rules Engine Diamond
        red = createRulesEngineDiamond(address(0xB0b));
        // Create and connect user contract to Rules Engine
        userContract = new ExampleUserContract();
        userContractAddress = address(userContract);
        userContract.setRulesEngineAddress(address(red));
        userContract.setCallingContractAdmin(callingContractAdmin);
        // create internal user contract
        userContractInternal = new ExampleUserContract();
        // create foreign call test contract
        testContract = new ForeignCallTestContract();
        // create and connect second user contract to Rules Engine
        newUserContract = new ExampleUserContract();
        newUserContractAddress = address(newUserContract);
        newUserContract.setRulesEngineAddress(address(red));

        //create permissioned foreign call test contract and set address
        permissionedForeignCallContract = new PermissionedForeignCallTestContract();
        permissionedForeignCallContract.setRulesEngineAddress(address(red));
        pfcContractAddress = address(permissionedForeignCallContract);

        _setupEffectProcessor();
    }
}
