// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Test} from "forge-std/src/Test.sol";
import {console} from "forge-std/src/console.sol";
import {StdInvariant} from "forge-std/src/StdInvariant.sol";
import "test/utils/RulesEngineCommon.t.sol";
import "test/clientContractExamples/ExampleUserContract.sol";

contract RulesEngineAdminRolesTest is RulesEngineCommon, RulesEngineAdminRolesFacet{
    
    uint256 public testPolicyId;
    address public testUserContract;
    uint256 public proposedPolicyAdminsCount;
    uint256 public successfulPolicyAdminTransfers;
    uint256 public proposedCallingContractAdminsCount;
    uint256 public successfulCallingContractAdminTransfers;
    uint256 public unauthorizedActionAttempts;
    uint256 public proposedAdminAttempts;
    uint256 public proposedAdminSuccesses;
    uint256 public unauthorizedSuccessfulProposals;
    
    // Each property test will ensure this is set to true before running
    // This is a workaround for setUp() not being able to be called in property tests
    bool public ensuredSetup;
    
    modifier ensureInitialized() {
        if (!ensuredSetup) {
            _initializeForPropertyTesting();
            ensuredSetup = true;
        }
        _;
    }
    
    function _initializeForPropertyTesting() internal {
        if (ensuredSetup) return;
        
        // Initialize RulesEngine and policy if needed
        if (address(red) == address(0)) {
            red = createRulesEngineDiamondNoCheatcodes(address(this));
        }
        
        if (testPolicyId == 0) {
            testPolicyId = RulesEnginePolicyFacet(address(red)).createPolicy(PolicyType.CLOSED_POLICY);
        }
        
        if (testUserContract == address(0)) {
            testUserContract = address(new ExampleUserContract());
            ExampleUserContract(testUserContract).setRulesEngineAddress(address(red));
            ExampleUserContract(testUserContract).setCallingContractAdmin(address(this));
        }
    }

    /*//////////////////////////////////////////////////////////////
                        GENERIC INVARIANTS
    //////////////////////////////////////////////////////////////*/

    // PROPERTY: Admin transfers are correctly tracked and completed
    function property_AdminTransfersCorrectlyTracked() public ensureInitialized returns (bool) {
        // Policy admin transfers
        bytes32 adminRoleId = _generatePolicyAdminRoleId(testPolicyId, POLICY_ADMIN);
        uint256 adminCount = RulesEngineAdminRolesFacet(address(red)).getRoleMemberCount(adminRoleId);
    
        // Calling contract admin transfers
        bytes32 ccAdminRoleId = _generateCallingContractAdminRoleId(testUserContract, CALLING_CONTRACT_ADMIN);
        uint256 ccAdminCount = RulesEngineAdminRolesFacet(address(red)).getRoleMemberCount(ccAdminRoleId);
    
        // If we've had admin transfers, the counts should be consistent
        if (successfulPolicyAdminTransfers > 0 || successfulCallingContractAdminTransfers > 0) {
            // There should be at least 1 admin if transfers happened
            return (adminCount > 0 && ccAdminCount > 0);
        }
    
        return true;
    }

    // PROPERTY: Admin transfer sequence maintains integrity
    function property_AdminTransferSequenceIntegrity() public ensureInitialized returns (bool) {
        // For policy admins: proposals should always be >= successful transfers
        if (proposedPolicyAdminsCount < successfulPolicyAdminTransfers) {
            return false;
        }
    
        // For calling contract admins: proposals should always be >= successful transfers
        if (proposedCallingContractAdminsCount < successfulCallingContractAdminTransfers) {
            return false;
        }
    
        return true;
    }
    
    /*//////////////////////////////////////////////////////////////
                        POLICY ADMIN INVARIANTS
    //////////////////////////////////////////////////////////////*/

    // PROPERTY: Policy must have one admin
    function property_PolicyHasOneAdmin() public ensureInitialized returns (bool) {
        bytes32 adminRoleId = _generatePolicyAdminRoleId(testPolicyId, POLICY_ADMIN);
        uint256 adminCount = RulesEngineAdminRolesFacet(address(red)).getRoleMemberCount(adminRoleId);
        return adminCount == 1;
    }
    
    // PROPERTY: Only the current admin can propose a new admin
    function property_OnlyCurrentAdminCanProposeNewAdmin() public ensureInitialized returns (bool) {
        // If we've attempted unauthorized actions but succeeded in fewer proposals than attempts,
        // then the property holds (unauthorized attempts failed)
        if (unauthorizedActionAttempts > 0) {
            return proposedPolicyAdminsCount < unauthorizedActionAttempts;
        }
        
        // If no unauthorized attempts have been made, property holds by default
        return true;
    }
    
    // PROPERTY: Proposed admin can't act as admin until confirmed
    function property_ProposedAdminCannotActUntilConfirmed() public ensureInitialized returns (bool) {
        // No address should have both roles simultaneously
        bytes32 adminRoleId = _generatePolicyAdminRoleId(testPolicyId, POLICY_ADMIN);
        bytes32 proposedAdminRoleId = _generatePolicyAdminRoleId(testPolicyId, PROPOSED_POLICY_ADMIN);
    
        uint256 proposedCount = RulesEngineAdminRolesFacet(address(red)).getRoleMemberCount(proposedAdminRoleId);
    
        for (uint256 i = 0; i < proposedCount; i++) {
            address proposed = RulesEngineAdminRolesFacet(address(red)).getRoleMember(proposedAdminRoleId, i);
        
            if (RulesEngineAdminRolesFacet(address(red)).hasRole(adminRoleId, proposed)) {
                return false;  // Violation: address has both roles
            }
        }
    
        // Proposed admins should never succeed in admin actions
        if (proposedAdminAttempts > 0) {
            return proposedAdminSuccesses == 0;  // Property holds only if no successes
        }
    
        return true;
    }
    
    // PROPERTY: Zero address is never an admin
    function property_ZeroAddressIsNeverAdmin() public ensureInitialized returns (bool) {
        _generatePolicyAdminRoleId(testPolicyId, POLICY_ADMIN);
        // False is expected on this call, will cause the property to fail without the bang
        return !RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(testPolicyId, address(0));
    }

    /*//////////////////////////////////////////////////////////////
                  CALLING CONTRACT ADMIN INVARIANTS
    //////////////////////////////////////////////////////////////*/
    
    // PROPERTY: Only the current calling contract admin can propose a new admin
    function property_OnlyCurrentCallingContractAdminCanProposeNewAdmin() public ensureInitialized returns (bool) {
        // If we've had unauthorized attempts, check that none succeeded
        if (unauthorizedActionAttempts > 0 || unauthorizedSuccessfulProposals > 0) {
            // Property holds if no unauthorized proposals succeeded AND
            // The number of successful proposals matches our counter
            bytes32 proposedRoleId = _generateCallingContractAdminRoleId(testUserContract, PROPOSED_CALLING_CONTRACT_ADMIN);
            uint256 actualProposedCount = RulesEngineAdminRolesFacet(address(red)).getRoleMemberCount(proposedRoleId);
        
            return unauthorizedSuccessfulProposals == 0 && proposedCallingContractAdminsCount == actualProposedCount;
        }
        // If no unauthorized attempts yet, property holds
        return true;
    }
    
    // PROPERTY: Calling contract can have at most one admin
    function property_CallingContractHasOneAdmin() public ensureInitialized returns (bool) {
        bytes32 adminRoleId = _generateCallingContractAdminRoleId(
            testUserContract, 
            CALLING_CONTRACT_ADMIN
        );
        
        uint256 adminCount = RulesEngineAdminRolesFacet(address(red)).getRoleMemberCount(adminRoleId);
        return adminCount == 1;
    }
    
    // PROPERTY: Proposed calling contract admin can't act until confirmed
    function property_ProposedCallingContractAdminCannotActUntilConfirmed() public ensureInitialized returns (bool) {
        
        bytes32 adminRoleId = _generateCallingContractAdminRoleId(testUserContract, CALLING_CONTRACT_ADMIN);
        bytes32 proposedAdminRoleId = _generateCallingContractAdminRoleId(testUserContract, PROPOSED_CALLING_CONTRACT_ADMIN);
        
        uint256 proposedCount = RulesEngineAdminRolesFacet(address(red)).getRoleMemberCount(proposedAdminRoleId);
        
        for (uint256 i = 0; i < proposedCount; i++) {
            address proposed = RulesEngineAdminRolesFacet(address(red)).getRoleMember(proposedAdminRoleId, i);
            
            if (RulesEngineAdminRolesFacet(address(red)).hasRole(adminRoleId, proposed)) {
                return false;
            }
        }
        
        return true;
    }
    
    /*//////////////////////////////////////////////////////////////
                  MEDUSA SEQUENCE ACTIONS 
    //////////////////////////////////////////////////////////////*/
    
    function action_proposeNewPolicyAdmin(address sender, address newAdmin) public {
        if (newAdmin == address(0)) return;
    
        bool isCurrentAdmin = false;
        if(RulesEngineAdminRolesFacet(address(red)).isPolicyAdmin(testPolicyId, msg.sender)) {
            isCurrentAdmin = true;
        }
    
        // If needed to test different callers, only impersonate if caller is authorized
        if (isCurrentAdmin) {
            vm.startPrank(sender);
            try RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(newAdmin, testPolicyId) {
                proposedPolicyAdminsCount++;
            } catch {}
            vm.stopPrank();
        } else {
            // For unauthorized callers, don't impersonate
            try RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(newAdmin, testPolicyId) {
                console.log("INVARIANT VIOLATION: Non-admin successfully proposed new admin");
            } catch {
                unauthorizedActionAttempts++;
            }
        }
    }
    
    function action_confirmNewPolicyAdmin(address sender) public {
        
        // Check if sender is a proposed admin
        bytes32 proposedRoleId = _generatePolicyAdminRoleId(testPolicyId, PROPOSED_POLICY_ADMIN);
        
        bool isProposed = false;
        if(RulesEngineAdminRolesFacet(address(red)).hasRole(proposedRoleId, sender)) {
            isProposed = true;
        }
        
        if (!isProposed) return; // Skip if not proposed
        
        vm.startPrank(sender);
        try RulesEngineAdminRolesFacet(address(red)).confirmNewPolicyAdmin(testPolicyId) {
            // If successful, track the transfer
            successfulPolicyAdminTransfers++;
            
            // Verify property holds immediately after action
            bytes32 adminRoleId = _generatePolicyAdminRoleId(testPolicyId, POLICY_ADMIN);
            bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).hasRole(adminRoleId, sender);
            bool stillHasProposedRole = RulesEngineAdminRolesFacet(address(red)).hasRole(proposedRoleId, sender);
            
            if (hasAdminRole && stillHasProposedRole) {
                console.log("INVARIANT VIOLATION: Address has both proposed and admin roles");
            }
        } catch {}
        vm.stopPrank();
    }
    
    function action_confirmNewCallingContractAdmin(address sender) public {
        if (testUserContract == address(0)) return;
        
        // Check if sender is a proposed admin
        bytes32 proposedRoleId = _generateCallingContractAdminRoleId(
            testUserContract, 
            PROPOSED_CALLING_CONTRACT_ADMIN
        );
        
        bool isProposed = false;
        if(RulesEngineAdminRolesFacet(address(red)).hasRole(proposedRoleId, sender)) {
            isProposed = true;
        }
        
        if (!isProposed) return; // Skip if not proposed
        
        vm.startPrank(sender);
        try RulesEngineAdminRolesFacet(address(red)).confirmNewCallingContractAdmin(testUserContract) {
            // If successful, track the transfer
            successfulCallingContractAdminTransfers++;
            
            // Verify property holds immediately after action
            bytes32 adminRoleId = _generateCallingContractAdminRoleId(testUserContract, CALLING_CONTRACT_ADMIN);
            bool hasAdminRole = RulesEngineAdminRolesFacet(address(red)).hasRole(adminRoleId, sender);
            bool stillHasProposedRole = RulesEngineAdminRolesFacet(address(red)).hasRole(proposedRoleId, sender);
            
            if (hasAdminRole && stillHasProposedRole) {
                console.log("INVARIANT VIOLATION: Address has both proposed and admin roles");
            }
        } catch {}
        vm.stopPrank();
    }
    
    function action_attemptDirectRoleManagement(address sender, address target) public {
        if (target == address(0)) return;
        
        bytes32 adminRoleId = _generatePolicyAdminRoleId(testPolicyId, POLICY_ADMIN);
        
        vm.startPrank(sender);
        
        try RulesEngineAdminRolesFacet(address(red)).grantRole(adminRoleId, target) {
            console.log("INVARIANT VIOLATION: Direct role grant succeeded");
        } catch {
            // Direct grant failed as expected
        }
        
        try RulesEngineAdminRolesFacet(address(red)).revokeRole(adminRoleId, target) {
            console.log("INVARIANT VIOLATION: Direct role revoke succeeded");
        } catch {
            // Direct revoke failed as expected
        }
        
        try RulesEngineAdminRolesFacet(address(red)).renounceRole(adminRoleId, sender) {
            console.log("INVARIANT VIOLATION: Direct role renounce succeeded");
        } catch {
            // Direct renounce failed as expected
        }
        
        vm.stopPrank();
    }
    
    function action_proposedAdminTriesAdminAction(address sender) public {
        // Check if sender is a proposed admin but NOT an admin
        bytes32 adminRoleId = _generatePolicyAdminRoleId(testPolicyId, POLICY_ADMIN);
        bytes32 proposedRoleId = _generatePolicyAdminRoleId(testPolicyId, PROPOSED_POLICY_ADMIN);
    
        bool isProposed = false;
        bool isAdmin = false;
    
        try RulesEngineAdminRolesFacet(address(red)).hasRole(proposedRoleId, sender) returns (bool result) {
            isProposed = result;
        } catch {
            return;
        }
    
        try RulesEngineAdminRolesFacet(address(red)).hasRole(adminRoleId, sender) returns (bool result) {
            isAdmin = result;
        } catch {
            return;
        }
    
        // We only care about proposed admins who are not yet admins
        if (!isProposed || isAdmin) return;
    
        vm.startPrank(sender);
    
        // Try various admin actions
        proposedAdminAttempts++;
    
        // Try to cement the policy (admin-only action)
        try RulesEnginePolicyFacet(address(red)).cementPolicy(testPolicyId) {
            proposedAdminSuccesses++;
            console.log("INVARIANT VIOLATION: Proposed admin cemented policy");
        } catch {}
    
        // Try to propose another admin (admin-only action)
        try RulesEngineAdminRolesFacet(address(red)).proposeNewPolicyAdmin(address(0x123), testPolicyId) {
            proposedAdminSuccesses++;
            console.log("INVARIANT VIOLATION: Proposed admin proposed another admin");
        } catch {}
    
        vm.stopPrank();
    }

    function action_proposeNewCallingContractAdmin(address sender, address newAdmin) public {
        if (newAdmin == address(0) || testUserContract == address(0)) return;
    
        bool isCurrentAdmin = false;
        if(RulesEngineAdminRolesFacet(address(red)).isCallingContractAdmin(testUserContract,  msg.sender)) {
            isCurrentAdmin = true;
        }
    
        if (isCurrentAdmin) {
            // Only impersonate if the original caller is authorized
            vm.startPrank(sender);
            try RulesEngineAdminRolesFacet(address(red)).proposeNewCallingContractAdmin(testUserContract, newAdmin) {
                proposedCallingContractAdminsCount++;
            } catch {}
            vm.stopPrank();
        } else {
            // For unauthorized callers, don't impersonate - try directly
            try RulesEngineAdminRolesFacet(address(red)).proposeNewCallingContractAdmin(testUserContract, newAdmin) {
                // Track successful unauthorized proposal!
                unauthorizedSuccessfulProposals++;
                console.log("INVARIANT VIOLATION: Non-admin successfully proposed new calling contract admin");
            } catch {
                unauthorizedActionAttempts++;
            }
        }
    }
}
