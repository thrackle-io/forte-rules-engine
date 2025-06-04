/// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetCommonImports.sol";
import "src/engine/facets/AdminRoles.sol";
import "@openzeppelin/access/extensions/AccessControlEnumerable.sol"; 
import "@openzeppelin/access/IAccessControl.sol";
import "@openzeppelin/access/Ownable.sol";
import "@openzeppelin/utils/ReentrancyGuard.sol";

/**
 * @title Rules Engine Admin Roles Facet
 * @dev This contract serves as the primary Admin Roles facet for the Rules Engine. It is responsible for managing, mutating, 
 *      and granting all admin roles, including policy and calling contract admin roles. It enforces role-based access control 
 *      and ensures proper role assignment and revocation. The contract also provides mechanisms for proposing and confirming 
 *      new admin roles.
 * @notice This contract is a critical component of the Rules Engine, enabling secure and flexible role management.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract RulesEngineAdminRolesFacet is AccessControlEnumerable, ReentrancyGuard {
    
    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Policy Admin Functions 
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Checks if an address is the policy admin for a specific policy ID.
     * @param policyId The ID of the policy.
     * @param account The address to check for the policy admin role.
     * @return bool True if the address has the policy admin role, false otherwise.
     */
    function isPolicyAdmin(uint256 policyId, address account) public view returns (bool) { 
        return hasRole(_generatePolicyAdminRoleId(policyId, POLICY_ADMIN), account);
    }

    /**
     * @notice Generates and assigns a policy admin role to an address.
     * @dev This function is called internally by the Rules Engine to assign the policy admin role.
     * @param policyId The ID of the policy.
     * @param account The address to assign the policy admin role.
     * @return bytes32 The generated admin role identifier.
     */
    function generatePolicyAdminRole(uint256 policyId, address account) public nonReentrant returns (bytes32) {
        if(msg.sender != address(this)) revert(RULES_ENGINE_ONLY);
        // Create Admin Role for Policy: concat the policyId and adminRole key together and keccak them. Cast to bytes32 for Admin Role identifier 
        bytes32 adminRoleId = _generatePolicyAdminRoleId(policyId, POLICY_ADMIN);  
        // grant the admin role to the calling address of the createPolicy function from RulesEnginePolicyFacet 
        _grantRolePolicyAdmin(adminRoleId, account); 
        emit PolicyAdminRoleGranted(account, policyId); 
        return adminRoleId;
    }

    /**
     * @notice Proposes a new policy admin for a specific policy.
     * @param newPolicyAdmin The address of the proposed new policy admin.
     * @param policyId The ID of the policy.
     */
    function proposeNewPolicyAdmin(address newPolicyAdmin, uint256 policyId) public {
        if(!isPolicyAdmin(policyId, msg.sender)) revert(NOT_POLICY_ADMIN); 
        if (newPolicyAdmin == address(0)) revert(ZERO_ADDRESS);
        // grant proposed role to new admin address 
        _grantRole(_generatePolicyAdminRoleId(policyId, PROPOSED_POLICY_ADMIN), newPolicyAdmin);
        emit PolicyAdminRoleProposed(newPolicyAdmin, policyId);
    }

    /**
     * @notice Confirms the proposed policy admin for a specific policy.
     * @param policyId The ID of the policy.
     */
    function confirmNewPolicyAdmin(uint256 policyId) public { 
        address oldPolicyAdmin = getRoleMember(_generatePolicyAdminRoleId(policyId, POLICY_ADMIN), 0);
        if (!hasRole(_generatePolicyAdminRoleId(policyId, PROPOSED_POLICY_ADMIN), msg.sender)) revert(NOT_PROPOSED_POLICY_ADMIN); 
        _revokeRole(_generatePolicyAdminRoleId(policyId, PROPOSED_POLICY_ADMIN), msg.sender);
        _revokeRole(_generatePolicyAdminRoleId(policyId, POLICY_ADMIN), oldPolicyAdmin);
        _grantRole(_generatePolicyAdminRoleId(policyId, POLICY_ADMIN), msg.sender); 
        emit PolicyAdminRoleConfirmed(msg.sender, policyId);
    }

    /**
     * @dev This function is used to renounce Role. It is also preventing policyAdmins from renouncing ther role.
     * They must set another policyAdmin through the function proposeNewPolicyAdmin().
     * @param role the role to renounce.
     * @param account address renouncing to the role.
     */
    function renounceRole(bytes32 role, address account, uint256 policyId) public nonReentrant {
        /// enforcing the min-1-admin requirement.
        if (isPolicyAdmin(policyId, account)) revert(BELOW_ADMIN_THRESHOLD);
        AccessControl.renounceRole(role, account);
        emit PolicyAdminRoleRenounced(account, policyId);
    }

    /**
     * @dev This function overrides the parent's revokeRole function. Its purpose is to prevent Policy Admins from being revoked through
     * this "backdoor" which would effectively leave the policy in a Policy Admin-orphan state.
     * @param role the role to revoke.
     * @param account address of revoked role.
     */
    function revokeRole(bytes32 role, address account, uint256 policyId) public nonReentrant { 
        /// enforcing the min-1-admin requirement for policy admins.
        // This function should never be hit by Policy admins. This function is intended for other admin roles. 
        if (isPolicyAdmin(policyId, account)) revert(BELOW_ADMIN_THRESHOLD);
        // slither-disable-next-line reentrancy-events
        AccessControl.revokeRole(role, account);
        emit PolicyAdminRoleRevoked(account, policyId); 
    }

    /**
     * @notice Grants a policy admin role to an address.
     * @dev Internal function to assign the policy admin role.
     * @param _role The admin role identifier.
     * @param _account The address to be granted the role.
     */
    function _grantRolePolicyAdmin(bytes32 _role, address _account) internal {
        if (_account == address(0)) revert(ZERO_ADDRESS); 
        if (hasRole(_role, _account)) revert(POLICY_ADMIN_ALREADY_CREATED);
        // internal function of Access Control used here so we do not have to set RulesEngineAddress as the base admin for Policy Admins 
        _grantRole(_role, _account); 
    }

    /**
     * @notice Generates a unique identifier for a policy admin role.
     * @param _policyId The ID of the policy.
     * @param _adminRole The role constant identifier.
     * @return bytes32 The generated admin role identifier.
     */
    function _generatePolicyAdminRoleId(uint256 _policyId, bytes32 _adminRole) internal pure returns(bytes32) {
        // Create Admin Role for Policy: concat the policyId and adminRole strings together and keccak them. Cast to bytes32 for Admin Role identifier 
        return bytes32(abi.encodePacked(keccak256(bytes(string.concat(string(abi.encode(_policyId)), string(abi.encode(_adminRole)))))));
    }


    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Calling Contract Admin Functions
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

     /**
     * @notice Checks if an address is the calling contract admin for a specific contract.
     * @param _callingContract The address of the calling contract.
     * @param _account The address to check for the calling contract admin role.
     * @return bool True if the address has the calling contract admin role, false otherwise.
     */
    function isCallingContractAdmin(address _callingContract, address _account) public view returns (bool) { 
        return hasRole(_generateCallingContractAdminRoleId(_callingContract, CALLING_CONTRACT_ADMIN), _account);
    }

    /**
     * @notice Grants the calling contract admin role to an address.
     * @dev Call this function from your contract to set the calling contract admin.
     * @param _callingContract The address of the calling contract.
     * @param _account The address to assign the calling contract admin role.
     * @return bytes32 The generated admin role identifier.
     */
    function grantCallingContractRole(address _callingContract, address _account) public nonReentrant returns (bytes32) {
        if (_account == address(0)) revert(ZERO_ADDRESS);  
        if(msg.sender != _callingContract) revert(ONLY_CALLING_CONTRACT);
        // Create Admin Role for Calling Contract Role: concat the calling contract address and adminRole key together and keccak them. Cast to bytes32 for Admin Role identifier 
        bytes32 adminRoleId = _generateCallingContractAdminRoleId(_callingContract, CALLING_CONTRACT_ADMIN); 
        if (hasRole(adminRoleId, _account)) revert(CALLING_CONTRACT_ADMIN_ROLE_ALREADY_GRANTED);
        // grant the admin role to the calling address of the createPolicy function from RulesEnginePolicyFacet 
        _grantRole(adminRoleId, _account); 
        emit CallingContractAdminRoleGranted(_callingContract, _account); 
        return adminRoleId;
    }

    /**
     * @dev Function to grant calling contract admin role 
     * @dev Call this function when you are the calling contract admin of your contract
     * @param _callingContract policy Id 
     * @param _account address to assign admin role Id 
     * @return bytes32 adminRoleId 
     */
    function grantCallingContractRoleAccessControl(address _callingContract, address _account) public nonReentrant returns (bytes32) {
        if (_account == address(0)) revert(ZERO_ADDRESS); 
        // check that msg.sender has approved role 
        if (!IAccessControl(_callingContract).hasRole(CALLING_CONTRACT_ADMIN, msg.sender)) revert(CALLING_CONTRACT_ADMIN_ROLE_NOT_GRANTED_ACCESS_CONTROL);
        // Create Admin Role for Calling Contract Role: concat the calling contract address and adminRole key together and keccak them. Cast to bytes32 for Admin Role identifier 
        bytes32 adminRoleId = _generateCallingContractAdminRoleId(_callingContract, CALLING_CONTRACT_ADMIN); 
        if (hasRole(adminRoleId, _account)) revert(CALLING_CONTRACT_ADMIN_ROLE_ALREADY_GRANTED);
        // grant the admin role to the calling address of the createPolicy function from RulesEnginePolicyFacet 
        _grantRole(adminRoleId, _account); 
        emit CallingContractAdminRoleGranted(_callingContract, _account); 
        return adminRoleId;
    }

    /**
     * @notice Grants the calling contract admin role to an address.
     * @dev Call this function from your contract to set the calling contract admin.
     * @param _callingContract The address of the calling contract.
     * @param _account The address to assign the calling contract admin role.
     * @return bytes32 The generated admin role identifier.
     */
    function grantCallingContractRoleOwnable(address _callingContract, address _account) public nonReentrant returns (bytes32) {
        // Create Admin Role for Calling Contract Role: concat the calling contract address and adminRole key together and keccak them. Cast to bytes32 for Admin Role identifier 
        bytes32 adminRoleId = _generateCallingContractAdminRoleId(_callingContract, CALLING_CONTRACT_ADMIN); 
        if (_account == address(0)) revert(ZERO_ADDRESS); 
        // check that msg.sender is owner of calling contract  
        if (msg.sender != Ownable(_callingContract).owner()) revert(CALLING_CONTRACT_ADMIN_ROLE_NOT_GRANTED_ACCESS_CONTROL);
        if (hasRole(adminRoleId, _account)) revert(CALLING_CONTRACT_ADMIN_ROLE_ALREADY_GRANTED);
        // grant the admin role to the calling address of the createPolicy function from RulesEnginePolicyFacet 
        _grantRole(adminRoleId, _account); 
        emit CallingContractAdminRoleGranted(_callingContract, _account);  
        return adminRoleId;
    }

    /**
     * @dev This function grants the proposed admin role to the newPolicyAdmin address 
     * @dev Calling Contract Admin does not have a revoke or renounce function. Only Use Propose and Confirm to transfer Role. 
     * @notice There can only ever be one Calling Contract Admin per calling contract 
     * @param callingContractAddress address of the calling contract.
     * @param newCallingContractAdmin address of new admin.
     */
    function proposeNewCallingContractAdmin(address callingContractAddress, address newCallingContractAdmin) public {
        if(!isCallingContractAdmin(callingContractAddress, msg.sender)) revert(NOT_CALLING_CONTRACT_ADMIN); 
        if (newCallingContractAdmin == address(0)) revert(ZERO_ADDRESS);
        // grant proposed role to new admin address 
        _grantRole(_generateCallingContractAdminRoleId(callingContractAddress, PROPOSED_CALLING_CONTRACT_ADMIN), newCallingContractAdmin);
        emit CallingContractAdminRoleProposed(callingContractAddress, newCallingContractAdmin);  
    }

    /**
     * @dev This function confirms the proposed admin role
     * @param callingContractAddress address of the calling contract.
     */
    function confirmNewCallingContractAdmin(address callingContractAddress) public { 
        address oldCallingContractAdmin = getRoleMember(_generateCallingContractAdminRoleId(callingContractAddress, CALLING_CONTRACT_ADMIN), 0);
        if (!hasRole(_generateCallingContractAdminRoleId(callingContractAddress, PROPOSED_CALLING_CONTRACT_ADMIN), msg.sender)) revert(NOT_PROPOSED_CALLING_CONTRACT_ADMIN); 
        _revokeRole(_generateCallingContractAdminRoleId(callingContractAddress, PROPOSED_CALLING_CONTRACT_ADMIN), msg.sender);
        _revokeRole(_generateCallingContractAdminRoleId(callingContractAddress, CALLING_CONTRACT_ADMIN), oldCallingContractAdmin);
        _grantRole(_generateCallingContractAdminRoleId(callingContractAddress, CALLING_CONTRACT_ADMIN), msg.sender); 
        emit CallingContractAdminRoleConfirmed(callingContractAddress, msg.sender);  
    }

   /**
     * @notice Generates a unique identifier for a calling contract admin role.
     * @param _callingContract The address of the calling contract.
     * @param _adminRole The role constant identifier.
     * @return bytes32 The generated admin role identifier.
     */
    function _generateCallingContractAdminRoleId(address _callingContract, bytes32 _adminRole) internal pure returns(bytes32) {
        // Create Admin Role for Policy: concat the policyId and adminRole strings together and keccak them. Cast to bytes32 for Admin Role identifier 
        return bytes32(abi.encodePacked(keccak256(bytes(string.concat(string(abi.encode(_callingContract)), string(abi.encode(_adminRole)))))));
    }

    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Overridden Functions
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

   /**
     * @notice Overrides the parent's `renounceRole` function to disable its public nature.
     * @dev This function is intentionally disabled to enforce role renouncing through specific channels.
     * @param role The role to renounce.
     * @param account The address renouncing the role.
     */
    function renounceRole(bytes32 role, address account ) public virtual override(AccessControl, IAccessControl) {
        role;
        account;
        revert("Function disabled");
    }

    /**
     * @notice Overrides the parent's `revokeRole` function to disable its public nature.
     * @dev This function is intentionally disabled to enforce role revocation through specific channels.
     * @param role The role to revoke.
     * @param account The address of the revoked role.
     */
    function revokeRole(bytes32 role, address account) public virtual override(AccessControl, IAccessControl) {
        role;
        account;
        revert("Function disabled");
    }

    /**
     * @notice Overrides the parent's `grantRole` function to disable its public nature.
     * @dev This function is intentionally disabled to enforce role granting through specific channels.
     * @param role The role to grant.
     * @param account The address to grant the role to.
     */
    function grantRole(bytes32 role, address account) public pure override(AccessControl, IAccessControl) {
        /// this is done to funnel all the role granting functions through this contract since
        /// the policyAdmins could add other policyAdmins through this back door
        role;
        account;
        revert("Function disabled");
    }
}
