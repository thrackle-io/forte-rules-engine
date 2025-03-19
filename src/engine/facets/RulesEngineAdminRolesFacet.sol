// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "src/engine/facets/FacetCommonImports.sol";
import "src/engine/facets/AdminRoles.sol";
import "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol"; 
import "@openzeppelin/contracts/access/IAccessControl.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";



/**
 * @title Rules Engine Admin Roles Facet
 * @author @TJ-Everett
 * @dev This contract serves as the primary Admin Roles facet for the rules engine. It is responsible for mutating and granting all the admin roles.
 * @notice Admin Roles facet for the Rules Engine
 */

contract RulesEngineAdminRolesFacet is AccessControlEnumerable, ReentrancyGuard {
    
    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Policy Admin Functions 
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @dev View Function to determine if address is the policy admin for policy Id 
     * @param _policyId policy Id 
     * @param _account address to check for role  
     * @return bytes32 adminRoleId 
     */
    function isPolicyAdmin(uint256 _policyId, address _account) public view returns (bool) { 
        return hasRole(_generatePolicyAdminRoleId(_policyId, POLICY_ADMIN), _account);
    }

    /**
     * @dev Function to generate admin role identifier 
     * @param _policyId policy Id 
     * @param _account address to assign admin role Id 
     * @return bytes32 adminRoleId 
     */
    function generatePolicyAdminRole(uint256 _policyId, address _account) public nonReentrant returns (bytes32) {
        if (_account == address(0)) revert(ZERO_ADDRESS);  
        if(msg.sender != address(this)) revert(RULES_ENGINE_ONLY);
        // Create Admin Role for Policy: concat the policyId and adminRole key together and keccak them. Cast to bytes32 for Admin Role identifier 
        bytes32 adminRoleId = _generatePolicyAdminRoleId(_policyId, POLICY_ADMIN);  
        // grant the admin role to the calling address of the createPolicy function from RulesEnginePolicyFacet 
        _grantRolePolicyAdmin(adminRoleId, _account); 
        emit PolicyAdminRoleGranted(_account, _policyId); 
        return adminRoleId;
    }

    /**
     * @dev Function to grant admin role identifier 
     * @param _role bytes32 admin role to be assigned  
     * @param _account address to be granted role (this is msg.sender of the createPolicy function from RulesEnginePolicyFacet)
     */
    function _grantRolePolicyAdmin(bytes32 _role, address _account) internal {
        if (_account == address(0)) revert(ZERO_ADDRESS); 
        if (hasRole(_role, _account)) revert(POLICY_ADMIN_ALREADY_CREATED);
        // internal function of Access Control used here so we do not have to set RulesEngineAddress as the base admin for Policy Admins 
        _grantRole(_role, _account); 
    }


    /**
     * @dev This function grants the proposed admin role to the newPolicyAdmin address 
     * @param newPolicyAdmin new admin role.
     * @param policyId policy Id.
     */
    function proposeNewPolicyAdmin(address newPolicyAdmin, uint256 policyId) public {
        if(!isPolicyAdmin(policyId, msg.sender)) revert(NOT_POLICY_ADMIN); 
        if (newPolicyAdmin == address(0)) revert(ZERO_ADDRESS);
        // grant proposed role to new admin address 
        _grantRole(_generatePolicyAdminRoleId(policyId, PROPOSED_POLICY_ADMIN), newPolicyAdmin);
        emit PolicyAdminRoleProposed(newPolicyAdmin, policyId);
    }

    /**
     * @dev This function confirms the proposed admin role
     * @param policyId policy Id.
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
     * @dev Function to create the role identifier 
     * @param _policyId policy Id 
     * @param _adminRole The Role constant identifier  
     */
    function _generatePolicyAdminRoleId(uint256 _policyId, bytes32 _adminRole) internal pure returns(bytes32) {
        // Create Admin Role for Policy: concat the policyId and adminRole strings together and keccak them. Cast to bytes32 for Admin Role identifier 
        return bytes32(abi.encodePacked(keccak256(bytes(string.concat(string(abi.encode(_policyId)), string(abi.encode(_adminRole)))))));
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


    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Calling Contract Admin Functions
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @dev View Function to determine if address is the policy admin for policy Id 
     * @param _callingContract address of the calling contract  
     * @param _account address to check for role  
     * @return bytes32 adminRoleId 
     */
    function isCallingContractAdmin(address _callingContract, address _account) public view returns (bool) { 
        return hasRole(_generateCallingContractAdminRoleId(_callingContract, CALLING_CONTRACT_ADMIN), _account);
    }

    /**
     * @dev Function to grant calling contract admin role 
     * @dev Call this function from your contract to set calling contract admin 
     * @param _callingContract policy Id 
     * @param _account address to assign admin role Id 
     * @return bytes32 adminRoleId 
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
     * @dev Function to grant calling contract admin role 
     * @dev Call this function when Ownable from the Calling Contract 
     * @param _callingContract policy Id 
     * @param _account address to assign admin role Id 
     * @return bytes32 adminRoleId 
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
     * @dev Function to create the role identifier 
     * @param _callingContract calling contract address
     * @param _adminRole The Role constant identifier  
     */
    function _generateCallingContractAdminRoleId(address _callingContract, bytes32 _adminRole) internal pure returns(bytes32) {
        // Create Admin Role for Policy: concat the policyId and adminRole strings together and keccak them. Cast to bytes32 for Admin Role identifier 
        return bytes32(abi.encodePacked(keccak256(bytes(string.concat(string(abi.encode(_callingContract)), string(abi.encode(_adminRole)))))));
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
        address oldPolicyAdmin = getRoleMember(_generateCallingContractAdminRoleId(callingContractAddress, CALLING_CONTRACT_ADMIN), 0);
        if (!hasRole(_generateCallingContractAdminRoleId(callingContractAddress, PROPOSED_CALLING_CONTRACT_ADMIN), msg.sender)) revert(NOT_PROPOSED_CALLING_CONTRACT_ADMIN); 
        _revokeRole(_generateCallingContractAdminRoleId(callingContractAddress, PROPOSED_CALLING_CONTRACT_ADMIN), msg.sender);
        _revokeRole(_generateCallingContractAdminRoleId(callingContractAddress, CALLING_CONTRACT_ADMIN), oldPolicyAdmin);
        _grantRole(_generateCallingContractAdminRoleId(callingContractAddress, CALLING_CONTRACT_ADMIN), msg.sender); 
        emit CallingContractAdminRoleConfirmed(callingContractAddress, msg.sender);  
    }

    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Overridden functions Functions
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @dev This function overrides the parent's grantRole function. This disables its public nature to make it private.
     * @param role the role to grant to an acount.
     * @param account address being granted the role.
     * @notice This is purposely going to fail every time it will be invoked in order to force users to only use the appropiate
     * channels to grant roles.
     */
    function grantRole(bytes32 role, address account) public pure override(AccessControl, IAccessControl) {
        /// this is done to funnel all the role granting functions through this contract since
        /// the policyAdmins could add other policyAdmins through this back door
        role;
        account;
        revert("Function disabled");
    }

    /**
     * @dev This function overrides the parent's renounceRole function. Its purpose is to override and disable native renounceRole().
     * @param role the role to renounce.
     * @param account address renouncing to the role.
     */
    function renounceRole(bytes32 role, address account ) public virtual override(AccessControl, IAccessControl) {
        role;
        account;
        revert("Function disabled");
    }

    /**
     * @dev This function overrides the parent's revokeRole function. Its purpose is to override and disable native revokeRole().  
     * @param role the role to revoke.
     * @param account address of revoked role.
     */
    function revokeRole(bytes32 role, address account) public virtual override(AccessControl, IAccessControl) {
        role;
        account;
        revert("Function disabled");
    }


}
