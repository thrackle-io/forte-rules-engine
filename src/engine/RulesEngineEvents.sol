// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

// x5f6d49ad = x + (Keccak of RulesEngineV2)

/// Effect Events
event x5f6d49ad_RulesEngineEvent(uint256 indexed _eventKey, bytes32 _eventString, string _message);
event x5f6d49ad_RulesEngineEvent(uint256 indexed _eventKey, bytes32 _eventString, bytes32 _bytes);
event x5f6d49ad_RulesEngineEvent(uint256 indexed _eventKey, bytes32 _eventString, uint256 indexed _num);
event x5f6d49ad_RulesEngineEvent(uint256 indexed _eventKey, bytes32 _eventString, address indexed _address);
event x5f6d49ad_RulesEngineEvent(uint256 indexed _eventKey, bytes32 _eventString, bool indexed _bool);

/// Foreign Call Events
event x5f6d49ad_ForeignCallCreated(uint256 indexed policyId, uint256 indexed foreignCallId);
event x5f6d49ad_ForeignCallUpdated(uint256 indexed policyId, uint256 indexed foreignCallId);
event x5f6d49ad_ForeignCallDeleted(uint256 indexed policyId, uint256 indexed foreignCallId);

/// Tracker Events 
event x5f6d49ad_TrackerCreated(uint256 indexed policyId, uint256 indexed trackerId);
event x5f6d49ad_TrackerUpdated(uint256 indexed policyId, uint256 indexed trackerId);
event x5f6d49ad_TrackerDeleted(uint256 indexed policyId, uint256 indexed trackerId);

/// Rule Events 
event x5f6d49ad_RuleCreated(uint256 indexed policyId, uint256 indexed ruleId);
event x5f6d49ad_RuleUpdated(uint256 indexed policyId, uint256 indexed ruleId);
event x5f6d49ad_RuleDeleted(uint256 indexed policyId, uint256 indexed ruleId);

/// Policy Events 
event x5f6d49ad_PolicyCreated(uint256 indexed policyId);
event x5f6d49ad_PolicyUpdated(uint256 indexed policyId);
event x5f6d49ad_PolicyDeleted(uint256 indexed policyId);
event x5f6d49ad_PolicyCemented(uint256 indexed policyId);
event x5f6d49ad_PolicyApplied(uint256[] policyIds, address indexed callingContract);
event x5f6d49ad_PolicyRemoved(uint256 indexed removedPolicyId, address indexed callingContract);
event x5f6d49ad_PolicySubsciberAdded(uint256 indexed policyId, address indexed subscriber);
event x5f6d49ad_PolicySubsciberRemoved(uint256 indexed policyId, address indexed subscriber);

/// Function Signature Events 
event x5f6d49ad_FunctionSignatureCreated(uint256 indexed policyId, uint256 indexed functionSignatureId);
event x5f6d49ad_FunctionSignatureUpdated(uint256 indexed policyId, uint256 indexed functionSignatureId);
event x5f6d49ad_FunctionSignatureDeleted(uint256 indexed policyId, uint256 indexed functionSignatureId);

/// Admin Events 
event x5f6d49ad_PolicyAdminRoleGranted(address indexed adminAddress, uint256 indexed policyId); 
event x5f6d49ad_PolicyAdminRoleProposed(address indexed proposedAdminAddress, uint256 indexed policyId); 
event x5f6d49ad_PolicyAdminRoleConfirmed(address indexed adminAddress, uint256 indexed policyId); 
event x5f6d49ad_PolicyAdminRoleRenounced(address indexed adminAddress, uint256 indexed policyId); 
event x5f6d49ad_PolicyAdminRoleRevoked(address indexed adminAddress, uint256 indexed policyId); 

event x5f6d49ad_CallingContractAdminRoleGranted(address indexed callingContract, address indexed adminAddress); 
event x5f6d49ad_CallingContractAdminRoleProposed(address indexed callingContract, address indexed proposedAdminAddress); 
event x5f6d49ad_CallingContractAdminRoleConfirmed(address indexed callingContract, address indexed adminAddress); 
event x5f6d49ad_CallingContractAdminRoleRenounced(address indexed callingContract, address indexed adminAddress); 
event x5f6d49ad_CallingContractAdminRoleRevoked(address indexed callingContract, address indexed adminAddress); 

