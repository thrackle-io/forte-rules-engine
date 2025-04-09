// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

/// Effect Events
event RulesEngineEvent(uint256 indexed _eventKey, bytes32 _eventString, string _message);
event RulesEngineEvent(uint256 indexed _eventKey, bytes32 _eventString, bytes32 _bytes);
event RulesEngineEvent(uint256 indexed _eventKey, bytes32 _eventString, uint256 indexed _num);
event RulesEngineEvent(uint256 indexed _eventKey, bytes32 _eventString, address indexed _address);
event RulesEngineEvent(uint256 indexed _eventKey, bytes32 _eventString, bool indexed _bool);

/// Foreign Call Events
event ForeignCallCreated(uint256 indexed policyId, uint256 indexed foreignCallId);
event ForeignCallUpdated(uint256 indexed policyId, uint256 indexed foreignCallId);
event ForeignCallDeleted(uint256 indexed policyId, uint256 indexed foreignCallId);
/// When a Foriegn Call is deleted we delete all Rules associated 
event AssociatedRuleDeleted(uint256 indexed policyId, uint256 indexed foreignCallId);

/// Tracker Events 
event TrackerCreated(uint256 indexed policyId, uint256 indexed trackerId);
event TrackerUpdated(uint256 indexed policyId, uint256 indexed trackerId);
event TrackerDeleted(uint256 indexed policyId, uint256 indexed trackerId);

/// Rule Events 
event RuleCreated(uint256 indexed policyId, uint256 indexed ruleId);
event RuleUpdated(uint256 indexed policyId, uint256 indexed ruleId);
event RuleDeleted(uint256 indexed policyId, uint256 indexed ruleId);

/// Policy Events 
event PolicyCreated(uint256 indexed policyId);
event PolicyUpdated(uint256 indexed policyId);
event PolicyDeleted(uint256 indexed policyId);
event PolicyCemented(uint256 indexed policyId);
event PolicyOpened(uint256 indexed policyId);
event PolicyClosed(uint256 indexed policyId);
event PolicyApplied(uint256[] policyIds, address indexed callingContract);
event PolicyRemoved(uint256 indexed removedPolicyId, address indexed callingContract);
event PolicySubsciberAdded(uint256 indexed policyId, address indexed subscriber);
event PolicySubsciberRemoved(uint256 indexed policyId, address indexed subscriber);

/// Function Signature Events 
event FunctionSignatureCreated(uint256 indexed policyId, uint256 indexed functionSignatureId);
event FunctionSignatureUpdated(uint256 indexed policyId, uint256 indexed functionSignatureId);
event FunctionSignatureDeleted(uint256 indexed policyId, uint256 indexed functionSignatureId);

/// Admin Events 
event PolicyAdminRoleGranted(address indexed adminAddress, uint256 indexed policyId); 
event PolicyAdminRoleProposed(address indexed proposedAdminAddress, uint256 indexed policyId); 
event PolicyAdminRoleConfirmed(address indexed adminAddress, uint256 indexed policyId); 
event PolicyAdminRoleRenounced(address indexed adminAddress, uint256 indexed policyId); 
event PolicyAdminRoleRevoked(address indexed adminAddress, uint256 indexed policyId); 

event CallingContractAdminRoleGranted(address indexed callingContract, address indexed adminAddress); 
event CallingContractAdminRoleProposed(address indexed callingContract, address indexed proposedAdminAddress); 
event CallingContractAdminRoleConfirmed(address indexed callingContract, address indexed adminAddress); 

