// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

// Rules Engine Error Constants
string constant SIGNATURES_INCONSISTENT = "Signatures and signature id's are inconsistent";
string constant POLICY_ID_0 = "Policy ID cannot be 0. Create policy before updating";
string constant POLICY_DOES_NOT_EXIST = "Policy does not exist";
string constant POLICY_CEMENTED = "Not allowed for cemented policy";
string constant VERIFIED_SUBSCRIBER_ONLY = "Only verified policy subscriber can apply closed policies";
string constant INVALID_RULE = "Invalid Rule";
string constant INVALID_SIGNATURE = "Invalid Signature";
string constant FOREIGN_CALL_NOT_SET = "Foreign Call referenced in rule not set";
string constant TRACKER_NOT_SET = "Tracker referenced in rule not set";
string constant INVALID_PARAM_TYPE = "Invalid Param Type";
string constant INVALID_EFFECT_TYPE = "Invalid Effect Type";
string constant INVALID_INSTRUCTION = "Invalid Instruction";
string constant INVALID_INSTRUCTION_SET = "Invalid Instruction Set";
string constant MEMORY_OVERFLOW = "Memory Overflow";
string constant EMPTY_INSTRUCTION_SET = "Empty Instruction Set";
string constant ZERO_ADDRESS_NOT_ALLOWED = "Zero Address Is Not Allowed";
string constant INVALID_TRACKER_TYPE = "Invalid tracker type";
string constant INVALID_TRACKER_KEY_TYPE = "Invalid tracker key type";



// Admin Error Constants
string constant RULES_ENGINE_ONLY = "OnlyRulesEngineCanCreateAdminRoles";
string constant POLICY_ADMIN_ALREADY_CREATED = "Policy Admin Already Created";
string constant NOT_POLICY_ADMIN = "Not Policy Admin";
string constant NOT_PROPOSED_POLICY_ADMIN = "Not Proposed Policy Admin";
string constant ZERO_ADDRESS = "Zero Address Cannot Be Admin";
string constant BELOW_ADMIN_THRESHOLD = "Below Min Admin Threshold";
string constant CALLING_CONTRACT_ADMIN_ROLE_NOT_GRANTED_ACCESS_CONTROL = "Calling Contract Admin Role Not Granted From Calling Contract";
string constant CALLING_CONTRACT_ADMIN_ROLE_ALREADY_GRANTED = "Calling Contract Admin Already Granted";
string constant ONLY_CALLING_CONTRACT = "Only Calling Contract Can Create Admin";
string constant NOT_CALLING_CONTRACT_ADMIN = "Not Calling Contract Admin";
string constant NOT_PROPOSED_CALLING_CONTRACT_ADMIN = "Not Proposed Calling Contract Admin";
string constant FOREIGN_CALL_ADMIN_ALREADY_GRANTED = "Foreign Call Admin Already Granted";
string constant NOT_FOREIGN_CALL_ADMIN = "Not Foreign Call Admin";
string constant NOT_PROPOSED_FOREIGN_CALL_ADMIN = "Not Proposed Foreign Call Admin";
string constant ONLY_FOREIGN_CALL_CONTRACT = "Only Foreign Call Contract Can Create Admin Role";
string constant FOREIGN_CALL_SELECTOR_NOT_SET = "Foreign Call Not Set";
string constant NOT_PERMISSIONED_FOR_FOREIGN_CALL = "Not Permissioned For Foreign Call";
