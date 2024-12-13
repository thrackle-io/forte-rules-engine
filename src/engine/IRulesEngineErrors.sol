// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

interface IRulesEngineErrors {
    error OnlyRulesEngineCanCreateAdminRoles(); 
    error NotPolicyAdmin(); 
    error NewAdminAlreadyProposed();
    error NotProposedPolicyAdmin(); 
    error BelowMinAdminThreshold();
    error ZeroAddressCannotBeAdmin(); 
    error PolicyAdminAlreadyCreated(); 

}
