# Test Priority Level 
## Highest 
### Admin Roles Invariants 
#### Policy Admin 
- A policy must always have one policy admin 
- There can only ever be one policy admin per policy at a time
- Only the current policy admin can propose a new policy admin 
- Proposed Admin Role cannot act as policy admin until role is confirmed  
- Zero address can never be policy admin 

#### Calling Contract Admin 
- A calling contract must always have a calling contract admin
- There can only ever be one calling contract admin per calling contract at a time
- Only the current calling contract admin can propose a new calling contract admin 
- Proposed calling contract Admin Role cannot act as calling contract admin until role is confirmed  
- Only the calling contract admin can set which policies are invoked by the calling contract 
- Zero address can never be calling contract admin 

### Policy Invariants 
- policyId can never be 0 
- policyId can never decrement 
- A cemented policy can never be changed
- A cemented policy can never be updated 
- A cemented policy can never be deleted 
- A cemented policy can never add new subscribers 
- A closed and cemented policy can never increment or decrement subscribers 
- A closed policy can only be applied by subscribers of that policy 
- An open policy can be applied to any calling contract by the calling contract admin 
- A disabled policy will never be invoked within the checkPolicies function 
- Only the policy admin for the policy can add a subscriber 
- Only the policy admin for the policy can update a policy 
- Only the policy admin for the policy can delete a policy 
- Only the policy admin can close the policy 
- Only the policy admin can open the policy 
- Only the policy admin can cement the policy 
- Only the policy admin can disable the policy 
- Only the policy admin can enable the policy once disabled
- Only the calling contract admin can apply the policy to the calling contract
- Only the calling contract admin can un apply the policy from calling contract

### Tracker Invariants 
- Only the policy admin for the policy can create a tracker within the policy 
- Only the policy admin for the policy can delete a tracker within the policy 
- Only the policy admin for the policy can update a tracker's definition within the policy
- trackerIdxCounter can only ever increment within a policy
- Tracker and Mapped Tracker values can still update when policy is closed 
- Tracker and Mapped Tracker values can only update from rule effects within the policy they are assigned

## High 
### Rules Invariants 
- Only the policy admin for the policy can create a rule within the policy 
- Only the policy admin for the policy can delete a rule within the policy 
- Only the policy admin for the policy can update a rule within the policy 
- RuleId can only ever increment within a policy 

### Components Invariants 
#### Foreign Call Invariants 
- Only the policy admin for the policy can create a foreign call within the policy 
- Only the policy admin for the policy can delete a foreign call within the policy 
- Only the policy admin for the policy can update a foreign call within the policy
- foreignCallIdxCounter can only ever increment within a policy

#### Calling Function Invariants 
- Only the policy admin for the policy can create a calling function within the policy 
- Only the policy admin for the policy can delete a calling function within the policy 
- Only the policy admin for the policy can update a calling function within the policy
- Deleting a calling function will always delete associated rules 
- callingFunctionId can only ever increment within a policy

### Effect Invariants 
- When rule conditionals evaluate to true, the positive effect(s) will always execute 
- When rule conditionals evaluate to false, the negative effect(s) will always execute 
- When a revert effect is executed, all transaction changes are reverted and no changes to state are stored. 
- The reversion message will always match the effect errorMessage for the executing rule.

## Medium 
### Diamond Pattern Invariants 
- Diamond Facets Cannot be upgraded once the diamond is initialized 
- Diamond Facets Cannot be deleted once the diamond is initialized  
- Diamond Facets Cannot be replaced once the diamond is initialized
- Diamond can only be initialized once 
- Diamond Ownership will be transferred to the address that deploys the Rules Engine  

## Low 
