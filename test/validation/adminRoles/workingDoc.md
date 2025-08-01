Admin Roles Testing Working Doc: 


#### Policy Admin 
- A policy must always have one policy admin [x]
- There can only ever be one policy admin per policy at a time [ ] need to try calling grantRole()
- Only the current policy admin can propose a new policy admin [x]
- Proposed Admin Role cannot act as policy admin until role is confirmed [x]
- Zero address can never be policy admin [ ] (need to test)

#### Calling Contract Admin 
- A calling contract must always have a calling contract admin
- There can only ever be one calling contract admin per calling contract at a time
- Only the current calling contract admin can propose a new calling contract admin 
- Proposed calling contract Admin Role cannot act as calling contract admin until role is confirmed  
- Only the calling contract admin can set which policies are invoked by the calling contract 
- Zero address can never be calling contract admin 

#### Permissioned Foreign Call Admin 
- Each Foreign Call contract and selector pair has exactly one Foreign Call Admin
- A single address may be the Foreign Call Admin for multiple different contracts
- A single address may be the Foreign Call Admin for multiple different contract and selector pairs
- The Foreign Call sets its own Foreign Call Admin via the setForeignCallAdmin() function within RulesEngineForeignCallAdmin
- Only the current foreign call admin can propose a new calling contract admin 
- Proposed foreign call Admin Role cannot act as the foreign call admin until role is confirmed 
- For a given Foreign contract and selector pair, the Foreign Call Admin is the only one who can configure which Policy Admins may leverage the Foreign Call in their policies


JB Test Scenario from slack 

FCAdmin1 creates a permissioned FC for reward().
FCAdmin1 adds PolicyAdmin1 and PolicyAdmin2 as being allowed to use it.
PolicyAdmin1 creates Policy1 and sets up 2 rules. 1 rule invokes FC:reward()
PolicyAdmin2 creates Policy2 and sets up 3 rules, 2 of which invoke FC:reward().


calling contract admin application via the ownable and access control functions 
