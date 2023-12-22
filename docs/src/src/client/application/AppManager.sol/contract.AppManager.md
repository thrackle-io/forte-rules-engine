# AppManager
[Git Source](https://github.com/thrackle-io/tron/blob/ee06788a23623ed28309de5232eaff934d34a0fe/src/client/application/AppManager.sol)

**Inherits:**
[IAppManager](/src/client/application/IAppManager.sol/interface.IAppManager.md), AccessControlEnumerable, [IAppLevelEvents](/src/common/IEvents.sol/interface.IAppLevelEvents.md)

**Author:**
@ShaneDuncan602, @oscarsernarosero, @TJ-Everett

This contract is the permissions contract

*This uses AccessControlEnumerable to maintain user permissions, handles metadata storage, and checks application level rules via its handler.*


## State Variables
### VERSION

```solidity
string private constant VERSION = "1.1.0";
```


### APP_ADMIN_ROLE

```solidity
bytes32 constant APP_ADMIN_ROLE = keccak256("APP_ADMIN_ROLE");
```


### ACCESS_TIER_ADMIN_ROLE

```solidity
bytes32 constant ACCESS_TIER_ADMIN_ROLE = keccak256("ACCESS_TIER_ADMIN_ROLE");
```


### RISK_ADMIN_ROLE

```solidity
bytes32 constant RISK_ADMIN_ROLE = keccak256("RISK_ADMIN_ROLE");
```


### RULE_ADMIN_ROLE

```solidity
bytes32 constant RULE_ADMIN_ROLE = keccak256("RULE_ADMIN_ROLE");
```


### SUPER_ADMIN_ROLE

```solidity
bytes32 constant SUPER_ADMIN_ROLE = keccak256("SUPER_ADMIN_ROLE");
```


### PROPOSED_SUPER_ADMIN_ROLE

```solidity
bytes32 constant PROPOSED_SUPER_ADMIN_ROLE = keccak256("PROPOSED_SUPER_ADMIN_ROLE");
```


### accounts
Data contracts


```solidity
IAccounts accounts;
```


### accessLevels

```solidity
IAccessLevels accessLevels;
```


### riskScores

```solidity
IRiskScores riskScores;
```


### generalTags

```solidity
IGeneralTags generalTags;
```


### pauseRules

```solidity
IPauseRules pauseRules;
```


### newAccessLevelsProviderAddress

```solidity
address newAccessLevelsProviderAddress;
```


### newAccountsProviderAddress

```solidity
address newAccountsProviderAddress;
```


### newGeneralTagsProviderAddress

```solidity
address newGeneralTagsProviderAddress;
```


### newPauseRulesProviderAddress

```solidity
address newPauseRulesProviderAddress;
```


### newRiskScoresProviderAddress

```solidity
address newRiskScoresProviderAddress;
```


### appName
Application name string


```solidity
string appName;
```


### applicationHandler
Application Handler Contract


```solidity
ProtocolApplicationHandler public applicationHandler;
```


### applicationHandlerAddress

```solidity
address applicationHandlerAddress;
```


### applicationRulesActive

```solidity
bool applicationRulesActive;
```


### tokenToAddress

```solidity
mapping(string => address) tokenToAddress;
```


### addressToToken

```solidity
mapping(address => string) addressToToken;
```


### registeredHandlers

```solidity
mapping(address => bool) registeredHandlers;
```


### tokenList
Token array (for balance tallying)


```solidity
address[] tokenList;
```


### tokenToIndex

```solidity
mapping(address => uint256) tokenToIndex;
```


### isTokenRegistered

```solidity
mapping(address => bool) isTokenRegistered;
```


### ammList
AMM List (for token level rule exemptions)


```solidity
address[] ammList;
```


### ammToIndex

```solidity
mapping(address => uint256) ammToIndex;
```


### isAMMRegistered

```solidity
mapping(address => bool) isAMMRegistered;
```


### treasuryList
Treasury List (for token level rule exemptions)


```solidity
address[] treasuryList;
```


### treasuryToIndex

```solidity
mapping(address => uint256) treasuryToIndex;
```


### isTreasuryRegistered

```solidity
mapping(address => bool) isTreasuryRegistered;
```


### stakingList
Staking Contracts List (for token level rule exemptions)


```solidity
address[] stakingList;
```


### stakingToIndex

```solidity
mapping(address => uint256) stakingToIndex;
```


### isStakingRegistered

```solidity
mapping(address => bool) isStakingRegistered;
```


## Functions
### constructor

*This constructor sets up the first default admin and app administrator roles while also forming the hierarchy of roles and deploying data contracts. App Admins are the top tier. They may assign all admins, including other app admins.*


```solidity
constructor(address root, string memory _appName, bool upgradeMode);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`root`|`address`|address to set as the default admin and first app administrator|
|`_appName`|`string`|Application Name String|
|`upgradeMode`|`bool`|specifies whether this is a fresh AppManager or an upgrade replacement.|


### grantRole

this is purposely going to fail every time it will be invoked in order to force users to only use the appropiate
channels to grant roles, and therefore enforce the special rules in an app.

*This function overrides the parent's grantRole function. This basically disables its public nature to make it private.*


```solidity
function grantRole(bytes32 role, address account) public virtual override(AccessControl, IAccessControl);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`role`|`bytes32`|the role to grant to an acount.|
|`account`|`address`|address being granted the role.|


### renounceRole

this is done to funnel all the role granting functions through the app manager functions since
the superAdmins could add other superAdmins through this back door

*This function overrides the parent's renounceRole function. Its purpose is to prevent superAdmins from renouncing through
this "backdoor", so they are forced to find another superAdmin through the function proposeNewSuperAdmin.*


```solidity
function renounceRole(bytes32 role, address account) public virtual override(AccessControl, IAccessControl);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`role`|`bytes32`|the role to renounce.|
|`account`|`address`|address renouncing to the role.|


### revokeRole

enforcing the min-1-admin requirement. Only PROPOSED_SUPER_ADMIN_ROLE should be able to bypass this rule

*This function overrides the parent's revokeRole function. Its purpose is to prevent superAdmins from being revoked through
this "backdoor" which would effectively leave the app in a superAdmin-orphan state.*


```solidity
function revokeRole(bytes32 role, address account) public virtual override(AccessControl, IAccessControl);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`role`|`bytes32`|the role to revoke.|
|`account`|`address`|address of revoked role.|


### isSuperAdmin

enforcing the min-1-admin requirement.

*This function is where the Super admin role is actually checked*


```solidity
function isSuperAdmin(address account) public view returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|address to be checked|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|success true if admin, false if not|


### proposeNewSuperAdmin

-------------- PROPOSE NEW SUPER ADMIN ------------------

*Propose a new super admin. Restricted to super admins.*


```solidity
function proposeNewSuperAdmin(address account) external onlyRole(SUPER_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|address to be added|


### confirmSuperAdmin

we should only have 1 proposed superAdmin. If there is one already in this role, we should remove it to replace it.

only the proposed account can accept this role.

*confirm the superAdmin role.*


```solidity
function confirmSuperAdmin() external;
```

### isAppAdministrator

We first check that only the proposed superAdmin can confirm
then we transfer the role
we emit the events
-------------APP ADMIN---------------

*This function is where the app administrator role is actually checked*


```solidity
function isAppAdministrator(address account) public view returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|address to be checked|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|success true if app administrator, false if not|


### addAppAdministrator

*Add an account to the app administrator role. Restricted to super admins.*


```solidity
function addAppAdministrator(address account) external onlyRole(SUPER_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|address to be added|


### addMultipleAppAdministrator

*Add an array of accounts to the app administrator role. Restricted to admins.*


```solidity
function addMultipleAppAdministrator(address[] memory _accounts) external onlyRole(SUPER_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_accounts`|`address[]`|address array to be added|


### renounceAppAdministrator

*Remove oneself from the app administrator role.*


```solidity
function renounceAppAdministrator() external;
```

### checkForAdminWithdrawal

If the AdminWithdrawal rule is active, App Admins are not allowed to renounce their role to prevent manipulation of the rule

*Loop through all the registered tokens, if they are capable of admin withdrawal, see if it's active. If so, revert*


```solidity
function checkForAdminWithdrawal() internal;
```

### isRuleAdministrator

-------------RULE ADMIN---------------

*This function is where the rule admin role is actually checked*


```solidity
function isRuleAdministrator(address account) public view returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|address to be checked|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|success true if RULE_ADMIN_ROLE, false if not|


### addRuleAdministrator

*Add an account to the rule admin role. Restricted to app administrators.*


```solidity
function addRuleAdministrator(address account) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|address to be added as a rule admin|


### addMultipleRuleAdministrator

*Add a list of accounts to the rule admin role. Restricted to app administrators.*


```solidity
function addMultipleRuleAdministrator(address[] memory account) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address[]`|address to be added as a rule admin|


### renounceRuleAdministrator

*Remove oneself from the rule admin role.*


```solidity
function renounceRuleAdministrator() external;
```

### onlyAccessTierAdministrator

-------------ACCESS TIER---------------

*Checks for if msg.sender is a Access Tier*


```solidity
modifier onlyAccessTierAdministrator();
```

### isAccessTier

*This function is where the access tier role is actually checked*


```solidity
function isAccessTier(address account) public view returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|address to be checked|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|success true if ACCESS_TIER_ADMIN_ROLE, false if not|


### addAccessTier

*Add an account to the access tier role. Restricted to app administrators.*


```solidity
function addAccessTier(address account) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|address to be added as a access tier|


### addMultipleAccessTier

*Add a list of accounts to the access tier role. Restricted to app administrators.*


```solidity
function addMultipleAccessTier(address[] memory account) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address[]`|address to be added as a access tier|


### renounceAccessTier

*Remove oneself from the access tier role.*


```solidity
function renounceAccessTier() external;
```

### isRiskAdmin

-------------RISK ADMIN---------------

*This function is where the risk admin role is actually checked*


```solidity
function isRiskAdmin(address account) public view returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|address to be checked|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|success true if RISK_ADMIN_ROLE, false if not|


### addRiskAdmin

*Add an account to the risk admin role. Restricted to app administrators.*


```solidity
function addRiskAdmin(address account) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address`|address to be added|


### addMultipleRiskAdmin

*Add a list of accounts to the risk admin role. Restricted to app administrators.*


```solidity
function addMultipleRiskAdmin(address[] memory account) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`account`|`address[]`|address to be added|


### renounceRiskAdmin

*Remove oneself from the risk admin role.*


```solidity
function renounceRiskAdmin() external;
```

### addAccessLevel

-------------MAINTAIN ACCESS LEVELS---------------

*Add the Access Level(0-4) to the account. Restricted to Access Tiers.*


```solidity
function addAccessLevel(address _account, uint8 _level) external onlyRole(ACCESS_TIER_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_account`|`address`|address upon which to apply the Access Level|
|`_level`|`uint8`|Access Level to add|


### addAccessLevelToMultipleAccounts

*Add the Access Level(0-4) to multiple accounts. Restricted to Access Tiers.*


```solidity
function addAccessLevelToMultipleAccounts(address[] memory _accounts, uint8 _level)
    external
    onlyRole(ACCESS_TIER_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_accounts`|`address[]`|address upon which to apply the Access Level|
|`_level`|`uint8`|Access Level to add|


### addMultipleAccessLevels

*Add the Access Level(0-4) to the list of account. Restricted to Access Tiers.*


```solidity
function addMultipleAccessLevels(address[] memory _accounts, uint8[] memory _level)
    external
    onlyRole(ACCESS_TIER_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_accounts`|`address[]`|address array upon which to apply the Access Level|
|`_level`|`uint8[]`|Access Level array to add|


### getAccessLevel

*Get the AccessLevel Score for the specified account*


```solidity
function getAccessLevel(address _account) external view returns (uint8);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_account`|`address`|address of the user|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint8`||


### addRiskScore

-------------MAINTAIN RISK SCORES---------------

*Add the Risk Score. Restricted to Risk Admins.*


```solidity
function addRiskScore(address _account, uint8 _score) external onlyRole(RISK_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_account`|`address`|address upon which to apply the Risk Score|
|`_score`|`uint8`|Risk Score(0-100)|


### addRiskScoreToMultipleAccounts

*Add the Risk Score to each address in array. Restricted to Risk Admins.*


```solidity
function addRiskScoreToMultipleAccounts(address[] memory _accounts, uint8 _score) external onlyRole(RISK_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_accounts`|`address[]`|address array upon which to apply the Risk Score|
|`_score`|`uint8`|Risk Score(0-100)|


### addMultipleRiskScores

*Add the Risk Score at index to Account at index in array. Restricted to Risk Admins.*


```solidity
function addMultipleRiskScores(address[] memory _accounts, uint8[] memory _scores) external onlyRole(RISK_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_accounts`|`address[]`|address array upon which to apply the Risk Score|
|`_scores`|`uint8[]`|Risk Score array (0-100)|


### getRiskScore

*Get the Risk Score for an account.*


```solidity
function getRiskScore(address _account) external view returns (uint8);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_account`|`address`|address upon which the risk score was set|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`uint8`|score risk score(0-100)|


### addPauseRule

--------------MAINTAIN PAUSE RULES---------------

Adding a pause rule will change the bool to true in the hanlder contract and pause rules will be checked.

*Add a pause rule. Restricted to Application Administrators*


```solidity
function addPauseRule(uint64 _pauseStart, uint64 _pauseStop) external onlyRole(RULE_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_pauseStart`|`uint64`|Beginning of the pause window|
|`_pauseStop`|`uint64`|End of the pause window|


### removePauseRule

If no pause rules exist after removal bool is set to false in handler and pause rules will not be checked until new rule is added.

*Remove a pause rule. Restricted to Application Administrators*


```solidity
function removePauseRule(uint64 _pauseStart, uint64 _pauseStop) external onlyRole(RULE_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_pauseStart`|`uint64`|Beginning of the pause window|
|`_pauseStop`|`uint64`|End of the pause window|


### activatePauseRuleCheck

if length is 0 no pause rules exist
set handler bool to false to save gas and prevent pause rule checks when non exist

*enable/disable rule. Disabling a rule will save gas on transfer transactions.
This function calls the appHandler contract to enable/disable this check.*


```solidity
function activatePauseRuleCheck(bool _on) external onlyRole(RULE_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_on`|`bool`|boolean representing if a rule must be checked or not.|


### getPauseRules

*Get all pause rules for the token*


```solidity
function getPauseRules() external view returns (PauseRule[] memory);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`PauseRule[]`|PauseRule An array of all the pause rules|


### cleanOutdatedRules

*Remove any expired pause windows.*


```solidity
function cleanOutdatedRules() external;
```

### addGeneralTag

-------------MAINTAIN GENERAL TAGS---------------

there is a hard limit of 10 tags per address.

*Add a general tag to an account. Restricted to Application Administrators. Loops through existing tags on accounts and will emit an event if tag is * already applied.*


```solidity
function addGeneralTag(address _account, bytes32 _tag) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_account`|`address`|Address to be tagged|
|`_tag`|`bytes32`|Tag for the account. Can be any allowed string variant|


### addGeneralTagToMultipleAccounts

there is a hard limit of 10 tags per address.

*Add a general tag to an account. Restricted to Application Administrators. Loops through existing tags on accounts and will emit an event if tag is * already applied.*


```solidity
function addGeneralTagToMultipleAccounts(address[] memory _accounts, bytes32 _tag) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_accounts`|`address[]`|Address array to be tagged|
|`_tag`|`bytes32`|Tag for the account. Can be any allowed string variant|


### addMultipleGeneralTagToMultipleAccounts

there is a hard limit of 10 tags per address.

*Add a general tag to an account at index in array. Restricted to Application Administrators. Loops through existing tags on accounts and will emit  an event if tag is already applied.*


```solidity
function addMultipleGeneralTagToMultipleAccounts(address[] memory _accounts, bytes32[] memory _tag)
    external
    onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_accounts`|`address[]`|Address array to be tagged|
|`_tag`|`bytes32[]`|Tag array for the account at index. Can be any allowed string variant|


### removeGeneralTag

*Remove a general tag. Restricted to Application Administrators.*


```solidity
function removeGeneralTag(address _account, bytes32 _tag) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_account`|`address`|Address to have its tag removed|
|`_tag`|`bytes32`|The tag to remove|


### hasTag

*Check to see if an account has a specific general tag*


```solidity
function hasTag(address _account, bytes32 _tag) public view returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_account`|`address`|Address to check|
|`_tag`|`bytes32`|Tag to be checked for|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|success true if account has the tag, false if it does not|


### getAllTags

*Get all the tags for the address*


```solidity
function getAllTags(address _address) external view returns (bytes32[] memory);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_address`|`address`|Address to retrieve the tags|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bytes32[]`|tags Array of all tags for the account|


### proposeRiskScoresProvider

*First part of the 2 step process to set a new risk score provider. First, the new provider address is proposed and saved, then it is confirmed by invoking a confirmation function in the new provider that invokes the corresponding function in this contract.*


```solidity
function proposeRiskScoresProvider(address _newProvider) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_newProvider`|`address`|Address of the new provider|


### getRiskScoresProvider

*Get the address of the risk score provider*


```solidity
function getRiskScoresProvider() external view returns (address);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address`|provider Address of the provider|


### proposeGeneralTagsProvider

*First part of the 2 step process to set a new general tag provider. First, the new provider address is proposed and saved, then it is confirmed by invoking a confirmation function in the new provider that invokes the corresponding function in this contract.*


```solidity
function proposeGeneralTagsProvider(address _newProvider) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_newProvider`|`address`|Address of the new provider|


### getGeneralTagProvider

*Get the address of the general tag provider*


```solidity
function getGeneralTagProvider() external view returns (address);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address`|provider Address of the provider|


### proposeAccountsProvider

*First part of the 2 step process to set a new account provider. First, the new provider address is proposed and saved, then it is confirmed by invoking a confirmation function in the new provider that invokes the corresponding function in this contract.*


```solidity
function proposeAccountsProvider(address _newProvider) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_newProvider`|`address`|Address of the new provider|


### getAccountProvider

*Get the address of the account provider*


```solidity
function getAccountProvider() external view returns (address);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address`|provider Address of the provider|


### proposePauseRulesProvider

*First part of the 2 step process to set a new pause rule provider. First, the new provider address is proposed and saved, then it is confirmed by invoking a confirmation function in the new provider that invokes the corresponding function in this contract.*


```solidity
function proposePauseRulesProvider(address _newProvider) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_newProvider`|`address`|Address of the new provider|


### getPauseRulesProvider

*Get the address of the pause rules provider*


```solidity
function getPauseRulesProvider() external view returns (address);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address`|provider Address of the provider|


### proposeAccessLevelsProvider

*First part of the 2 step process to set a new access level provider. First, the new provider address is proposed and saved, then it is confirmed by invoking a confirmation function in the new provider that invokes the corresponding function in this contract.*


```solidity
function proposeAccessLevelsProvider(address _newProvider) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_newProvider`|`address`|Address of the new provider|


### getAccessLevelProvider

*Get the address of the Access Level provider*


```solidity
function getAccessLevelProvider() external view returns (address);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address`|accessLevelProvider Address of the Access Level provider|


### requireValuations

APPLICATION CHECKS

*checks if any of the balance prerequisite rules are active*


```solidity
function requireValuations() external returns (bool);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|true if one or more rules are active|


### checkApplicationRules

*Check Application Rules for valid transactions.*


```solidity
function checkApplicationRules(
    ActionTypes _action,
    address _from,
    address _to,
    uint128 _usdBalanceTo,
    uint128 _usdAmountTransferring
) external onlyHandler;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_action`|`ActionTypes`|Action to be checked|
|`_from`|`address`|address of the from account|
|`_to`|`address`|address of the to account|
|`_usdBalanceTo`|`uint128`|recepient address current total application valuation in USD with 18 decimals of precision|
|`_usdAmountTransferring`|`uint128`|valuation of the token being transferred in USD with 18 decimals of precision|


### isRegisteredHandler

*This function checks if the address is a registered handler within one of the registered protocol supported entities*


```solidity
function isRegisteredHandler(address _address) public view returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_address`|`address`|address to be checked|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`bool`|isHandler true if handler, false if not|


### onlyHandler

*Checks if _msgSender() is a registered handler*


```solidity
modifier onlyHandler();
```

### registerToken

*This function allows the devs to register their token contract addresses. This keeps everything in sync and will aid with the token factory and application level balance checks.*


```solidity
function registerToken(string calldata _token, address _tokenAddress) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_token`|`string`|The token identifier(may be NFT or ERC20)|
|`_tokenAddress`|`address`|Address corresponding to the tokenId|


### getTokenAddress

*This function gets token contract address.*


```solidity
function getTokenAddress(string calldata _tokenId) external view returns (address);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_tokenId`|`string`|The token id(may be NFT or ERC20)|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address`|tokenAddress the address corresponding to the tokenId|


### getTokenID

*This function gets token identification string.*


```solidity
function getTokenID(address _tokenAddress) external view returns (string memory);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_tokenAddress`|`address`|the address of the contract of the token to query|

**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`string`|the identification string.|


### deregisterToken

*This function allows the devs to deregister a token contract address. This keeps everything in sync and will aid with the token factory and application level balance checks.*


```solidity
function deregisterToken(string calldata _tokenId) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_tokenId`|`string`|The token id(may be NFT or ERC20)|


### _removeAddressWithMapping

also remove its handler from the registration

*This function removes an address from a dynamic address array by putting the last element in the one to remove and then removing last element.*


```solidity
function _removeAddressWithMapping(
    address[] storage _addressArray,
    mapping(address => uint256) storage _addressToIndex,
    mapping(address => bool) storage _registerFlag,
    address _address
) private;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_addressArray`|`address[]`|The array to have an address removed|
|`_addressToIndex`|`mapping(address => uint256)`|mapping that keeps track of the indexes in the list by address|
|`_registerFlag`|`mapping(address => bool)`|mapping that keeps track of the addresses that are members of the list|
|`_address`|`address`|The address to remove|


### registerAMM

we store the last address in the array on a local variable to avoid unnecessary costly memory reads
we check if we're trying to remove the last address in the array since this means we can skip some steps
if it is not the last address in the array, then we store the index of the address to remove
we remove the address by replacing it in the array with the last address of the array (now duplicated)
we update the last address index to its new position (the removed-address index)
we remove the last element of the _addressArray since it is now duplicated
we set to false the membership mapping for this address in _addressArray
we set the index to zero for this address in _addressArray

*This function allows the devs to register their AMM contract addresses. This will allow for token level rule exemptions*


```solidity
function registerAMM(address _AMMAddress) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_AMMAddress`|`address`|Address for the AMM|


### isRegisteredAMM

Also add their handler to the registry

*This function allows the devs to register their AMM contract addresses. This will allow for token level rule exemptions*


```solidity
function isRegisteredAMM(address _AMMAddress) public view returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_AMMAddress`|`address`|Address for the AMM|


### deRegisterAMM

*This function allows the devs to deregister an AMM contract address.*


```solidity
function deRegisterAMM(address _AMMAddress) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_AMMAddress`|`address`|The of the AMM to be de-registered|


### isTreasury

*This function allows the devs to register their treasury addresses. This will allow for token level rule exemptions*


```solidity
function isTreasury(address _treasuryAddress) public view returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_treasuryAddress`|`address`|Address for the treasury|


### registerTreasury

*This function allows the devs to register their treasury addresses. This will allow for token level rule exemptions*


```solidity
function registerTreasury(address _treasuryAddress) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_treasuryAddress`|`address`|Address for the treasury|


### deRegisterTreasury

*This function allows the devs to deregister an treasury address.*


```solidity
function deRegisterTreasury(address _treasuryAddress) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_treasuryAddress`|`address`|The of the AMM to be de-registered|


### registerStaking

*This function allows the devs to register their Staking contract addresses. Allow contracts to check if contract is registered staking contract within ecosystem.
This check is used in minting rewards tokens for example.*


```solidity
function registerStaking(address _stakingAddress) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_stakingAddress`|`address`|Address for the AMM|


### deRegisterStaking

*This function allows the devs to deregister a Staking contract address.*


```solidity
function deRegisterStaking(address _stakingAddress) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_stakingAddress`|`address`|The of the Staking contract to be de-registered|


### isStaking

*This function allows the devs to register their staking addresses. This will allow for token level rule exemptions*


```solidity
function isStaking(address _stakingAddress) public view returns (bool);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_stakingAddress`|`address`|Address for the staking|


### getAccessLevelDataAddress

*Getter for the access level contract address*


```solidity
function getAccessLevelDataAddress() external view returns (address);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address`|AccessLevelDataAddress|


### getAccountDataAddress

*Getter for the Account data contract address*


```solidity
function getAccountDataAddress() external view returns (address);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address`|accountDataAddress|


### getRiskDataAddress

*Getter for the risk data contract address*


```solidity
function getRiskDataAddress() external view returns (address);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address`|riskDataAddress|


### getGeneralTagsDataAddress

*Getter for the general tags data contract address*


```solidity
function getGeneralTagsDataAddress() external view returns (address);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address`|generalTagsDataAddress|


### getPauseRulesDataAddress

*Getter for the pause rules data contract address*


```solidity
function getPauseRulesDataAddress() external view returns (address);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address`|pauseRulesDataAddress|


### getTokenList

*Return the token list for calculation purposes*


```solidity
function getTokenList() external view returns (address[] memory);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address[]`|tokenList list of all tokens registered|


### version

*gets the version of the contract*


```solidity
function version() external pure returns (string memory);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`string`|VERSION|


### setNewApplicationHandlerAddress

this is for upgrading to a new ApplicationHandler contract

*Update the Application Handler Contract Address*


```solidity
function setNewApplicationHandlerAddress(address _newApplicationHandler) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_newApplicationHandler`|`address`|address of new Application Handler contract|


### getHandlerAddress

*this function returns the application handler address*


```solidity
function getHandlerAddress() external view returns (address);
```
**Returns**

|Name|Type|Description|
|----|----|-----------|
|`<none>`|`address`|handlerAddress|


### setAppName

*Setter for application Name*


```solidity
function setAppName(string calldata _appName) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_appName`|`string`|application name string|


### confirmAppManager

*Part of the two step process to set a new AppManager within a Protocol Entity*


```solidity
function confirmAppManager(address _assetAddress) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_assetAddress`|`address`|address of a protocol entity that uses AppManager|


### deployDataContracts

-------------DATA CONTRACT DEPLOYMENT---------------

*Deploy all the child data contracts. Only called internally from the constructor.*


```solidity
function deployDataContracts() private;
```

### proposeDataContractMigration

*This function is used to propose the new owner for data contracts.*


```solidity
function proposeDataContractMigration(address _newOwner) external onlyRole(APP_ADMIN_ROLE);
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_newOwner`|`address`|address of the new AppManager|


### confirmDataContractMigration

*This function is used to confirm this contract as the new owner for data contracts.*


```solidity
function confirmDataContractMigration(address _oldAppManagerAddress) external onlyRole(APP_ADMIN_ROLE);
```

### confirmNewDataProvider

*Part of the two step process to set a new Data Provider within a Protocol AppManager. Final confirmation called by new provider*


```solidity
function confirmNewDataProvider(IDataModule.ProviderType _providerType) external;
```
**Parameters**

|Name|Type|Description|
|----|----|-----------|
|`_providerType`|`IDataModule.ProviderType`|the type of data provider|

