# AppManager Invariants

## [Role Management Invariants](../../../../../../test/client/application/invariant/ApplicationAppManagerRoles.t.i.sol)
- There will always be a SuperAdmin
- When grantRole is called directly on the AppManager contract the transaction will be reverted.
- When renounceRole is called by the Super Admin the transaction will be reverted.
- When addAppAdministrator is called by an account other than the Super Admin the transaction will be reverted.
- When addAppAdministrator is called with an address of 0 the transaction will be reverted.
- If addAppAdministrator is not reverted the AppAdministrator event will be emitted. 
- When renounceRole is called with argument APP_ADMIN_ROLE the AppAdministrator event will be emitted.
- When addRuleAdministrator is called by an account other other than an App Admin the transaction will be reverted.
- When addRuleAdministrator is called with an address of 0 the transaction will be reverted.
- If addRuleAdministrator is not reverted the RuleAdmin event will be emitted.
- When renounceRole is called with argument RULE_ADMIN_ROLE the RuleAdministrator event will be emitted.
- When addRiskAdmin is called by an account other than an App Admin the transaction will be reverted.
- When addRiskAdmin is called with an address of 0 the transaction will be reverted.
- If addRiskAdmin is not reverted the RiskAdmin event will be emitted.
- When renounceRole is called with argument RISK_ADMIN_ROLE the RiskAdmin event will be emitted.
- When addTreasuryAccount is called by an account other than an App Admin the transaction will be reverted.
- When addTreasuryAccount is called with an address of 0 the transaction will be reverted.
- If addTreasuryAccount is not reverted the TreasuryAccount event will be emitted.
- When renounceRole is called with argument TREASURY_ACCOUNT the TreasuryAccount event will be emitted.
- When addAccessLevelAdmin is called by an account other than an App Admin the transaction will be reverted.
- When addAccessLevelAdmin is called with an address of 0 the transaction will be reverted.
- If addAccessLevelAdmin is not reverted the AccessLevelAdmin event will be emitted.
- When renounceRole is called with argument ACCESS_LEVEL_ADMIN_ROLE the AccessLevelAdmin event will be emitted.
  

## [Access Level Invariants](../../../../../../test/client/application/invariant/ApplicationAppManagerData.t.i.sol)
- If addAccessLevel is called by an account that is not an Access Level Admin the transaction will be reverted.
- If addAccessLevelToMultipleAccounts is called by an account that is not an Access Level Admin the transaction will be reverted.
- If addMultipleAccessLevels is called by an account that is not an Access Level Admin the transaction will be reverted. 
- If removeAccessLevel is called by an account that is not an Access Level Admin the transaction will be reverted.

## [Risk Score Invariants](../../../../../../test/client/application/invariant/ApplicationAppManagerData.t.i.sol)
- If addRiskScore is called by an account that is not a Risk Admin the transaction will be reverted.
- If addRiskScoreToMultipleAccounts is called by an account that is not a Risk Admin the transaction will be reverted.
- If addMultipleRiskScores is called by an account that is not a Risk Admin the transaction will be reverted. 
- If removeRiskScore is called by an account that is not a Risk Admin the transaction will be reverted.


## [Pause Rule Invariants](../../../../../../test/client/application/invariant/ApplicationAppManagerData.t.i.sol)
- If addPauseRule is called by an account that is not a Rule Admin the transaction will be reverted.
- If removePauseRule is called by an account that is not a Rule Admin the transaction will be reverted.
- If activatePauseRuleCheck is called by an account that is not a Rule Admin the transaction will be reverted.


## [Tags Invariants](../../../../../../test/client/application/invariant/ApplicationAppManagerData.t.i.sol)
- If addTag is called by an account that is not an App Admin the transaction will be reverted.
- If addTagToMultipleAccounts is called by an account that is not an App Admin the transaction will be reverted.
- If addMultipleTagToMultipleAccounts is called by an account that is not an App Admin the transaction will be reverted.
- If removeTag is called by an account that is not an App Admin the transaction will be reverted.


## [Providers](../../../../../../test/client/application/invariant/ApplicationAppManagerData.t.i.sol)
- If proposeRiskScoresProvider is called with an address of 0 the transaction will be reverted.
- If proposeRiskScoresProvider is called by an account that is not an App Admin the transaction will be reverted.
- If proposeTagsProvider is called with an address of 0 the transaction will be reverted.
- If proposeTagsProvider is called by an account that is not an App Admin the transaction will be reverted.
- If proposePauseRulesProvider is called with an address of 0 the transaction will be reverted.
- If proposePauseRulesProvider is called by an account that is not an App Admin the transaction will be reverted.
- If proposeAccessLevelsProvider is called with an address of 0 the transaction will be reverted.
- If proposeAccessLevelsProvider is called by an account that is not an App Admin the transaction will be reverted.

## [Registration](../../../../../../test/client/application/invariant/ApplicationAppManager.t.i.sol)
- If isRegisteredHandler returns false for an address, calling checkApplicationRules from the address will result in the transaction being reverted.
- If registerToken is called with an address of 0 the transaction will be reverted.
- If registerToken is called by an account that is not an App Admin the transaction will be reverted. 
- If deregisterToken is called with the address of a token that is not registered, the transaction will be reverted. 
- If deregisterToken is called by an account that is not an App Admin the transaction will be reverted.  
- If deregisterToken is not reverted the RemoveFromRegistry event will be emitted.

## [Trading Rule Allow List](../../../../../../test/client/application/invariant/ApplicationAppManager.t.i.sol)
- If approveAddressToTradingRuleAllowlist is called by an account that is not an App Admin the transaction will be reverted.
- If an address that has not been previously added is passed in along with a false for isApproved the transaction will be reverted.
- If an address that is already approved is passed in along with a true for isApproved the transaction will be reverted. 
- If approveAddressToTradingRuleAllowList is not reverted the TradingRuleAddressAllowList event will be emitted.
- If setNewApplicationHandlerAddress is called with an address of 0 the transaction will be reverted.
- If setNewApplicationHandlerAddress is called by an account that is not an App Admin the transaction will be reverted. 
- If setNewApplicationHandlerAddress is not reverted the HandlerConnected event will be emitted.
- If setAppName is called by an account that is not an App Admin the transaction will be reverted. 
- If proposeDataContractMigration is called by an account that is not an App Admin the transaction will be reverted. 
- If proposeDataContractMigation is not reverted the AppManagerDataUpgradeProposed event is emitted.

## [New Data Provider](../../../../../../test/client/application/invariant/ApplicationAppManager.t.i.sol)
- When confirmNewDataProvider is called with a provider type of TAG and is not reverted, the TagProviderSet event will be emitted.
- When confirmNewDataProvider is called with a provider type of RISK_SCORE and is not reverted, the RiskProviderSet event will be emitted.
- When confirmNewDataProvider is called with a provider type of ACCESS_LEVEL and is not reverted, the AccessLevelProviderSet event will be emitted.
- When confirmNewDataProvider is called with a provider type of PAUSE_RULE and is not reverted, the PauseRuleProviderSet event will be emitted.

## [Data Migration](../../../../../../test/client/application/invariant/ApplicationAppManager.t.i.sol)
- If confirmDataContractMigration is called by an account that is not an App Admin the transaction will be reverted.
- If confirmDataContractMigration is not reverted the DataContractsMigrated event is emitted.

## [App Manager Upgrade](../../../../../../test/client/application/invariant/ApplicationAppManager.t.i.sol)
- If confirmAppManager is called by an account that is not an App Admin the transaction will be reverted. 



