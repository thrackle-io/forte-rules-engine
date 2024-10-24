# Account Approve Deny Oracle Rule

## Purpose

The purpose of the account-approve-deny-oracle rule is to check if an address in the transaction is an approved or denied address. Addresses are added to the oracle lists by the owner of the oracle contract for any reason that the owner deems necessary. Oracle rules are applied per [action type](./ACTION-TYPES.md) and for burn and sell actions the sender address is checked. For all other actions, the receiver address is checked. 

If an address is not on an approved oracle list, they will be denied from receiving application tokens. This rule can be used to restrict transfers to only specific contract addresses or wallets that are approved by the oracle owner. An example is NFT exchanges that support ERC2981 royalty payments. 

The deny list is designed as a tool to reduce the risk of malicious actors in the ecosystem. If an address is on the deny oracle list they are denied receiving tokens. Any address not on the deny list will pass this rule check.

## Applies To:

- [x] ERC20
- [x] ERC721

## Applies To Actions:

- [x] MINT
- [x] BURN
- [x] BUY
- [x] SELL
- [x] TRANSFER(Peer to Peer)

## Scope 

This rule works at the token level. It must be activated and configured for each desired token in the corresponding token handler. When configured at a token level, each token can have a maximum of 10 oracle rules associated with it.

## Data Structure

An account-approve-deny-oracle rule is composed of 2 components:

- **Oracle Type** (uint8): The Type of Oracle (0 for denied, 1 for approved).
- **Oracle Address** (address): The address of the approve Oracle contract. 

```c
/// ******** Oracle ********
struct AccountApproveDenyOracle {
    uint8 oracleType; /// enum value --> 0 = denied; 1 = approved
    address oracleAddress;
}
```
###### *see [RuleDataInterfaces](../../../src/protocol/economic/ruleProcessor/RuleDataInterfaces.sol)*

The approve-oracle rules are stored in a mapping indexed by ruleId(uint32) in order of creation:

 ```c
/// ******** Oracle ********
struct AccountApproveDenyOracleS {
    mapping(uint32 => INonTaggedRules.AccountApproveDenyOracle) accountApproveDenyOracleRules;
    uint32 accountApproveDenyOracleIndex;
}
```
###### *see [IRuleStorage](../../../src/protocol/economic/ruleProcessor/IRuleStorage.sol)*

## Configuration and Enabling/Disabling
- This rule can only be configured in the protocol by a **rule administrator**.
- This rule can only be set in the asset handler by a **rule administrator**.
- This rule can only be activated/deactivated in the asset handler by a **rule administrator**.
- This rule can only be updated in the asset handler by a **rule administrator**.

## Rule Evaluation

The rule will be evaluated with the following logic (this logic will be evaluated for each oracle rule associated with the token):

1. The handler determines if the rule is active from the supplied action. If not, processing does not continue past this step.
2. The processor will receive the ID of the approve-oracle rule set in the application handler. 
3. The processor will receive the address that is to be checked in the oracle.
4. The processor will determine the type of oracle based on the rule id. 
5. The processor will then call the oracle address to check if the address to be checked is on the oracle's list: 
- Action types of Mint: check if the receiver address is an approved address. If the address is not on the approved list the transaction will revert. 
- Action types of Burn: check if the sender is a denied address. If the address is denied the transaction will revert.
- Action types of Transfer, Sell, Buy: 
    - Deny Oracle: check if the sender or receiver is a denied address. If either address is denied the transaction will revert.
    - Approve Oracle: check if the sender or receiver is an approved address. If neither address is approved the transaction will revert.

**The list of available actions rules can be applied to can be found at [ACTION_TYPES.md](./ACTION-TYPES.md)**

###### *see [ERC20RuleProcessorFacet](../../../src/protocol/economic/ruleProcessor/ERC20RuleProcessorFacet.sol) -> checkAccountApproveDenyOracle*

## Evaluation Exceptions 
- This rule doesn't apply when a **treasuryAccount** address is in either the *from* or the *to* side of the transaction. This doesn't necessarily mean that if an treasury account is the one executing the transaction it will bypass the rule, unless the aforementioned condition is true.

### Revert Message

The rule processor will revert with one of the following errors if the rule check fails: 

```
error AddressNotApproved();
```

The selector for this error is `0xcafd3316`.

```
error AddressIsDenied();
```

The selector for this error is `0x2767bda4`.

When adding an oracle rule to a token, if there are already 10 oracle rules associated the handler will revert with the following error:

```
error AccountApproveDenyOraclesPerAssetLimitReached();
```

The selector for this error is `0xcafd3316`.

## Create Function

Adding an account-approve-deny-oracle rule is done through the function:

```c
function addAccountApproveDenyOracle(
    address _appManagerAddr, 
    uint8 _type, 
    address _oracleAddress
) external ruleAdministratorOnly(_appManagerAddr) returns (uint32);
```
###### *see [RuleDataFacet](../../../src/protocol/economic/ruleProcessor/RuleDataFacet.sol)*

The add function will return the protocol ID of the rule.

### Parameters:

- **_appManagerAddr** (address): The address of the application manager to verify that the caller has Rule administrator privileges.
- **_oracleType** (uint8): The type of oracle for this rule (0 for denied, 1 for approved).
- **_oracleAddress** (address): the address of the approve oracle.


### Parameter Optionality:

There is no parameter optionality for this rule. 

### Parameter Validation:

The following validation will be carried out by the add function in order to ensure that these parameters are valid and make sense:

- `_appManagerAddr` is not the zero address.
- `_oracleAddress` is not the zero address. 
- `_type` is not greater than 1. 


###### *see [RuleDataFacet](../../../src/protocol/economic/ruleProcessor/RuleDataFacet.sol)*

## Other Functions:

- In Protocol [ERC20RuleProcessorFacet](../../../src/protocol/economic/ruleProcessor/ERC20RuleProcessorFacet.sol):
    -  Function to get a rule by its ID:
        ```c
        function getAccountApproveDenyOracle(
                    uint32 _index
                ) 
                external 
                view 
                returns 
                (NonTaggedRules.AccountApproveDenyOracle memory);
        ```
    - Function to get current amount of rules in the protocol:
        ```c
        function getTotalAccountApproveDenyOracle() public view returns (uint32);
        ```
- In Protocol [ERC20RuleProcessorFacet](../../../src/protocol/economic/ruleProcessor/ERC20RuleProcessorFacet.sol):
    - Function that evaluates the rule:
        ```c
        function checkAccountApproveDenyOracle(
                    uint32 _ruleId, 
                    address _address
                    ) 
                    external 
                    view;
        ```
- in Asset Handler:
    - Function to set and activate at the same time the rule in an asset handler:
        ```c
        function setAccountApproveDenyOracleId(ActionTypes[] calldata _actions, uint32 _ruleId) external ruleAdministratorOnly(appManagerAddress);
        ```
    - Function to activate/deactivate the rule for the supplied actions in an asset handler:
        ```c
        function activateAccountApproveDenyOracle(ActionTypes[] calldata _actions, bool _on, uint32 ruleId) external ruleAdministratorOnly(appManagerAddress);
        ```
    - Function to know the activation state of the rule for the supplied action in an asset handler:
        ```c
        function isAccountApproveDenyOracleActive(ActionTypes _action, uint32 ruleId) external view returns (bool);
        ```
    - Function to get the rule Ids for the supplied action from an asset handler:
        ```c
        function getAccountApproveDenyOracleIds(ActionTypes _action) external view returns (uint32);
        ```
    - Function to remove a rule:
        ```c
        function removeAccountApproveDenyOracle(uint32 ruleId) external;
        ```
## Return Data

This rule does not return any data.

## Data Recorded

This rule does not require any data to be recorded. 

## Events

- **event AD1467_ProtocolRuleCreated(bytes32 indexed ruleType, uint32 indexed ruleId, bytes32[] extraTags)**: 
    - Emitted when: the rule has been created in the protocol.
    - Parameters:
        - ruleType: "ACCOUNT_APPROVE_DENY_ORACLE".
        - ruleId: the index of the rule created in the protocol by rule type.
        - extraTags: an empty array.

- **event AD1467_ApplicationHandlerActionApplied(bytes32 indexed ruleType, ActionTypes action, uint32 indexed ruleId)**:
    - Emitted when: rule has been applied in an asset handler.
    - Parameters: 
        - ruleType: "ACCOUNT_APPROVE_DENY_ORACLE".
        - action: the protocol action the rule is being applied to.
        - ruleId: the index of the rule created in the protocol by rule type.
        
- **event AD1467_ApplicationHandlerActionActivated(bytes32 indexed ruleType, ActionTypes actions, uint256 indexed ruleId)** 
    - Emitted when: rule has been activated in the asset handler.
    - Parameters:
        - ruleType: "ACCOUNT_APPROVE_DENY_ORACLE".
        - actions: the protocol actions for which the rule is being activated.
        - ruleId: the id of the rule to activate.
- **event AD1467_ApplicationHandlerActionDeactivated(bytes32 indexed ruleType, ActionTypes actions, uint256 indexed ruleId)** 
    - Emitted when: rule has been deactivated in the asset handler.
    - Parameters:
        - ruleType: "ACCOUNT_APPROVE_DENY_ORACLE".
        - actions: the protocol actions for which the rule is being deactivated.
        - ruleId: the id of the rule to deactivate.

## Dependencies

- This rule is dependant on a deployed oracle with either of the function signatures:

```c
function isDenied(address _address) external view returns (bool)
```
```c
function isApproved(address _address) external view returns (bool)
```
