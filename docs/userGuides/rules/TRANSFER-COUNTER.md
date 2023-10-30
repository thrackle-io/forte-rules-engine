# Transfer Counter Rule

## Purpose

The transfer-counter rule enforces a daily limit on the number of trades for each token within a collection. In the context of this rule, a "trade" is a transfer of a token from one address to another. Example uses of this rule: to reduce price volatility of tokens in the collection via the limitation of wash trading or the prevention of malfeasance for holders who transfer a token between addresses repeatedly. When this rule is active and the tradesAllowedPerDay is 0 this rule will act as a pseudo "soulBound" token, preventing all transfers of tokens in the collection.  

## Tokens Supported

- ERC721 

## Scope 

This rule works at a token level. It must be activated and configured for each desired token in the corresponding token handler.

## Data Structure

This is a [tag](../GLOSSARY.md)-based rule, you can think of it as a collection of rules, where all "sub-rules" are independent from each other, and where each "sub-rule" is indexed by its tag. In this case, the tag is applied to the NFT collection address. The transfer counter rule is composed of two components:

- **Trades allowed per day** (uint8): The number of trades allowed per tokenId of the collection while the rule is active 
- **Start timestamp** (uint64): The unix timestamp for the time that the rule starts. 

```c
/// ******** NFT ********
    struct NFTTradeCounterRule {
        uint8 tradesAllowedPerDay;
        uint64 startTs; // starting timestamp for the rule
    }
```
###### *see [RuleDataInterfaces](../../../src/economic/ruleStorage/RuleDataInterfaces.sol)*

Additionally, each one of these data structures will be under a tagged NFT Collection (bytes32):

tag -> token collection (sub-rule).

```c
    //       tag         =>   sub-rule
    mapping(bytes32 => INonTaggedRules.NFTTradeCounterRule)
```
###### *see [IRuleStorage](../../../src/economic/ruleStorage/IRuleStorage.sol)*

The tagged token collections then compose a transfer-counter rule.

 ```c
    struct NFTTransferCounterRuleS {
        /// ruleIndex => taggedNFT => tradesAllowed
        mapping(uint32 => mapping(bytes32 => INonTaggedRules.NFTTradeCounterRule)) NFTTransferCounterRule;
        uint32 NFTTransferCounterRuleIndex; /// increments every time someone adds a rule
    }
```
###### *see [IRuleStorage](../../../src/economic/ruleStorage/IRuleStorage.sol)*

A transfer-counter rule must have at least one sub-rule. There is no maximum number of sub-rules.

### Role Applicability

- **Evaluation Exceptions**: 
    - This rule doesn't apply when an **app administrator** address is in either the *from* or the *to* side of the transaction.

- **Configuration and Enabling/disabling**:
    - This rule can only be configured in the protocol by a **rule administrator**.
    - This rule can only be set in the asset handler by a **rule administrator**.
    - This rule can only be activated/deactivated in the asset handler by a **rule administrator**.
    - This rule can only be updated in the asset handler by a **rule administrator**.

## Rule Evaluation

The rule will be evaluated in the following way:

1. The collection being evaluated will pass to the protocol all the tags it has registered to its address in the application manager.
2. The processor will receive these tags along with the ID of the transfer-counter rule set in the token handler.
3. The processor will then try to retrieve the sub-rule associated with each tag.
4. The processor will evaluate whether the trade is within a new period. If no, the rule will continue to the trades per day check (step 5). If yes, the rule will return `tradesInPeriod` of 1 (current trade) for the token Id. 
5. The processor will evaluate if the total number of trades within the period plus the current trade would be more than the amount of trades allowed per day by the rule in the case of the transaction succeeding. If yes (trades will exceed allowable trades per day), then the transaction will revert.

###### *see [IRuleStorage](../../../src/economic/ruleProcessor/ERC721RuleProcessorFacet.sol) -> checkNFTTransferCounter*

### Create Function

Adding a transfer-counter rule is done through the function:

```c
function addNFTTransferCounterRule(
        address _appManagerAddr,
        bytes32[] calldata _nftTypes,
        uint8[] calldata _tradesAllowed,
        uint64 _startTs
    ) external ruleAdministratorOnly(_appManagerAddr) returns (uint32)
```
bytes32 _nftTypes are the same as [tags](../GLOSSARY.md) and are applied to the ERC721 contract address in the App Manager. 

The create function in the protocol needs to receive the appManager address of the application in order to verify that the caller has Rule administrator privileges. 

The function will return the protocol id of the rule.

###### *see [RuleDataFacet](../../../src/economic/ruleStorage/RuleDataFacet.sol)*

### Revert Message

The rule processor will revert with the following error if the rule check fails: 

```
error MaxNFTTransferReached();
```

The selector for this error is `0x00b223e3`.

### Parameter Optionality:

The parameters where developers have the options are:
- **_startTimestamps**: developers can pass Unix timestamps or simply 0s. If a `startTimestamp` is 0, then the protocol will interpret this as the timestamp of rule creation. 
- **_tradesAllowed**: developers can pass the amount of trades allowed for each tag `_nftTypes` given at creation. The protocol will validate each allowable trade limit based on the tag(s) added to the collection address. 

### Parameter Validation:

The following validation will be carried out by the create function in order to ensure that these parameters are valid and make sense:

- `_appManagerAddr` is not the zero address.
- All the parameter arrays have at least one element.
- All the parameter arrays have the exact same length.
- Not one `tag` can be a blank tag.


###### *see [TaggedRuleDataFacet](../../../src/economic/ruleStorage/TaggedRuleDataFacet.sol)*

## Other Functions:

- In Protocol [Storage Diamond]((../../../src/economic/ruleStorage/TaggedRuleDataFacet.sol)):
    -  Function to get a rule by its ID:
        ```c
        function getNFTTransferCounterRule(
                    uint32 _index, 
                    bytes32 _nftType
                ) 
                external 
                view 
                returns 
                (TaggedRules.NFTTradeCounterRule memory);
        ```
    - Function to get current amount of rules in the protocol:
        ```c
        function getTotalNFTTransferCounterRules() public view returns (uint32);
        ```
- In Protocol [Rule Processor](../../../src/economic/ruleProcessor/ERC721TaggedRuleProcessorFacet.sol):
    - Function that evaluates the rule:
        ```c
        function checkNFTTransferCounter(
                    uint32 ruleId, 
                    uint256 transfersWithinPeriod, 
                    bytes32[] calldata nftTags
                ) 
                external 
                view;
        ```
- in Asset Handler:
    - Function to set and activate at the same time the rule in an asset handler:
        ```c
        function setTradeCounterRuleId(uint32 _ruleId) external ruleAdministratorOnly(appManagerAddress);
        ```
    - Function to activate/deactivate the rule in an asset handler:
        ```c
        function activateTradeCounterRule(bool _on) external ruleAdministratorOnly(appManagerAddress);
        ```
    - Function to know the activation state of the rule in an asset handler:
        ```c
        function isTradeCounterRuleActive() external view returns (bool);
        ```
    - Function to get the rule Id from an asset handler:
        ```c
        function getTradeCounterRuleId() external view returns (uint32);
        ```

### Return Data

This rule returns a new tradesInPeriod(uint256) to the token handler on success.

```c
mapping(uint256 => uint256) tradesInPeriod;
```
###### *see [ERC721Handler](../../../src/token/ERC721/ProtocolERC721Handler.sol)*
### Data Recorded

This rule requires that the handler record the timestamp for each tokenId's last trade. This is recorded only after the rule is activated and after each successful transfer. 
```c
mapping(uint256 => uint64) lastTxDate;
```
###### *see [ERC721Handler](../../../src/token/ERC721/ProtocolERC721Handler.sol)*
### Events

- **ProcotolRuleCreated(bytes32 indexed ruleType, uint32 indexed ruleId, bytes32[] extraTags)** emitted when a Transfer counter rule has been added. For this rule:
    - ruleType: NFT_TRANSFER
    - index: the rule index set by the Protocol
    - extraTags: an empty array.
- **ApplicationHandlerApplied(bytes32 indexed ruleType, address indexed handlerAddress, uint32 ruleId)** emitted when a Transfer counter rule has been added. For this rule:
    - ruleType: NFT_TRANSFER
    - handlerAddress: the address of the asset handler where the rule has been applied
    - ruleId: the index of the rule created in the protocol by rule type 
- **ApplicationHandlerActivated(bytes32 indexed ruleType, address indexed handlerAddress)** emitted when a Transfer counter rule has been activated in an asset handler:
    - ruleType: NFT_TRANSFER
    - handlerAddress: the address of the asset handler where the rule has been activated

### Dependencies

- **Tags**: This rule relies on NFT Collections having [tags](../GLOSSARY.md) registered in their [AppManager](../GLOSSARY.md), and they must match the tag in the rule for it to have any effect.