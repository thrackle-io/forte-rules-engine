# Protocol Fee Structure 

## Purpose

This document outlines the overall fee structure of the protocol, how fees are applied and at what level the fees are applied. Each fee type has its own documentation associated to the specifics of that Fee type and are stored in the [fee guide](./README.md).

A Fee data contract is deployed at the same time as the token handler. All supporting fee data is stored in this contract and owned by the handler. Data contracts can be migrated to a new handler in the event of an upgrade so that fee data is not lost. Only the previous handler owner or [app administrators](../../userGuides/permissions/ADMIN-ROLES.md) can migrate the data contracts. Migrations to a new handler are completed through a two step migration process.

Fees are applied to accounts via general tags in the [AppMananger](../../../src/client/application/AppManager.sol). Each Fee applied via tags to an account can be additive (increase the fee amount owed) or subtractive (reduce the fee amount owed) and are expressed in basis points.

Protocol supported tokens will always assess all fees assigned to the account executing the current function. If a token has fees active and an account is tagged with applicable fees or a blank tag is used to assign a default fee, those fees are assessed on token transfers (additive). Token fees are assessed and taken from the token itself, not a collateralized token, when fees are active in the token handler. 

Fees are transferred to fee sink addresses when a fee is created for the token. These addresses will be subject to all active token and application level [rules](../rules/README.md). In order for fees to function in conjunction with other enabled rules, it is recommended the fee sink address be granted the role of [Treasury Account](../permissions/ADMIN-ROLES.md). If a fee sink address is granted the Treasury account role, that address will be exempt from all rule checks. 


## Applies To:

- [x] ERC20
- [ ] ERC721

## Scope 
### Token Fees:
Token Fees work at the token level. Fees must be activated and configured for each token in the corresponding token handler. Token fees are assessed in the transfer function of the token. This requires that the token inherit from ApplicationERC20 
or add the transfer function group to the token contract. 

###### *see [ApplicationERC20](../../../src/example/ERC20/ApplicationERC20.sol)*


## Data Structure
Fees are stored in a struct inside the Fees data contract. 

```c
struct Fee {
        uint256 minBalance;
        uint256 maxBalance;
        int24 feePercentage;
        address feeSink;
    }
```
- **minBalance** (uint256): minimum balance for fee application 
- **maxBalance** (uint256): maximum balance for fee application 
- **feePercentage** (int24): fee percentage to assess in basis units (-10000 to 10000)
- **feeSink** (address): address of the fees recipient account 

Each Fee struct is stored in a mapping by the bytes32 tag associated to that fee: 
```c
///     tag   => Fee struct 
mapping(bytes32 => Fee) feesByTag;
```

###### *see [Fees](../../../src/client/token/handler/ruleContracts/Fees.sol)*

## Configuration and Enabling/Disabling
- Fees can only be configured in the asset handler by a **rule administrator**.
- Fees can only be added in the asset handler by a **rule administrator**.
- Fees can only be removed in the asset handler by a **rule administrator**.

## Fees Evaluation

### Token Evaluation: 
The token determines if the handler has fees active. 
The token retrieves all applicable fees for the account transferring tokens (msg.sender).
The token loops through each applicable fee and sends that amount from the transfer total to the `feeSink` for that fee. The total amount of fees assesed is tracked within the transfer as `fees`, upon complettion of the loop the amount of tokens minus the `fees` is transferred to the recipient of the transaction.  


###### *see an example [UtilApplicationERC20](../../../test/util/UtilApplicationERC20.sol) -> transfer*

## Evaluation Exceptions 
- There are no evaluation exceptions when fees are active. Fees are assessed in the token transfer function for token fees. No exceptions are made for the assessment of fees. If an address or account should not have fees assessed, there should not be a tag applied to it.

### Revert Message

The transaction will revert with the following error if Fees are higher than transfer amount: 

```
error FeesAreGreaterThanTransactionAmount();
```

The selector for this error is `0x248ee764`.


## Add Function

Adding a fee is done through the function:

```c
function addFee(bytes32 _tag, uint256 _minBalance, uint256 _maxBalance, int24 _feePercentage, address _targetAccount)   external ruleAdministratorOnly(appManagerAddress); 
```
###### *see [Fees](../../../src/client/token/handler/ruleContracts/Fees.sol)*

### Parameters:

- **_tag** (bytes32): tag for fee application to an account.
- **minBalance** (uint256): minimum balance for fee application 
- **maxBalance** (uint256): maximum balance for fee application 
- **feePercentage** (int24): fee percentage to assess in basis units (-10000 to 10000)
- **_targetAccount** (address): address of the fees recipient account 

This create function allows for fees to be applied via a blank tag and will work as a default fee for all accounts. Additional tags applied to account will resault in additional fees being assessed for that account. Accounts can have up to 10 tags per account and can reflect both additive fees or deductive fees (discounts). 

### Parameter Optionality:

There are no options for the parameters of this function.

### Parameter Validation:

The following validation will be carried out by the create function in order to ensure that these parameters are valid and make sense:

- The `minBalance` is less than `maxBalance`.
- `feePercentage` is greater than -10000 and less than 10000.
- `feePercentage` is not equal to 0.
- `targetAccount` is not the zero address. 

###### *see [Fees](../../../src/client/token/handler/ruleContracts/Fees.sol)*

## Other Functions:

- In [Fees](../../../src/client/token/handler/ruleContracts/Fees.sol):
    -  Function to remove a fee:
        ```c
        function removeFee(bytes32 _tag) external onlyOwner;
        ```
    -  Function to get a fee:
        ```c
        function getFee(bytes32 _tag) public view onlyOwner returns (Fee memory);
        ```
    -  Function to get total nuber of fees:
        ```c
        function getFeeTotal() external view onlyOwner returns (uint256)
        ```
    -  Function to propose new data contract owner:
        ```c
        function proposeOwner(address _newOwner) external onlyOwner;
        ```
    -  Function to confirm new data contract owner:
        ```c
        function confirmOwner() external;
        ```

## Return Data

When assessing fees the function getApplicableFees() returns: 
- **feeSinks** (address[]): List of fee recipient addresses
- **feePercentagess** (int24[]): List of fee percentages 

## Data Recorded

Fee totals are added inside of a loop and then total fees are subtracted from the amount being transferred within the transfer function. This data is not saved to storage. 

## Events

- **FeeType(bytes32 indexed tag, bool indexed add, uint256 minBalance, uint256 maxBalance, int256 feePercentage, address targetAccount)**: emitted when:
    - A fee has been added. In this case, the `add` field of the event will be *true*.
    - A fee has been removed. In this case, the `add` field of the event will be *false*.

## Dependencies

- **Tags**: This rule relies on accounts having [tags](../GLOSSARY.md) registered in their [AppManager](../GLOSSARY.md), and they should match at least one of the tags in the rule for it to have any effect.