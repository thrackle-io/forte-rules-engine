# External Oracle
[![Project Version][version-image]][version-url]

External oracles may be used in the protocol. They must conform to the [IOracle](../../../src/common/IOracle.sol) interface. Oracles must be of approved or denied style where the user address is checked for approval or denial.

## Required functions for the External Oracle

### Denial Oracle
```c
function isDenied(address _address) external view returns (bool);
```

### Approval Oracle
```c
function isApproved(address _address) external view returns (bool);
```

NOTE: It is not necessary to implement the [IOracle](../../../src/common/IOracle.sol) interface in the external oracle. The correct function needs only to exist within it.

Sample implementations for each of the above functions can be found in the example oracle contracts.

###### *see [OracleApproved](../../../src/example/OracleApproved.sol)*
###### *see [OracleDenied](../../../src/example/OracleDenied.sol)*

## Process for using an external oracle

External oracles are used in conjunction with the [Account Approve Deny Oracle Rule](../rules/ACCOUNT-APPROVE-DENY-ORACLE.md) or the [Account Approve Deny Oracle Flexible Rule](../rules/ACCOUNT-APPROVE-DENY-ORACLE-FLEXIBLE.md). The external oracle is created and its deployed address is noted. When the oracle rule is created, this address is used in the **_oracleAddress** parameter whereas **_oracleType** corresponds to approved or denied type(0 for denied, 1 for approved).

###### *see [Account Approve Deny Oracle Rule](../rules/ACCOUNT-APPROVE-DENY-ORACLE.md) or [Account Approve Deny Oracle Flexible Rule](../rules/ACCOUNT-APPROVE-DENY-ORACLE-FLEXIBLE.md)*

Once the this rule is created, it can then be applied like any other rule. The process is as follows:

- 1. Deploy the external oracle.
- 2. Create the rule specifying the _oracleAddress and _oracleType. 
    - See [Account Approve Deny Oracle Rule](../rules/ACCOUNT-APPROVE-DENY-ORACLE.md).
    - See [Account Approve Deny Oracle Flexible Rule](../rules/ACCOUNT-APPROVE-DENY-ORACLE-FLEXIBLE.md).
- 3. Apply the rule to the desired token's handler. 
    - See [Account Approve Deny Oracle Rule](../rules/ACCOUNT-APPROVE-DENY-ORACLE.md). 
    - See [Account Approve Deny Oracle Flexbile Rule](../rules/ACCOUNT-APPROVE-DENY-ORACLE-FLEXIBLE.md).
    

<!-- These are the header links -->
[version-image]: https://img.shields.io/badge/Version-2.1.0-brightgreen?style=for-the-badge&logo=appveyor
[version-url]: https://github.com/thrackle-io/forte-rules-engine
