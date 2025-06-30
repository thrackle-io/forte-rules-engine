# Test Archecture 

This file is to serve as a visual aide for the Rules Engine Testing Suite.  


The directory structure is: 
```
test 
├── validation
│ ├── adminRoles
| │ └── adminRoles.t.sol
│ ├── components
| │ └── components.t.sol 
│ ├── forkTests 
| │ └──forkTests.t.sol
│ ├── policy 
| │ └──policy.t.sol
│ └── rules
|   └──rules.t.sol
├── execution 
│ ├── diamondInternalFunctions
| │ └──diamondInternalFunctions.t.sol 
│ ├── rulesEngineInternalFunctions
| │ └──rulesEngineInternalFunctions.t.sol 
│ ├── effects
| │ └── effects.t.sol
│ ├── foreignCalls
| │ └── foreignCalls.t.sol 
│ ├── instuctionSet
| │ └── instructionSet.t.sol 
│ ├── runFunction
| │ └── runFunction.t.sol
│ └── trackers 
|   └── trackers.t.sol 
│ └── rulesExecution
|   └──rulesExecution.t.sol
│ └── policies
|   └──policiesExecution.t.sol
├── rulesEngine
│ └── rulesEngineUnitTest.t.sol
├── token
│ ├── ERC1155
│ ├── ERC721A
│ ├── ERC721
│ ├── ERC20
├── invariants 
└── utils
    └── GasReports 

```
Each directory above will contain unit test files. Some may contain helper function files, fuzz tests or various util functions. Unit test files are named with the directory level name + `.t.sol`. For different types such as fuzz a descriptor should be added to the file name, e.g. adminRolesFuzz.t.sol to deliniate the type of test inside the file, without needing to open (help keep navigation easy!). 

When adding new tests make effort to consolidate everything needed for that tests directory, within the directory only. 

Shared utility and set up files should be in utils directory (if more than one directory shares, it goes in utils). 

For individual testing directories requirements reference the Rules Engine Testing Scope doc. 




Remaining Tests Strategy: 

Each validation test should consist of at least: 
Create 
Update 
Delete 
Get 
Event 

Any additional validations necessary for that specific directory. 

Execution tests should consist of at least: 
Positive 
Negative 
-1,0,1 tests (meaning below the executing conditional, at the conditional and above the conditional)
        i.e. minBalance rule conditional would execute tests for below the min, at the min and above the min value. 

Any additional executions necessary for that specific directory.


Gas Snapshots taken and stored inside of: 
snapshots
    RulesEngineUnitTests.json 

These snapshots are used for development and may not reflect real world gas costs. These should only be used as an indicator for changes to gas consuption over time. 

For "real world" gas reporting see test/utils/gasReport/GasReport.t.sol

