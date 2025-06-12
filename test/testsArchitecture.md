# Test Archecture 

This file is to aid in transitioning tests to the new test directory architecture and should be removed with the final PR for this effort. 


The new directory structure is: 

``
test 
├── validation
│ ├── adminRoles
| │ └── adminRoles.t.sol
│ ├── components
| │ └── components.t.sol 
│ ├── policy 
| │ └──policy.t.sol
│ └── rules
|   └──rules.t.sol
├── execution 
│ ├── diamondInternalFunctions
| │ └──diamondInternalFunctions.t.sol 
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
├── invariants 
└── utils
    └── GasReports 

``
Each directory above will contain unit test files. Some may need to contain helper function files, fuzz tests or various util functions. It should be assumed that unit test files are the directory level name + `.t.sol`. For different types such as fuzz a descriptor should be added to the file name, e.g. adminRolesFuzz.t.sol to deliniate the type of test inside the file, without needing to open (help keep navigation easy!). 

Make effort to consolidate everything needed for each test directory to be contained within the directory only. 

Shares utility and set up files should be in utils directory (if more than one directory shares, it goes in utils). 

For individual testing directories requirements reference the Rules Engine Testing Scope doc. 

Strategy for tests migration: 

1. Move shared files and set up files to the proper directories first and ensure

2. Copy tests into their proper test files and ensure the tests still run 

3. Comment or remove the test from the improper test file (comment if swarming / remove if solo). 

4. Remove test files, directories and THIS DOCUMENT when all tests have been migrated. 

!! REMOVE ONCE TESTS ARE IN NEW ARCHECTURE  !!
