# Test Archecture 

This file is to aid in transitioning tests to the new test directory architecture and should be removed with the final PR for this effort. 


The new directory structure is: 

``
test 
├── validation
│ ├── adminRoles
│ ├── components
│ ├── policy 
│ └── rules
├── execution 
│ ├── diamondInternalFunctions
│ ├── effects
│ ├── foreignCalls
│ ├── instuctionSet
│ ├── runFunction
│ └── trackers 
├── invariants 
└── utils

``
Each directory above will contain unit test files. Some may need to contain helper function files, fuzz tests or various util functions. 

Make effort to consolidate everything needed for each test directory to be contained within the directory only. 

Shares utility and set up files should be in utils directory (if more than one directory shares, it goes in utils). 

For individual testing directories requirements reference the Rules Engine Testing Scope doc. 

!! REMOVE ONCE TESTS ARE IN NEW ARCHECTURE  !!
