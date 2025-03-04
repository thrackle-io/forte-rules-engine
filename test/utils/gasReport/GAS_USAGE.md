# Gas Usage Report

**NOTE: This is a temporary hard-coded report for use during development. This report will be modified and generated dynamically by a script **

## Purpose

This chart shows how individual active rules affect gas consumption of basic token actions.

The gas tests were done using a simple contract with very little overhead. The comparison is between the base usage(Rules engine integrated but with no active rules) and with the rule active and passing.

These gas tests can be run with the following command:

```
forge test --ffi --match-test testGas -vv 
```

Column Definitions
- Rule = Rule being tested
- Gas = Gas used to evaluate the rule

---
| Rule | Gas |
|:-|:-|
| Base | 42851 |
| Using REv2 No Policies Active | 57073 |
| Hardcoding Min Transfer Revert | 44980 |
| Using REv2 Min Transfer With Revert | 109836 |
| Hardcoding Multiple Min Transfer Revert | 93922 |
| Using REv2 Multiple Min Transfer Revert | 584781 |
| Hardcoding With Foreign Call | 50354 |
| Using REv2 With Foreign Call | 122105 |
| Hardcoding Min Transfer With Foreign Call | 52485 |
| Using REv2 Min Transfer With Foreign Call | 169197 |
| Hardcoding Min And Max Transfer With Foreign Call | 52505 |
| Using REv2 Min And Max Transfer With Foreign Call | 216048 |

