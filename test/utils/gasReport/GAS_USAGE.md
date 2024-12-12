# Gas Usage Report

**NOTE: This is a temporary hard-coded report for use during development. This report will be modified and generated dynamically by a script **

## Purpose

This chart shows how individual active rules affect gas consumption of basic token actions.

The gas tests were done using a simple contract with very little overhead. The comparison is between the base usage(Rules engine integrated but with no active rules) and with the rule active and passing.

These gas tests can be run with the following command:

```
forge test --match-contract GasReports -vv --ffi
```

Column Definitions
- Rule = Rule being tested
- Gas = Gas used to evaluate the rule

---
| Rule | Gas |
|:-|:-|
| Hardcoding Min Transfer Not Triggered | 838 |
| Using REv2 Min Transfer Not Triggered | 47774 |
| Hardcoding Min Transfer Triggered With Effect | 2461 |
| Using REv2 Min Transfer Triggered With Effect | 51821 |
| Hardcoding Min Transfer With Foreign Call Not Triggered | 6620 |
| Using REv2 Min Transfer With Foreign Call Not Triggered | 62333 |
| Hardcoding Min Transfer With Foreign Call Triggered With Effect | 8243 |
| Using REv2 Min Transfer With Foreign Call Triggered With Event | 66380 |