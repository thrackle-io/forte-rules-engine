# Gas Usage Report

**NOTE: This is a temporary hard-coded report for use during development. This report will be modified and generated dynamically by a script **

## Purpose

This chart shows how individual active rules affect gas consumption of basic token actions.

The gas tests were done using a simple contract with very little overhead. The comparison is between the base usage(Rules engine integrated but with no active rules) and with the rule active and passing.

These gas tests can be run with the following command:

```
forge test --match-test testGasReport -vv --ffi
```

Column Definitions
- Rule = Rule being tested
- Gas = Gas used to evaluate the rule

---
| Rule | Gas |
|:-|:-|
| Using REv2 No Policies Active | 12339 |
| Hardcoding Min Transfer Not Triggered | 844 |
| Using REv2 Min Transfer Not Triggered | 47774 |
| Hardcoding Min Transfer Triggered With Effect | 2477 |
| Using REv2 Min Transfer Triggered With Effect | 51821 |
| Hardcoding Min Transfer With Foreign Call Not Triggered | 1729 |
| Using REv2 Min Transfer With Foreign Call Not Triggered | 57433 |
| Hardcoding Min Transfer With Foreign Call Triggered With Effect | 3362 |
| Using REv2 Min Transfer With Foreign Call Triggered With Event | 61480 |