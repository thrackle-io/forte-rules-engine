# Gas Usage Report

**Last Updated:** 2025-07-21 09:58:05 UTC  
**Generated automatically by:** `script/reportGas.sh`

## Purpose

This chart shows how individual active rules affect gas consumption of basic token actions.

The gas tests were done using a simple contract with very little overhead. The comparison is between the base usage (Rules engine integrated but with no active rules) and with the rule active and passing.

These gas tests can be run with the following commands:

**Rules Engine Tests:**
```bash
forge test -vvv --ffi --match-path test/utils/gasReport/GasReport.t.sol
```

**Hardcoded Baseline Tests:**
```bash
forge test -vv --ffi --match-path test/utils/gasReport/GasReportHardcoded.t.sol
```

Or regenerate this entire report with:

```bash
bash ./script/reportGas.sh
```

## Gas Usage Results

Column Definitions:
- Rule = Rule being tested
- Gas = Gas used to evaluate the rule

---

| Rule | Gas |
|:-|:-|
| Base | 42827 |
| Hardcoding Many Min Transfer Revert | 93898 |
| Hardcoding Min Transfer Revert | 44956 |
| Hardcoding OFAC deny list | 50441 |
| Hardcoding OFAC deny list | 53476 |
| Hardcoding OFAC deny list with min and max balance transfer | 47599 |
| Hardcoding OFAC deny list with min and max transfer | 52592 |
| Hardcoding OFAC deny list with min transfer | 52572 |
| Hardcoding OFAC deny list with pause transfer | 42827 |
| Using REv2 Event Effect with min transfer gas report | 150207 |
| Using REv2 Min Transfer Triggered With Revert Effect | 115934 |
| Using REv2 No Policies Active | 56984 |
| Using REv2 OFAC gas report | 130779 |
| Using REv2 OFAC with min and max transfer gas report | 227900 |
| Using REv2 OFAC with min transfer gas report | 156747 |
| Using REv2 OFAC with min transfer gas report | 179435 |
| Using REv2 OFAC with min transfer gas report | 187237 |
| Using REv2 Oracle Flex gas report | 177868 |
| Using REv2 Pause Rule gas report | 112065 |
| Using REv2 min transfer 20 iterations | 601161 |

## Gas Snapshots

The following snapshots are taken from automated test runs and represent comprehensive gas usage across the entire test suite:

| Test | Gas Used |
|:-|:-|
| Additional_Encoding_Address_Value | 29507 |
| Additional_Encoding_Bool_Value | 29626 |
| Additional_Encoding_Bytes_Value | 26500 |
| Additional_Encoding_DynamicArray_Value | 32856 |
| Additional_Encoding_ForeignCall_Value | 34036 |
| Additional_Encoding_StaticArray_Value | 30782 |
| Additional_Encoding_String_Value | 30921 |
| Additional_Encoding_Uint_Value | 33554 |
| CheckRules_Event_CustomParams_Address | 34556 |
| CheckRules_Event_CustomParams_Bool | 34614 |
| CheckRules_Event_CustomParams_Bytes32 | 34553 |
| CheckRules_Event_CustomParams_String | 35866 |
| CheckRules_Event_CustomParams_Uint | 34430 |
| CheckRules_Event_DynamicParams_Address | 37669 |
| CheckRules_Event_DynamicParams_Uint | 37495 |
| CheckRules_Event | 35878 |
| CheckRules_Explicit_WithTrackerUpdateEffectAddress | 38967 |
| CheckRules_Explicit_WithTrackerUpdateEffectBool | 58867 |
| CheckRules_Explicit_WithTrackerUpdateEffectBytes | 106596 |
| CheckRules_Explicit_WithTrackerUpdateEffectString | 106596 |
| CheckRules_Explicit_WithTrackerUpdateEffectUint | 38931 |
| CheckRules_Explicit | 21220 |
| CheckRules_Multiple_Positive_Event | 42757 |
| CheckRules_Revert | 31195 |
| CheckRules_WithTrackerValue | 38488 |
| MappedTrackerAsConditional_AddressToAddress | 36549 |
| MappedTrackerAsConditional_AddressToBool | 36559 |
| MappedTrackerAsConditional_AddressToString | 37611 |
| MappedTrackerAsConditional_AddressToUint | 36477 |
| MappedTrackerAsConditional_BoolToAddress | 36559 |
| MappedTrackerAsConditional_BoolToUint | 36596 |
| MappedTrackerAsConditional_StringToAddress | 37238 |
| MappedTrackerAsConditional_UintToAddress | 36513 |
| MappedTrackerAsConditional_UintToBool | 36596 |
| MappedTrackerAsConditional_UintToUint | 34857 |
| MappedTrackerAsConditional_Uint_Positive | 36450 |
| MappedTrackerUpdatedFromEffects_AddressToAddress | 41739 |
| MappedTrackerUpdatedFromEffects_AddressToBool | 61639 |
| MappedTrackerUpdatedFromEffects_AddressToUint | 41739 |
| MappedTrackerUpdatedFromEffects_UintToUint | 41550 |
| PauseRuleRecreation | 58100 |
| checkRule_ForeignCall_ForeignCallReferenced | 59854 |
| checkRule_ForeignCall_TrackerValuesUsed | 33575 |
| checkRule_ForeignCall | 60156 |
| checkRule_simpleGTEQL | 26654 |
| checkRule_simpleLTEQL | 26683 |
| checkRule_simple_GT | 28995 |

---
