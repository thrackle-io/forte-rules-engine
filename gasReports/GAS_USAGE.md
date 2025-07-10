# Gas Usage Report

**Last Updated:** 2025-07-10 12:53:17 UTC  
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
./script/reportGas.sh
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
| Using REv2 Event Effect with min transfer gas report | 161310 |
| Using REv2 Min Transfer Triggered With Revert Effect | 117609 |
| Using REv2 No Policies Active | 56984 |
| Using REv2 OFAC gas report | 137136 |
| Using REv2 OFAC with min and max transfer gas report | 242594 |
| Using REv2 OFAC with min transfer gas report | 163225 |
| Using REv2 OFAC with min transfer gas report | 189966 |
| Using REv2 OFAC with min transfer gas report | 197768 |
| Using REv2 Oracle Flex gas report | 193856 |
| Using REv2 Pause Rule gas report | 123110 |
| Using REv2 min transfer 20 iterations | 604903 |

## Gas Snapshots

The following snapshots are taken from automated test runs and represent comprehensive gas usage across the entire test suite:

| Test | Gas Used |
|:-|:-|
| Additional_Encoding_Address_Value | 28629 |
| Additional_Encoding_Bool_Value | 28866 |
| Additional_Encoding_Bytes_Value | 26325 |
| Additional_Encoding_DynamicArray_Value | 31913 |
| Additional_Encoding_ForeignCall_Value | 33081 |
| Additional_Encoding_StaticArray_Value | 29839 |
| Additional_Encoding_String_Value | 30685 |
| Additional_Encoding_Uint_Value | 32651 |
| CheckRules_Event_CustomParams_Address | 32222 |
| CheckRules_Event_CustomParams_Bool | 32280 |
| CheckRules_Event_CustomParams_Bytes32 | 32218 |
| CheckRules_Event_CustomParams_String | 33569 |
| CheckRules_Event_CustomParams_Uint | 32096 |
| CheckRules_Event_DynamicParams_Address | 36022 |
| CheckRules_Event_DynamicParams_Uint | 35848 |
| CheckRules_Event | 33581 |
| CheckRules_Explicit_WithTrackerUpdateEffectAddress | 35829 |
| CheckRules_Explicit_WithTrackerUpdateEffectBool | 55729 |
| CheckRules_Explicit_WithTrackerUpdateEffectBytes | 104167 |
| CheckRules_Explicit_WithTrackerUpdateEffectString | 104167 |
| CheckRules_Explicit_WithTrackerUpdateEffectUint | 35712 |
| CheckRules_Explicit | 18886 |
| CheckRules_Multiple_Positive_Event | 40494 |
| CheckRules_Revert | 28854 |
| CheckRules_WithTrackerValue | 37570 |
| MappedTrackerAsConditional_AddressToAddress | 31410 |
| MappedTrackerAsConditional_AddressToBool | 31536 |
| MappedTrackerAsConditional_AddressToString | 33873 |
| MappedTrackerAsConditional_AddressToUint | 31293 |
| MappedTrackerAsConditional_BoolToAddress | 31536 |
| MappedTrackerAsConditional_BoolToUint | 31574 |
| MappedTrackerAsConditional_StringToAddress | 31985 |
| MappedTrackerAsConditional_UintToAddress | 31410 |
| MappedTrackerAsConditional_UintToBool | 31846 |
| MappedTrackerAsConditional_UintToUint | 27831 |
| MappedTrackerAsConditional_Uint_Positive | 31293 |
| MappedTrackerUpdatedFromEffects_AddressToAddress | 39966 |
| MappedTrackerUpdatedFromEffects_AddressToBool | 59866 |
| MappedTrackerUpdatedFromEffects_AddressToUint | 39966 |
| MappedTrackerUpdatedFromEffects_UintToUint | 39670 |
| PauseRuleRecreation | 58630 |
| checkRule_ForeignCall_ForeignCallReferenced | 58218 |
| checkRule_ForeignCall_TrackerValuesUsed | 32704 |
| checkRule_ForeignCall | 57825 |
| checkRule_simpleGTEQL | 26820 |
| checkRule_simpleLTEQL | 26849 |
| checkRule_simple_GT | 26661 |

---

*This report is automatically generated from test output.*  
*To update this report, run: `./script/reportGas.sh`*  
*Rules Engine tests: [`test/utils/gasReport/GasReport.t.sol`](test/utils/gasReport/GasReport.t.sol)*  
*Hardcoded tests: [`test/utils/gasReport/GasReportHardcoded.t.sol`](test/utils/gasReport/GasReportHardcoded.t.sol)*  
*Snapshots: [`snapshots/RulesEngineUnitTests.json`](snapshots/RulesEngineUnitTests.json)*
