# TokenMaxDailyTradesS
[Git Source](https://github.com/thrackle-io/forte-rules-engine/blob/7ed34a62033174e2129a3d6ffafc4f97afb624f7/src/client/token/handler/diamond/RuleStorage.sol)


```solidity
struct TokenMaxDailyTradesS {
    mapping(ActionTypes => Rule) tokenMaxDailyTrades;
    mapping(uint32 => mapping(uint256 => uint256)) tradesInPeriod;
    mapping(uint32 => mapping(uint256 => uint64)) lastTxDate;
    uint256 ruleChangeDate;
}
```

