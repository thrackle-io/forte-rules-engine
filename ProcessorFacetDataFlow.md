# Data flow through the processor facet 

## Entry Point 

A calling contract will invoke `checkPolicies(bytes calldata arguments)` function as the primary entry point for the process of validating rules for the contract. The arguments parameter is all of the encoded data for the processing of the calling contract's applied policies. 

This must include, at a minimum, the message signature of the calling function and any additional data to be used or passed to the Rules Engine. Data not included in the function signature may be encoded and passed to the Rules Engine. 

The engine will retrieve the policy associated storage and the `policyIdMap` for the msg.sender. 

For each policyId from the map the engine will loop and continue with the _checkPolicies helper: 
```c
_checkPolicy(uint256 _policyId, address _contractAddress, bytes calldata _arguments) internal returns (bool retVal)
``` 

The engine retrieves the policy storage sets for the `policyId`. 

The engine retrieves the rule data for that `policyId`.

Then the engine then calls: 
```c
_evaluateRulesAndExecuteEffects(
            ruleData,
            _policyId,
            _loadApplicableRules(ruleData, policyStorageSet.policy, bytes4(_arguments[:4])),
            _arguments[4:]
        );
```

Note: This function's parameters calls the helper: 

```c
_loadApplicableRules(
        mapping(uint256 ruleId => RuleStorageSet) storage _ruleData,
        Policy storage _policy,
        bytes4 _callingFunction
    ) internal view returns (uint256[] memory)
```

This returns the uint256 array of applicable `ruleIds`. 

When invoking `_evaluateRulesAndExecuteEffects` function the engine is now slicing the `_arguments` in order to separate out the function signature from the rest of the arguments: `bytes4(_arguments[:4])` and `_arguments[4:]`.


## Evaluate Rules and Execute Effects 
Inside of the `checkPolicies` function the engine differentiates between rule processing and effects of the rules within applied policies. 

This function will loop through the `_applicableRules` array for each ruleId. 

Rule processing takes place in the function `_evaluateIndividualRule`. 

The effects of a rule take place in the function `_doEffects`.


### Evaluate Individual Rules 
Inside of the:
```c
_evaluateIndividualRule(
        Rule storage _rule,
        uint256 _policyId,
        bytes calldata _callingFunctionArgs
    ) internal returns (bool response)
```

The engine will call the `_buildArguments` and the `_run` functions. 

While building the arguments the engine will load the values of each placeholder based on their types and locations into memory addresses. 

The `_run` function will take the instruction set and the place holders array and process the logical operations of the instruction set with the conditionals and placeholder values. 

#### Build Arguments  
```c
_buildArguments(
        Rule storage _rule,
        uint256 _policyId,
        bytes calldata _callingFunctionArgs,
        bool _effect
    ) internal returns (bytes[] memory, Placeholder[] memory)

```

The `_buildArguments` function processes the `Rule`, `_policyId`, `_callingFunctionArgs` and `_effect` bool. 

First the engine checks if this is an effect to determine which instruction set to pull from the `Rule`.

Next, the engine creates a new array: bytes[] retVals for holding the return values from foreign calls.

The engine loops through the placeholders from the `Rule` in order to replace the data values with their actual values based on the instruction set. Each placeholder is then placed into a memory address and its location placed into the placeholders[]. 

This may be global variables (aka transaction data), foreign call return values, tracker values (trackers or mapped trackers), values from the encoded data or parameters from the calling function. 
 

Example: This instruction set will check if the placeholder from the calling function (transfer(address to, uint256 value)) is Greater Than the number 100. In this case assume the placeholder is the value of the transfer function. 

[3,0,0,100,10,0,1] 

The build arguments function will then place `value` into `placeholders` so that the _run function can retrieve the value.  

##### Build Arguments helpers 
In order to build the arguments properly, the engine has several helper functions to retrieve and replace the placeholder values: 

```c
_extractFlags(
        Placeholder memory placeholder
    ) internal pure returns (bool isTrackerValue, bool isForeignCall, uint8 globalVarType)
```

This function determines if the type of placeholder is a Foreign call, tracker, or global variable type. 


```c
_handleGlobalVar(uint256 globalVarType) internal view returns (bytes memory, ParamTypes)
```

When a placeholder is a global variable, this function will store the appropriate global variable (msg.sender, block.timestamp, msg.data, block number or tx.orgin) location in `placeholders`.

```c
_handleForeignCall(
        uint256 _policyId,
        bytes calldata _callingFunctionArgs,
        uint256 typeSpecificIndex,
        bytes[] memory retVals,
        ForeignCallEncodedIndex[] memory metadata
    ) internal returns (bytes memory, ParamTypes)
```

This function will store the location of the return value of a foreign call in `placeholders`. 

Note: The foreign call outside of the rules engine will take place at this time. Inside of `_handleForeignCall` are the helper functions `evaluateForeignCalls` which invokes `evaluateForeignCallForRule` 

```c
evaluateForeignCallForRule(
        ForeignCall memory fc,
        bytes calldata functionArguments,
        bytes[] memory retVals,
        ForeignCallEncodedIndex[] memory metadata,
        uint256 policyId
    ) public returns (ForeignCallReturnValue memory retVal)
```
This function will build the callData arguments for and call the address and signature stored in the foreign call storage. The return of that call is then returned back up to the building of the arguments and the memory location stored in `placeholders`. 

```c
_handleTrackerValue(uint256 _policyId, Placeholder memory placeholder) internal view returns (bytes memory)

```
This function will store the location of the tracker in `placeholders`.

```c
_handleRegularParameter(
        bytes calldata _callingFunctionArgs,
        Placeholder memory placeholder
    ) internal pure returns (bytes memory)
```
This function extracts the parameters from the callData of the calling function. Based on the type of the placeholder the return of this function will store the parameters location in memory in `placeholders`.


### Run 

```c
_run(
        uint256[] memory _prog,
        Placeholder[] memory _placeHolders,
        uint256 _policyId,
        bytes[] memory _arguments
    ) internal returns (bool)
``` 

This function performs the logical operations of the rule processing from the instruction set. 

- `_prog` This is the instruction set 
- `_placeHolders` This is the array of placeholders to be used in processing 
- `_policyId` PolicyId for the current policy being evaluated 
- `_arguments` Array of bytes containing 

Entering the logical processing loop the engine will iterate through the instruction set (`_prog`) and retrieve the placeholder values from their memory position. Each logical operator in the instruction set will be evaluated to either true or false and continue iterating through the instruction set until all logical operations are complete. 


## Effects 
Once the rule processing is complete the engine will then process the effects for each rule within the current policy being evaluated. 

```c
_doEffects(Rule storage _rule, uint256 _policyId, Effect[] memory _effects, bytes calldata _callingFunctionArgs)
```

Conditions of a rule will evaluate to positive or negative (true or false). 

If the effect is to revert on the conditions of the rule then engine will invoke:

```c
_doRevert(effect.errorMessage); 
```
This uses the `errorMessage` stored in the rule. This is an evm revert and all processing will stop. 

If the effect is to emit an event: 

```c
_buildEvent(
        Rule storage _rule,
        bool _isDynamicParam,
        uint256 _policyId,
        bytes32 _message,
        Effect memory _effectStruct,
        bytes calldata _callingFunctionArgs
    ) internal
```

This function will determine if the event to be emitted is a static event or dynamic event. 

Static events will invoke: 

```c
_fireEvent(uint256 _policyId, bytes32 _message, Effect memory _effectStruct)
```

The `_message` of the event and the third parameter of the event are stored within the rule structure. These will not update at run time. 

Dynamic events will invoke: 

```c
_fireDynamicEvent(Rule storage _rule, uint256 _policyId, bytes32 _message, bytes calldata _callingFunctionArgs)
``` 
The `_message` of the event is stored within the rule structure and the 3rd parameter of the event will be from a parameter of the calling function. 

If the effect is to process additional logic: 

```c
_evaluateExpression(
        Rule storage _rule,
        uint256 _policyId,
        bytes calldata _callingFunctionArgs,
        uint256[] memory _instructionSet
    ) internal
```

This function will return to the `_buildArguments` and the `_run` functions. The processing will be the same as above where this time the `_effect` for `_buildArguments` function. 
