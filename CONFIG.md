# Data Configurations

## Policy
### function createPolicy(PolicyType policyType, string calldata policyName, string calldata policyDescription)

Create a stubbed policy. 

1. ```policyType```(enum) - The type of the policy.(0 = closed, 1 = open, 2 = disabled)
2. ```policyName```(string) The name of the policy.
3. ```policyDescription```(string) A description of the policy.

## Rule
### function createRule(uint256 policyId, Rule calldata rule, string calldata ruleName, string calldata ruleDescription) external returns (uint256)

Create a rule in the policy. This can be done multiple times to create multiple rules. 

1. ```policyId```(uint256) ID of the policy the rule will be added to.
2. ```rule```(Rule) The rule to create.
   1. ```instructionSet```(uint256[])
      1. Tells the rules engine where, what, and how to process the rule. It utilizes the logical operators enum to specify these instructions. 
    ```enum LogicalOp {NUM,NOT,PLH,ASSIGN,PLHM,ADD,SUB,MUL,DIV,LT,GT,EQ,AND,OR,GTEQL,LTEQL,NOTEQ,TRU,TRUM}```
    A logical operator is followed by a subsequent element that pertains to the logical operator. Here are examples: 

     ---

    `NUM` stands for number. This tells the rules engine the next element in the instruction set is a number. 
    ```
        instructionSet[0] = uint(LogicalOp.NUM);
        instructionSet[1] = 5;
    ```

     ---

    `ADD, SUB, MUL, DIV` stand for their respective mathematical operations. The operators signal the rules engine to perform the operation on the next two values in the subsequent elements. Here are examples:
    ```
        instructionSet[0] = uint(LogicalOp.ADD);
        rule.instructionSet[1] = 0;
        rule.instructionSet[2] = 1;
    ```
    In this example, the rules engine will add the value in register 0 with the value in register 1. 

     ---

    `GT, LT, GTEQL, LTEQL, EQ, NOTEQ` are true logical operators that represent their respective relationship. This tells the rules engine the next element in the instruction set is a number to be used for comparison. 

   ```
        rule.instructionSet[4] = uint(LogicalOp.GTEQL);
        rule.instructionSet[5] = 0; 
        rule.instructionSet[6] = 1;
   ```
     In this example it would compare 0 and 1.

     ---

    `TRU` stands for Tracker Update. This tells the rules engine the next element in the instruction set contains a tracker id. This is used to access the a previously defined tracker within the policy. The subsequent elements provide instructions on what to do with the tracker. An example would be:
   ```
        rule.instructionSet[0] = uint(LogicalOp.TRU);
        rule.instructionSet[1] = 1;
        rule.instructionSet[2] = 0; 
        rule.instructionSet[3] = uint(TrackerTypes.PLACE_HOLDER); 
   ```
    This example takes the tracker value from trackerId=1 and puts it in place holder 0.

     ---

    `TRUM` stands for Tracker Update Mapped. It is a mapped tracker and requires a key to access the stored tracker value. An example would be:
   ```
        effect.instructionSet[4] = uint(LogicalOp.TRUM);
        effect.instructionSet[5] = 1;
        effect.instructionSet[6] = 0;
        effect.instructionSet[7] = 1; 
        effect.instructionSet[8] = uint(TrackerTypes.MEMORY) 
   ```
    This example takes the tracker value from trackerId=1 and puts it in place holder 0. The third index down is the key. In this case, 1 is the key. 

     ---

    `PLH` stands for Place Holder. This tells the rules engine the next element in the instruction set contains the the index where a value within the placeHolders array, below, exists. For instance, the following code would tell the rules engine to retrieve element ```0``` from the placeHolders array.
   ```
    instructionSet[0] = uint(LogicalOp.PLH);
    instructionSet[1] = 0;
   ```
   More information on place holders can be found below

   ---
        
   2. ```rawData```(RawData)
      1. The raw format string and addresses for values in the instruction set that have already been converted to uint256.
   3. ```placeHolders```(Placeholder[]) List of all placeholders used in the rule in order. Needs to contain the type, and index (zero based) of the particular type in the calling function. For example if the argument in question is the 2nd address in the calling function the placeHolder would be: ```pType = parameterType.ADDR index = 1```
   4. ```effectPlaceHolders```(Placeholder[])
   5. ```posEffects```(Effect[]) List of all positive effects
   6. ```negEffects```(Effect[]) List of all negitive effects
3. ```ruleName```(string) The name of the rule
4. ```ruleDescription```(string) The description of the rule
returns The generated rule ID.

## Foreign Call
### function createForeignCall(uint256 _policyId,ForeignCall calldata _foreignCall,string calldata foreignCallName) external returns (uint256)

Create a foreign call record within the policy. 

1. ```_policyId```(uint256) The policy ID the foreign call will be mapped to.
2. ```_foreignCall```(ForeignCall) The definition of the foreign call to create
3. ```foreignCallName```(string) The name of the foreign call

returns The index of the created foreign call.



