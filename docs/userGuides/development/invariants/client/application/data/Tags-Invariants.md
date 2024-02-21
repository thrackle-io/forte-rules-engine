# Tags Invariants

- Upon creation ownership of the contract will be transfered to the App Manager address passed in to the constructor.
- If addTag is called by an address that is not the registered App Manager the transaction will be reverted.
- If addTag is called with an empty string for the tag the transaction will be reverted.
- If addTag is called with an address of 0 the transaction will be reverted.
- If addTag is not reverted the Tag event will be emitted. 

- If addTagToMultipleAccounts is called by an address that is not the registered App Manager the transaction will be reverted. 
- If addTagToMultipleAccounts is called with an empty string for the tag the transaction will be reverted.
- If addTagToMultipleAccounts is not reverted the Tag event will be emitted for each address in the array.

- If removeTag is called by an address that is not the registered App Manager the transaction will be reverted.
- If removeTag is not reverted the Tag event will be emitted.