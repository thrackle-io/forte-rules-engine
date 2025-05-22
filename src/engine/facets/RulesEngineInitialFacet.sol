// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetCommonImports.sol";
/**
 * @title Rules Engine Processor Facet
 * @dev This contract serves as the core processor for evaluating rules and executing effects in the Rules Engine.
 *      It provides functionality for evaluating policies, rules, and conditions, as well as executing effects based on rule outcomes.
 *      The contract also supports foreign calls, dynamic argument handling, and tracker updates.
 * @notice This contract is a critical component of the Rules Engine, enabling secure and flexible rule evaluation and effect execution.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract RulesEngineInitialFacet is FacetCommonImports{

    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Initialization
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Initializes the Rules Engine with the specified owner.
     * @dev This function sets the initial owner of the diamond and ensures the contract is only initialized once.
     * @param _owner The initial owner of the diamond.
     */
    function initialize(address _owner) external {
        InitializedS storage init = lib.initializedStorage();
        if(init.initialized) revert ("AlreadyInitialized");
        callAnotherFacet(0xf2fde38b, abi.encodeWithSignature("transferOwnership(address)", _owner));
    }

    /**
     * @notice Retrieves the raw string associated with a specific instruction set within a rule and policy.
     * @dev This function is used to fetch a `StringVerificationStruct` containing the raw string data.
     * @param _policyId The ID of the policy containing the rule.
     * @param _ruleId The ID of the rule containing the instruction set.
     * @param instructionSetId The ID of the instruction set to retrieve the raw string from.
     * @return retVal A `StringVerificationStruct` containing the raw string data for the specified instruction set.
     */
    function retrieveRawStringFromInstructionSet(uint256 _policyId, uint256 _ruleId, uint256 instructionSetId) public view returns (StringVerificationStruct memory retVal) {
        (uint256 instructionSetValue, bytes memory encoded) = _retreiveRawEncodedFromInstructionSet(_policyId, _ruleId, instructionSetId, PT.STR);
        retVal.rawData = abi.decode(encoded, (string));
        retVal.instructionSetValue = instructionSetValue;
    }

    /**
     * @notice Retrieves the raw address from a specific instruction set.
     * @dev This function is used to fetch the raw address associated with a given
     *      policy ID, rule ID, and instruction set ID.
     * @param _policyId The ID of the policy to which the rule belongs.
     * @param _ruleId The ID of the rule within the policy.
     * @param instructionSetId The ID of the instruction set to retrieve the address verification structure from.
     * @return retVal The AddressVerificationStruct containing the raw address data.
     */
    function retrieveRawAddressFromInstructionSet(uint256 _policyId, uint256 _ruleId, uint256 instructionSetId) public view returns (AddressVerificationStruct memory retVal) {
        (uint256 instructionSetValue, bytes memory encoded) = _retreiveRawEncodedFromInstructionSet(_policyId, _ruleId, instructionSetId, PT.ADDR);
        retVal.rawData = abi.decode(encoded, (address));
        retVal.instructionSetValue = instructionSetValue;
    }

    /**
     * @dev Retrieves the raw encoded data and instruction set value from a given instruction set ID.
     * @param _policyId The ID of the policy associated with the instruction set.
     * @param _ruleId The ID of the rule associated with the instruction set.
     * @param instructionSetId The ID of the instruction set to retrieve data from.
     * @param pType The parameter type (PT) associated with the instruction set.
     * @return instructionSetValue The value of the instruction set.
     * @return encoded The raw encoded data associated with the instruction set.
     */
    function _retreiveRawEncodedFromInstructionSet(uint256 _policyId, uint256 _ruleId, uint256 instructionSetId, PT pType) internal view returns (uint256 instructionSetValue, bytes memory encoded) {
        RuleStorageSet memory _ruleStorage = lib.getRuleStorage().ruleStorageSets[_policyId][_ruleId];
        if(!_ruleStorage.set) {
            revert("Unknown Rule");
        }
        for(uint256 i = 0; i < _ruleStorage.rule.rawData.instructionSetIndex.length; i++) {
            if(_ruleStorage.rule.rawData.instructionSetIndex[i] == instructionSetId) {
                if(_ruleStorage.rule.rawData.argumentTypes[i] != pType) {
                    revert("Incorrect type");
                }
                encoded = _ruleStorage.rule.rawData.dataValues[i];
                instructionSetValue = _ruleStorage.rule.instructionSet[instructionSetId];
                break;
            }
        }
    }

}