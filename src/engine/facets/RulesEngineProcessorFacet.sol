// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import "src/engine/facets/FacetCommonImports.sol";
import {RulesEngineProcessorLib as ProcessorLib} from "src/engine/facets/RulesEngineProcessorLib.sol";

/**
 * @title Rules Engine Processor Facet
 * @dev This contract serves as the core processor for evaluating rules and executing effects in the Rules Engine.
 *      It provides functionality for evaluating policies, rules, and conditions, as well as executing effects based on rule outcomes.
 *      The contract also supports foreign calls, dynamic argument handling, and tracker updates.
 * @notice This contract is a critical component of the Rules Engine, enabling secure and flexible rule evaluation and effect execution.
 * @author @mpetersoCode55, @ShaneDuncan602, @TJ-Everett, @VoR0220
 */
contract RulesEngineProcessorFacet is FacetCommonImports{

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

    //-------------------------------------------------------------------------------------------------------------------------------------------------------
    // Rule Evaluation Functions
    //-------------------------------------------------------------------------------------------------------------------------------------------------------

    /**
     * @notice Evaluates the conditions associated with all applicable rules and returns the result.
     * @dev Primary entry point for policy checks.
     * @param contractAddress The address of the rules-enabled contract, used to pull the applicable rules.
     * @param arguments Function arguments, including the function signature and the arguments to be passed to the function.
     * @return retVal 1 if all rules pass, 0 if any rule fails.
     * TODO: refine the parameters to this function. contractAddress is not necessary as it's the message caller
     */
    function checkPolicies(address contractAddress, bytes calldata arguments) public returns (uint256 retVal) {  
        retVal = 1; 
        // Load the function signature data from storage
        PolicyAssociationS storage data = lib.getPolicyAssociationStorage();
        uint256[] memory policyIds = data.contractPolicyIdMap[contractAddress];
        // loop through all the active policies
        for(uint256 policyIdx = 0; policyIdx < policyIds.length; policyIdx++) {
            if(!_checkPolicy(policyIds[policyIdx], contractAddress, arguments)) {
                retVal = 0;
            }
        }
    }

    /**
     * @notice Checks a specific policy for compliance.
     * @param _policyId The ID of the policy to check.
     * @param _contractAddress The address of the contract being evaluated.
     * @param arguments Function arguments for the policy evaluation.
     * @return retVal True if the policy passes, false otherwise.
     */
    function _checkPolicy(uint256 _policyId, address _contractAddress, bytes calldata arguments) internal returns (bool retVal) {
        _contractAddress; // added to remove wanring. TODO remove this once msg.sender testing is complete 
        // Load the policy data from storage   
        PolicyStorageSet storage policyStorageSet = lib.getPolicyStorage().policyStorageSets[_policyId];
        mapping(uint256 ruleId => RuleStorageSet) storage ruleData = lib.getRuleStorage().ruleStorageSets[_policyId];

        // Retrieve placeHolder[] for specific rule to be evaluated and translate function signature argument array 
        // to rule specific argument array
        // note that arguments is being sliced, first 4 bytes are the function signature being passed (:4) and the rest (4:) 
        // are all the arguments associated for the rule to be invoked. This saves on further calculations so that we don't need to factor in the signature.
        retVal = evaluateRulesAndExecuteEffects(ruleData ,_policyId, _loadApplicableRules(ruleData, policyStorageSet.policy, bytes4(arguments[:4])), arguments[4:]);
    }

    /**
     * @notice Loads applicable rules for a given function signature.
     * @param ruleData The mapping of rule IDs to rule storage sets.
     * @param policy The policy structure containing the rules.
     * @param functionSignature The function signature to match rules against.
     * @return An array of applicable rule IDs.
     */
    function _loadApplicableRules(mapping(uint256 ruleId => RuleStorageSet) storage ruleData, Policy storage policy, bytes4 functionSignature) internal view returns(uint256[] memory){
        // Load the applicable rule data from storage
        uint256[] memory applicableRules = new uint256[](policy.signatureToRuleIds[functionSignature].length);
        // Load the function signature data from storage
        uint256[] storage storagePointer = policy.signatureToRuleIds[functionSignature];
        for(uint256 i = 0; i < applicableRules.length; i++) {
            if(ruleData[storagePointer[i]].set) {
                applicableRules[i] = storagePointer[i];
            }
        }
        return applicableRules;
    }
    
    /**
     * @notice Evaluates rules and executes their effects based on the evaluation results.
     * @param ruleData The mapping of rule IDs to rule storage sets.
     * @param _policyId The ID of the policy being evaluated.
     * @param applicableRules An array of applicable rule IDs.
     * @param functionSignatureArgs The arguments for the function signature.
     * @return retVal True if all rules pass, false otherwise.
     */
    function evaluateRulesAndExecuteEffects(mapping(uint256 ruleId => RuleStorageSet) storage ruleData, uint256 _policyId, uint256[] memory applicableRules, bytes calldata functionSignatureArgs) internal returns (bool retVal) {
        retVal = true;
        uint256 ruleCount = applicableRules.length;
        for(uint256 i = 0; i < ruleCount; i++) { 
            Rule memory rule = ruleData[applicableRules[i]].rule;
            if(!_evaluateIndividualRule(rule, _policyId, functionSignatureArgs)) {
                retVal = false;
                // _doEffects(rule, _policyId, rule.negEffects, functionSignatureArgs);
                callAnotherFacet(0xa5abb26b, abi.encodeWithSignature("doEffects(uint256,uint256,bool,bytes)", applicableRules[i], _policyId, false, functionSignatureArgs));
            } else{
                // revert("pos");
                // _doEffects(rule, _policyId, rule.posEffects, functionSignatureArgs);
                callAnotherFacet(0xa5abb26b, abi.encodeWithSignature("doEffects(uint256,uint256,bool,bytes)", applicableRules[i], _policyId, true, functionSignatureArgs));
            }
        }
    }

    /**
     * @dev evaluates an individual rules condition(s)
     * @param _policyId Policy id being evaluated.
     * @param rule the rule structure containing the instruction set, with placeholders, to execute
     * @param functionSignatureArgs the values to replace the placeholders in the instruction set with.
     * @return response the result of the rule condition evaluation 
     */
    function _evaluateIndividualRule(Rule memory rule, uint256 _policyId, bytes calldata functionSignatureArgs) internal returns (bool response) {
        (bytes[] memory ruleArgs, Placeholder[] memory placeholders) = ProcessorLib._buildArguments(rule, _policyId, functionSignatureArgs, false);
        response = ProcessorLib._run(rule.instructionSet, placeholders, _policyId, ruleArgs);
    }
}
