// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;
import "src/client/RulesEngineClient.sol";



/**
 * @title Example contract for testing the Rules Engine 
 * @dev This contract is to test encoding additional parameters to use in the rule processing 
 * @author @ShaneDuncan602 
 */
contract ExampleUserContractEncoding is RulesEngineClient {
    bytes data;
    uint256 uintParam; 
    string stringParam; 
    address addressParam; 

    // Use Uint Param for encoding testing 
    function transfer(address _to, uint256 _amount) public returns (bool _return) {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _to, _amount, uintParam, msg.sender);
        if (_invokeRulesEngine(encoded) == 1) {
            return true;
        }
       return false;
    }

    // use TranferFrom to use address param for encoding testing 
    function transferFrom(address _to, uint256 _amount) public returns (bool _return) {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _to, _amount, addressParam, msg.sender);
        if (_invokeRulesEngine(encoded) == 1) {
            return true;
        }
       return false;
    }

    // Use this function to encode new data that will be used by a rule for processing. 
    // Do not overwrite data without updating rule first. 
    function writeNewEncodedData(bytes memory _data) public returns (bytes memory) {
        data = abi.encode(_data);
        return data;
    }

    // Use this function to encode new data that will be used by a rule for processing. 
    function writeNewUintData(uint256 _data) public returns (uint256) {
        uintParam = _data;
        return uintParam;
    }

    // Use this function to encode new data that will be used by a rule for processing. 
    function writeNewAddressData(address _data) public returns (address) {
        addressParam = _data;
        return addressParam;
    }

}
