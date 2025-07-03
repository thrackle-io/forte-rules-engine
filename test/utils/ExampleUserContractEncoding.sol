/// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;
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
    bytes bytesParam;
    bool boolParam;
    uint256[] uintArray; 
    bytes[] dynamicArray;

    // Use Uint Param for encoding testing 
    function transfer(address _to, uint256 _amount) public returns (bool _return) {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _to, _amount, uintParam, msg.sender);
        _invokeRulesEngine(encoded);
        return true;
    }

    // use TranferFrom to use address param for encoding testing 
    function transferFrom(address _to, uint256 _amount) public returns (bool _return) {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _to, _amount, addressParam, msg.sender);
        _invokeRulesEngine(encoded);
        return true;
    }

    function transferWithBytes(address _to, uint256 _amount, bytes memory _bytes) public returns (bool _return) {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _to, _amount, _bytes);
        _invokeRulesEngine(encoded);
        return true;
    }

    function transferBytes(address _to, uint256 _amount) public returns (bool _return) {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _to, _amount, bytesParam, msg.sender);
        _invokeRulesEngine(encoded);
        return true;
    }

    function transferString(address _to, uint256 _amount) public returns (bool _return) {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _to, _amount, stringParam, msg.sender);
        _invokeRulesEngine(encoded);
        return true;
    }

    function transferWithString(address _to, uint256 _amount, string memory _string) public returns (bool _return) {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _to, _amount, _string);
        _invokeRulesEngine(encoded);
        return true;
    }

    function transferBool(address _to, uint256 _amount) public returns (bool _return) {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _to, _amount, boolParam, msg.sender);
        _invokeRulesEngine(encoded);
        return true;
    }

    function transferArray(address _to, uint256 _amount) public returns (bool _return) {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _to, _amount, uintArray, msg.sender);
        _invokeRulesEngine(encoded);
        return true;
    }

    function transferDynamicArray(address _to, uint256 _amount) public returns (bool _return) {
        bytes memory encoded = abi.encodeWithSelector(msg.sig, _to, _amount, dynamicArray, msg.sender);
        _invokeRulesEngine(encoded);
        return true;
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

    // Use this function to encode new data that will be used by a rule for processing. 
    function writeNewBytesData(bytes memory _data) public returns (bytes memory) {
        bytesParam = _data;
        return bytesParam;
    }

     // Use this function to encode new data that will be used by a rule for processing. 
    function writeNewStringData(string memory _data) public returns (string memory) {
        stringParam = _data;
        return stringParam;
    }

    // Use this function to encode new data that will be used by a rule for processing. 
    function writeNewBoolData(bool _data) public returns (bool) {
        boolParam = _data;
        return boolParam;
    }

    // Use this function to encode new data that will be used by a rule for processing. 
    function writeNewStaticArrayData(uint256[] memory _uintArray) public returns (uint256[] memory) {
        uintArray = _uintArray;
        return uintArray;
    }

    // Use this function to encode new data that will be used by a rule for processing. 
    function writeNewDynamicArrayData(bytes[] memory _bytesArray) public returns (bytes[] memory) {
        dynamicArray = _bytesArray;
        return dynamicArray;
    }

}
