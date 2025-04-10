// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "./GasHelpers.sol";
import "lib/forge-std/src/Test.sol";
import "test/utils/ExampleERC20Hardcoded.sol";
import "src/example/ExampleERC20.sol";
import "test/utils/ExampleERC20WithMinTransfer.sol"; 
import "test/utils/ExampleERC20WithDenyList.sol"; 
import "test/utils/ExampleERC20WithDenyListAndMinTransfer.sol";
import "test/utils/ExampleERC20WithDenyListMinAndMax.sol";
import "test/utils/ExampleERC20WithManyConditionMinTransfer.sol";
import "test/utils/ExampleERC20MinMaxBalance.sol";
import "test/utils/ExampleERC20Pause.sol";

contract GasReportHardcoded is GasHelpers, Test {

    uint256 gasUsed;
    address constant USER_ADDRESS = address(0xd00d); 
    address constant USER_ADDRESS_2 = address(0xBADd00d);
    uint256 constant ATTO = 10 ** 18;

    // ERC20's for Hardcoded tests
    //-------------------------------------------------------------------------------------    
    ExampleERC20Hardcoded hardCodedContract;
    ExampleERC20WithMinTransfer exampleERC20WithMinTransfer;
    ExampleERC20WithManyConditionMinTransfer exampleERC20WithManyConditionMinTransfer;
    ExampleERC20WithDenyList exampleERC20WithDenyList;
    ExampleERC20WithDenyListAndMinTransfer exampleERC20WithDenyListAndMinTransfer;
    ExampleERC20WithDenyListMinAndMax exampleERC20WithDenyListMinAndMax;
    ExampleERC20Pause exampleERC20Pause;
    ExampleERC20MinMaxBalance exampleERC20MinMax;

    //-------------------------------------------------------------------------------------


    function setUp() public {

        // Hardcoded Setup
        //-------------------------------------------------------------------------------------

        hardCodedContract = new ExampleERC20Hardcoded("Token Name", "SYMB");
        hardCodedContract.mint(USER_ADDRESS, 1_000_000 * ATTO);

        exampleERC20WithMinTransfer = new ExampleERC20WithMinTransfer("Token Name", "SYMB");
        exampleERC20WithMinTransfer.mint(USER_ADDRESS, 1_000_000 * ATTO);

        exampleERC20WithManyConditionMinTransfer = new ExampleERC20WithManyConditionMinTransfer("Token Name", "SYMB");
        exampleERC20WithManyConditionMinTransfer.mint(USER_ADDRESS, 1_000_000 * ATTO);

        exampleERC20WithDenyList = new ExampleERC20WithDenyList("Token Name", "SYMB");
        exampleERC20WithDenyList.mint(USER_ADDRESS, 1_000_000 * ATTO);
        exampleERC20WithDenyList.addToDenyList(address(0x7000000));

        exampleERC20WithDenyListAndMinTransfer = new ExampleERC20WithDenyListAndMinTransfer("Token Name", "SYMB");
        exampleERC20WithDenyListAndMinTransfer.mint(USER_ADDRESS, 1_000_000 * ATTO);
        exampleERC20WithDenyListAndMinTransfer.addToDenyList(address(0x7654321));

        exampleERC20WithDenyListMinAndMax = new ExampleERC20WithDenyListMinAndMax("Token Name", "SYMB");
        exampleERC20WithDenyListMinAndMax.mint(USER_ADDRESS, 1_000_000 * ATTO);
        exampleERC20WithDenyListMinAndMax.addToDenyList(address(0x7654321));

        exampleERC20Pause = new ExampleERC20Pause("Token Name", "SYMB");
        exampleERC20Pause.mint(USER_ADDRESS, 1_000_000 * ATTO);
        exampleERC20Pause.setPauseTime(1000000000);

        exampleERC20MinMax = new ExampleERC20MinMaxBalance("Token Name", "SYMB");
        exampleERC20MinMax.mint(USER_ADDRESS, 1_000_000 * ATTO);


        //-------------------------------------------------------------------------------------

    }



/**********  HARD CODED, No Rules Engine Integration **********/
//---------------------------------------------------------------------------------------------
    /**********  BASELINE gas test with no integrations or rules **********/
    function testGasExampleContract_Base() public {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(1, address(hardCodedContract), "Base");   
    }
    

// /**********  Hard-coded MinTransfer with positive effect **********/

    function testGasExampleHardcodedMinTransferRevert() public {  
        vm.startPrank(USER_ADDRESS);      
        _exampleContractGasReport(5, address(exampleERC20WithMinTransfer), "Hardcoding Min Transfer Revert"); 
    }

    function testGasExampleHardcodedManyMinTransferRevert() public {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(5, address(exampleERC20WithManyConditionMinTransfer), "Hardcoding Many Min Transfer Revert"); 
    }

// /**********  Hard-coded MinTransfer with foreign call and positive effect **********/

    function testGasExampleHardcodedOFAC() public {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(3, address(exampleERC20WithDenyList), "Hardcoding OFAC deny list"); 
    }

    function testGasExampleHardcodedOFACWithMinTransfer() public {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(5, address(exampleERC20WithDenyListAndMinTransfer), "Hardcoding OFAC deny list with min transfer"); 
    }

    function testGasExampleHardcodedOFACWithMinTransferAndMaxTransfer() public {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(5, address(exampleERC20WithDenyListMinAndMax), "Hardcoding OFAC deny list with min transfer"); 
    }

    function testGasExampleHardcodedMinMaxBalanceTransfer() public {
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(5, address(exampleERC20MinMax), "Hardcoding OFAC deny list with min transfer"); 
    }

    function testGasExampleHardcodedPauseTransfer() public {
        vm.warp(1000000001);
        vm.startPrank(USER_ADDRESS);
        _exampleContractGasReport(5, address(exampleERC20Pause), "Hardcoding OFAC deny list with min transfer"); 
    }


/**********  Rule Setup Helpers **********/
    function _exampleContractGasReport(uint256 _amount, address contractAddress, string memory _label) public {
        startMeasuringGas(_label);
        ExampleERC20(contractAddress).transfer(address(0x7654321), _amount);
        gasUsed = stopMeasuringGas();
        console.log(_label, gasUsed);  
    }



}
