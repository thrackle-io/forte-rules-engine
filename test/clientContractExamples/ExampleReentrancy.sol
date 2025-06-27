pragma solidity ^0.8.27;

import {RulesEngineComponentFacet} from "../../src/engine/facets/RulesEngineComponentFacet.sol";
import {Trackers} from "../../src/engine/RulesEngineStorageStructure.sol";

error ReentrancyFailed(uint);

contract ExampleReentrancy {
    bytes data;
    address to;
    bool delegatecall;
    uint counter;
    bytes[] public dataHistory;
    bytes[] public dataHistory2;
    address rulesEngine;

    fallback() external payable {
        if (data.length == 0) {
            data = msg.data;
        }
        reenter();
    }

    constructor(address _to, bool _delegatecall) {
        to = _to;
        delegatecall = _delegatecall;
    }

    function setCallData(bytes memory _data) public {
        data = _data;
    }

    function setRulesEngine(address _rulesEngine) public {
        rulesEngine = _rulesEngine;
    }

    function setDelegatecall(bool _delegatecall) public {
        delegatecall = _delegatecall;
    }

    function setTo(address _to) public {
        to = _to;
    }

    function getDataHistory() public view returns (bytes[] memory) {
        return dataHistory;
    }

    function getDataHistory2() public view returns (bytes[] memory) {
        return dataHistory2;
    }

    function reenter() internal {
        counter++;
        if (counter == 4) {
            return;
        }
        bool success;
        if (delegatecall) {
            (success, ) = address(to).delegatecall(data);
        } else {
            (success, ) = address(to).call(data);
        }
        Trackers memory tracker = RulesEngineComponentFacet(rulesEngine).getTracker(1, 1);
        dataHistory.push(tracker.trackerValue);
        Trackers memory tracker2 = RulesEngineComponentFacet(rulesEngine).getTracker(2, 1);
        dataHistory2.push(tracker2.trackerValue);
        if (!success) {
            revert ReentrancyFailed(counter);
        }
    }
}