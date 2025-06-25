pragma solidity ^0.8.27;



contract ExampleReentrancy {
    bytes data;
    address to;
    bool delegatecall;

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

    function setDelegatecall(bool _delegatecall) public {
        delegatecall = _delegatecall;
    }

    function reenter() internal {
        bool success;
        if (delegatecall) {
            (success, ) = address(to).delegatecall(data);
        } else {
            (success, ) = address(to).call(data);
        }
        require(success, "Reentrancy failed");
    }
}