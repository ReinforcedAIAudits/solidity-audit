pragma solidity ^0.8.0;

contract Relayer {
    mapping (bytes => bool) executed;
    address target;
    function forward(bytes memory _data) public {
        require(executed[_data] == false, "Replay protection");
        executed[_data] = true;
        target.call(abi.encodeWithSignature("execute(bytes)", _data));
    }
}