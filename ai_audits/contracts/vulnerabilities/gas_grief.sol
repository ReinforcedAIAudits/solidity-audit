contract Relayer {
    mapping (bytes => bool) executed;
    address target;
    function forward(bytes memory _data) public {
        require(!executed[_data], "Replay protection");
        executed[_data] = true;
        target.call(abi.encodeWithSignature("execute(bytes)", _data));
    }
}