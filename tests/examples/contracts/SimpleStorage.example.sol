pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 private storedData;
    mapping(address => uint256) public balanceOf;


    constructor(uint256 _initialSupply) {
        balanceOf[msg.sender] = _initialSupply;
    }

    function set(uint256 x) public {
        storedData = x;
    }

    function get() public view returns (uint256) {
        return storedData;
    }
}
