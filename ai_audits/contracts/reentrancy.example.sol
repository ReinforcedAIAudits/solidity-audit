// SPDX-License-Identifier: MIT 
pragma solidity ^0.8.0;

contract Reentrancy {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function balanceChange() public payable {
       balances[msg.sender] = 0;
    }
}