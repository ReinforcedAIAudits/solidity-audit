pragma solidity ^0.8.0;

contract GalacticBank {
    mapping(address => uint256) public userBalance;
    mapping(address => uint256) public userLastTransaction;
    mapping(address => bool) public userIsActive;
    uint256 public totalBalance;
    uint256 public transactionFee;
    address public owner;

    constructor() {
        owner = msg.sender;
        transactionFee = 0.1 ether;
    }

    function addToBalance() public payable {
        require(msg.value > 0, 'Invalid amount');
        userBalance[msg.sender] += msg.value;
        totalBalance += msg.value;
        userLastTransaction[msg.sender] = block.timestamp;
        userIsActive[msg.sender] = true;
    }

    function getBalance() public view returns (uint256) {
        return userBalance[msg.sender];
    }

    function withdrawBalance(uint256 amount) public {
        require(amount > 0, 'Invalid amount');
        require(userBalance[msg.sender] >= amount, 'Insufficient balance');
        require(userIsActive[msg.sender], 'User is not active');
        userBalance[msg.sender] -= amount;
        totalBalance -= amount;
        payable(msg.sender).transfer(amount - transactionFee);
        userLastTransaction[msg.sender] = block.timestamp;
    }

    function updateTransactionFee(uint256 newFee) public {
        require(msg.sender == owner, 'Only owner can update transaction fee');
        transactionFee = newFee;
    }

    function deactivateUser() public {
        require(userIsActive[msg.sender], 'User is not active');
        userIsActive[msg.sender] = false;
    }

    function getUserLastTransaction() public view returns (uint256) {
        return userLastTransaction[msg.sender];
    }
}