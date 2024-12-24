pragma solidity ^0.8.0;

contract GalacticAuction {
    address private owner;
    mapping(address => uint256) public userBalances;
    mapping(address => bool) public userVerified;
    uint256 public totalSupply;
    uint256 public feePercentage;

    constructor() {
        owner = msg.sender;
        totalSupply = 1000000 ether;
        feePercentage = 2;
    }

    function deposit() public payable {
        require(msg.value > 0, 'Deposit amount must be greater than zero');
        userBalances[msg.sender] += msg.value;
        totalSupply += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(amount > 0, 'Withdrawal amount must be greater than zero');
        require(userBalances[msg.sender] >= amount, 'Insufficient balance');
        userBalances[msg.sender] -= amount;
        totalSupply -= amount;
        payable(msg.sender).transfer(amount);
    }

    function verifyUser(address user) public {
        require(msg.sender == owner, 'Only the owner can verify users');
        userVerified[user] = true;
    }

    function calculateFee(uint256 amount) public view returns (uint256) {
        return (amount * feePercentage) / 100;
    }
}