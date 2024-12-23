pragma solidity ^0.8.0;

contract GalacticHub {
    address private owner;
    mapping(address => uint256) public userBalances;
    uint256 public totalSupply;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public feePercentage;

    constructor() {
        owner = msg.sender;
        totalSupply = 0;
        feePercentage = 5;
    }

    function deposit() public payable {
        userBalances[msg.sender] += msg.value;
        totalSupply += msg.value;
    }

    function withdraw(uint256 amount) public {
        require(userBalances[msg.sender] >= amount, 'Insufficient balance');
        userBalances[msg.sender] -= amount;
        totalSupply -= amount;
        payable(msg.sender).transfer(amount);
    }

    function transfer(address recipient, uint256 amount) public {
        require(userBalances[msg.sender] >= amount, 'Insufficient balance');
        userBalances[msg.sender] -= amount;
        userBalances[recipient] += amount;
    }

    function setFeePercentage(uint256 newFee) public {
        require(msg.sender == owner, 'Only the owner can set the fee percentage');
        feePercentage = newFee;
    }
}