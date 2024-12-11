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