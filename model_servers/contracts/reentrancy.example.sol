contract Reentrancy {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function balanceChange() public {
       balances[msg.sender] = 0;
    }
}