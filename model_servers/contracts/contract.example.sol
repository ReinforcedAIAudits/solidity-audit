contract TreasureVault {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalTreasures;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
        totalTreasures += msg.value;
    }

}