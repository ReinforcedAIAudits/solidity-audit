contract Wallet {
    mapping (address => uint) userBalance;
    function getBalance(address u) public returns(uint) {
        return userBalance[u];
    }

    function addToBalance() public payable{
        userBalance[msg.sender] += msg.value;
    }

    function withdrawBalance() public {
        (bool success,) = msg.sender.call{value: userBalance[msg.sender]}("");
        if (!success) {
            revert();
        }
        userBalance[msg.sender] = 0;
    }   
}