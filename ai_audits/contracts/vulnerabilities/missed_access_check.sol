import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract Bridge {
    address public owner;
    event Deposit(address _token, uint256 _amount);
    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    function changeOwner(address _newOwner) {
        owner = _newOwner;
    }

    function deposit(address _token, uint256 _amount) {
        IERC20(_token).transferFrom(msg.sender, address(this), _amount);
        emit Deposit(_token, _amount);
    }

    function withdraw(address _token, uint256 _amount) onlyOwner {
        IERC20(_token).transfer(msg.sender, _amount);
    }
}