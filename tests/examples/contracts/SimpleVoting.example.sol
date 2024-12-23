pragma solidity ^0.8.0;

contract SimpleVoting {
    mapping(address => bool) public voters;
    uint256 public voteCount;

    function vote() public {
        voters[msg.sender] = true;
    }

    function getVoteCount() public view returns (uint256) {
        return voteCount;
    }
}
