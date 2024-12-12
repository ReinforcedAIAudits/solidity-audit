// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleVoting {
    mapping(address => bool) public voters;
    uint256 public voteCount;

    function vote() public {
        require(!voters[msg.sender], "You have already voted");
        voters[msg.sender] = true;
        voteCount++;
    }

    function getVoteCount() public view returns (uint256) {
        return voteCount;
    }
}
