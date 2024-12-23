pragma solidity ^0.8.0;

contract TaskManager {
    struct Task {
        string description;
        bool completed;
    }

    mapping(uint256 => Task) public tasks;
    uint256 public taskCount;

    event TaskCreated(uint256 taskId, string description);
    event TaskCompleted(uint256 taskId);

    function createTask(string memory _description) public {
        taskCount++;
        tasks[taskCount] = Task(_description, false);
        emit TaskCreated(taskCount, _description);
    }

    function completeTask(uint256 _taskId) public {
        require(_taskId > 0 && _taskId <= taskCount, "Task is not found");
        tasks[_taskId].completed = true;
        emit TaskCompleted(_taskId);
    }

    function getTask(uint256 _taskId) public view returns (string memory, bool) {
        require(_taskId > 0 && _taskId <= taskCount, "Task is not found");
        Task memory task = tasks[_taskId];
        return (task.description, task.completed);
    }
}
