import os
import unittest

from ai_audits.contracts.contract_generator import Vulnerability, create_task
from ai_audits.protocol import TaskType


class HybridTaskTestCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.maxDiff = None

    def test_hybrid_task(self):
        pseudo_vul = """
        // missed access check
        
        bool public paused;

        constructor() {
            paused = false;
        }

        function pause() public {
            paused = true;
        }
        """

        contracts_path = os.path.join(os.path.dirname(__file__), "..", "examples", "contracts")

        with open(os.path.join(contracts_path, "ContractExample.sol"), "r") as f:
            contract = f.read()

        with open(os.path.join(contracts_path, "ContractWithVul.sol"), "r") as f:
            contract_with_vul = f.read()

        task = create_task(
            contract, Vulnerability(vulnerabilityClass="missed access check", code=pseudo_vul, taskType=TaskType.HYBRID)
        )
        self.assertEqual(task.contract_code.strip(), contract_with_vul.strip())
        self.assertEqual(task.from_line, 124)
        self.assertEqual(task.to_line, 126)
        self.assertEqual(
            task.contract_code.splitlines()[123:126],
            ["    function pause() public {", "        paused = true;", "    }"]
        )
