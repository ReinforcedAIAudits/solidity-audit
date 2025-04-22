import os
import unittest

from ai_audits.contracts.contract_generator import Vulnerability, create_task
from ai_audits.protocol import TaskType
from ai_audits.subnet_utils import SolcSingleton


class HybridTaskTestCase(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        SolcSingleton().install_solc()
        self.maxDiff = None

    def test_hybrid_task(self):
        pseudo_vul = """
        // missed access check

        bool public paused;

        struct User {
            uint256 id;
            string name;
        }

        event UserCreated(uint256 id, string name);

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

        self.assertEqual(task.contract_code.replace('\n', '').strip(), contract_with_vul.replace('\n', '').strip())
        self.assertEqual(task.from_line, 129)
        self.assertEqual(task.to_line, 131)
        self.assertEqual(
            task.contract_code.splitlines()[128:131],
            ["    function pause() public {", "        paused = true;", "    }"]
        )
