import os
import unittest

from ai_audits.contracts.contract_generator import Vulnerability, create_task


class HybridTaskTestCase(unittest.TestCase):

    def __init__(self, methodName="runTest"):
        super().__init__(methodName)
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

        with open(os.path.join(os.path.dirname(__file__), "../examples/contracts/ContractExample.sol"), "r") as f:
            contract = f.read()

        with open(os.path.join(os.path.dirname(__file__), "../examples/contracts/ContractWithVul.sol"), "r") as f:
            contract_with_vul = f.read()

        self.assertEqual(
            create_task(
                contract, Vulnerability(vulnerabilityClass="missed access check", code=pseudo_vul)
            ).contract_code.replace("\n", ""),
            contract_with_vul.replace("\n", ""),
        )
