from os.path import isfile, join, dirname
from os import listdir
import unittest
import solcx
from ai_audits.contracts.ast_models import SourceUnit
from ai_audits.contracts.contract_generator import parse_ast_to_solidity

CONTRACT_PATH = join(dirname(__file__), "..", "examples", "contracts")

class AstToSourceTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contracts = [
            (f.split('.')[0], f) for f in listdir(CONTRACT_PATH) if isfile(join(CONTRACT_PATH, f))
        ]
        solcx.install_solc()

    def test_ast_to_source(self):
        for contract_name, contract_filename in self.contracts:
            with self.subTest(contract=contract_name):
                self._test_single_ast(contract_name, contract_filename)

    def _test_single_ast(self, contract_name, contract_filename):
        with open(join(CONTRACT_PATH, contract_filename)) as f:
            source_code = f.read()
        suggested_version = solcx.install.select_pragma_version(
            source_code, solcx.get_installable_solc_versions()
        )
        solc_output = solcx.compile_source(source_code, solc_version=suggested_version)
        ast = SourceUnit(**solc_output[f"<stdin>:{contract_name}"]["ast"])
        try:
            parse_ast_to_solidity(ast)
        except Exception as ex:
            self.fail(f"Exception occurred while parsing {contract_name} contract code: {ex}")

if __name__ == "__main__":
    unittest.main()
