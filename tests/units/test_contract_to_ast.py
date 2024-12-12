from os.path import isfile, join, dirname
from os import listdir
import unittest

import solcx

from ai_audits.contracts.ast_models import SourceUnit

CONTRACT_PATH = join(dirname(__file__), "..", "examples", "contracts")


class ContractToAstTestCase(unittest.TestCase):
    def __init__(self, methodName="runTest"):
        self.contracts = [
            (f.split('.')[0], f) for f in listdir(CONTRACT_PATH) if isfile(join(CONTRACT_PATH, f))
        ]
        solcx.install_solc()
        super().__init__(methodName)

    def test_contract_to_ast(self):
        for contract_name, contract_filename in self.contracts:
            with self.subTest(input_value=contract_name):
                with open(join(CONTRACT_PATH, contract_filename)) as f:
                    source_code = f.read()
                suggested_version = solcx.install.select_pragma_version(
                    source_code, solcx.get_installable_solc_versions()
                )
                solc_output = solcx.compile_source(source_code, solc_version=suggested_version)
                # print(solc_output)
                try:
                    ast = SourceUnit(**solc_output[f"<stdin>:{contract_name}"]["ast"])
                except Exception as ex:
                    self.fail(f"Exception occured while parsing {contract_name} contract code: {ex}")