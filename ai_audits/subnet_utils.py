import os
import requests
import solcx
from ai_audits.solidity_generator import SolidityGenerator
from ai_audits.protocol import ValidatorTask, TaskType, KnownVulnerability
from solc_ast_parser.models import ast_models
from solc_ast_parser.utils import find_node_with_properties


__all__ = [
    "create_session", "ROLES", "is_synonyms", "SolcSingleton", "get_invalid_code", "solc", "has_chained_member_access"
]


class ROLES:
    SYSTEM = "system"
    ASSISTANT = "assistant"
    USER = "user"


class SynonymsSingleton:
    SYNONYMS = (
        (
            "Missing Check on Signature Recovery",
            "Signature replay",
            "Authorization Issue",
            "Invalid Signature Handling",
            "Invalid Signature Length",
            "Replay Attack",
            "Signature Malleability",
            "Signature Length Validation",
            "Authorization Bypass",
            "ECDSA Signature Malleability",
            "Unsecured Use of Keccak256",
            "Vulnerability in Signature Management",
            "Invalid Signature Recovery",
            "Incorrect Signature Verification",
        ),
        ("Gas griefing", "Gas grief", "unchecked call", "Gas Limit DoS", "Denial of Service"),
        (
            "Unguarded function",
            "Missed access check",
            "(un?)intentional backdoor",
            "Unprotected function",
            "Unexpected privilege grants",
            "Unsecured Function",
        ),
        ("Invalid code", "Invalid"),
        ("Forced reception", "Forced Ether Reception", "Forced ETH Reception"),
        ("Arithmetic Overflow", "Integer overflow", "Integer overflow/underflow"),
        (
            "Bad randomness",
            "Predictable Random Number",
            "Predictable Randomness",
            "Timestamp Dependence",
            "Weak Randomness",
            "Unsecured Randomness",
            "Unsecured Random Number Generation",
        ),
        ("Arithmetic Reentrancy", "Reentrancy", "Vulnerable to Reentrancy"),
    )

    def __init__(self):
        self._synonyms = None

    @property
    def synonyms(self) -> dict:
        if self._synonyms is None:
            self._synonyms = self.load_synonyms()
        return self._synonyms

    def load_synonyms(self) -> dict:
        prepared = {}
        for pairs in self.SYNONYMS:
            prepared_pairs = [x.lower().strip() for x in pairs]
            for variant in prepared_pairs:
                for other in prepared_pairs:
                    prepared.setdefault(variant, set()).add(other)
        return prepared


synonyms_instance = SynonymsSingleton()


def create_session():
    retries = requests.adapters.Retry(total=10, status_forcelist=[500, 503, 504])
    session = requests.Session()
    session.mount("https://", requests.adapters.HTTPAdapter(max_retries=retries))
    session.mount("http://", requests.adapters.HTTPAdapter(max_retries=retries))
    return session


def is_synonyms(expected_result: str, answer: str) -> bool:
    expected_result = expected_result.strip().lower()
    answer = answer.strip().lower()
    if answer == expected_result:
        return True
    return answer in synonyms_instance.synonyms.get(expected_result, set())


class SolcSingleton:
    def __init__(self):
        self.all_versions = solcx.get_installable_solc_versions()

    def install_solc(self):
        installed_versions = solcx.get_installed_solc_versions()
        to_install = [x for x in self.all_versions if x not in installed_versions]
        for version in to_install:
            solcx.install_solc(version)

    def compile(self, code: str):
        suggested_version = solcx.install.select_pragma_version(code, self.all_versions)
        return solcx.compile_source(code, solc_version=suggested_version, output_values=["abi", "bin", "metadata"])


solc = SolcSingleton()
solc.install_solc()


def get_invalid_code():
    retries = int(os.getenv("MAX_TRIES", "10"))
    while retries > 0:
        retries -= 1
        try:
            code = SolidityGenerator.generate_contract()
            solc.compile(code)
        except Exception:
            break
        if retries == 0:
            raise ValueError("Failed to generate invalid contract code after multiple attempts.")

    return ValidatorTask(
        contract_code=code,
        from_line=1,
        to_line=len(code.splitlines()) + 1,
        vulnerability_class=KnownVulnerability.INVALID_CODE,
        task_type=TaskType.RANDOM_TEXT,
    )


def has_chained_member_access(ast: ast_models.ASTNode, min_depth=2):
    function_calls = find_node_with_properties(
        ast,
        node_type=ast_models.NodeType.FUNCTION_CALL
    )

    for function_call_node in function_calls:
        current = function_call_node.expression
        member_access_count = 0
    
        while current and current.node_type == ast_models.NodeType.MEMBER_ACCESS:
            member_access_count += 1
            current = current.expression
    
        if member_access_count >= min_depth and current and current.node_type == ast_models.NodeType.IDENTIFIER:
            return True
    return False
