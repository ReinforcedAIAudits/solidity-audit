import random
import re
import os
import time
from pydantic import BaseModel
from solc_ast_parser.models.ast_models import (
    build_function_header,
    IdentifierPath,
    UsingForDirective,
    ElementaryTypeName,
)
from solc_ast_parser.comments import insert_comments_into_ast
from solc_ast_parser.enrichment import restore_function_definitions, restore_storages
from solc_ast_parser.utils import find_node_with_properties, replace_node_to_multiple, remove_node, insert_node, shuffle_functions_and_storages
from solc_ast_parser.models import ast_models
from solc_ast_parser.models.ast_models import (
    SourceUnit,
    VariableDeclaration,
    FunctionDefinition,
)
from solc_ast_parser.models.base_ast_models import NodeType, SolidityConfig, QuotePreference
from solc_ast_parser.utils import (
    create_ast_from_source,
    create_ast_with_standart_input,
    get_contract_nodes,
)
from solcx.exceptions import SolcError

from ai_audits.protocol import ValidatorTask, TaskType
from config import Config


def get_contract_nodes_from_source(source: str, node_type: NodeType) -> list[ast_models.ASTNode]:
    ast = create_ast_from_source(source)
    return get_contract_nodes(ast, node_type)


def change_function_in_contract(ast: SourceUnit, new_function: FunctionDefinition):
    for node in ast.nodes:
        if node.node_type == NodeType.CONTRACT_DEFINITION:
            for idx, contract_node in enumerate(node.nodes):
                if contract_node.node_type == NodeType.FUNCTION_DEFINITION:
                    if contract_node.kind == new_function.kind and contract_node.name == new_function.name:
                        node.nodes[idx] = new_function
                        return ast
    raise ValueError("Function not found in contract")


def check_node_in_contract(ast: SourceUnit, node_type: NodeType, **kwargs):
    for node in ast.nodes:
        if node.node_type == NodeType.CONTRACT_DEFINITION:
            for contract_node in node.nodes:
                if contract_node.node_type == node_type:
                    for key, value in kwargs.items():
                        if getattr(contract_node, key) == value:
                            return True
    return False


def append_node_to_contract(ast: SourceUnit, node: FunctionDefinition | VariableDeclaration):
    for ast_node in ast.nodes:
        if ast_node.node_type == NodeType.CONTRACT_DEFINITION:
            if node.node_type == NodeType.FUNCTION_DEFINITION:
                if node.kind == "constructor":
                    source_constructor = next(func for func in ast_node.nodes if func.kind == "constructor")
                    if source_constructor:
                        source_constructor.body.statements += node.body.statements
                        continue

            else:
                last_var_declaration = next(
                    (
                        idx
                        for idx, contract_node in enumerate(reversed(ast_node.nodes))
                        if contract_node.node_type == NodeType.VARIABLE_DECLARATION
                    ),
                    None,
                )
                if last_var_declaration:
                    ast_node.nodes.insert(last_var_declaration, node)
                    continue

            ast_node.nodes.append(node)

    return ast


def find_function_in_contract(contract_ast: SourceUnit, function_name: str) -> FunctionDefinition | None:
    for node in contract_ast.nodes:
        if node.node_type == NodeType.CONTRACT_DEFINITION:
            for contract_node in node.nodes:
                if contract_node.node_type == NodeType.FUNCTION_DEFINITION:
                    if contract_node.name == function_name:
                        return contract_node
    return None


def find_function_boundaries(
    contract_ast: SourceUnit,
    contract_code: str,
    function_names: list[str],
) -> tuple[int, int]:
    for function_name in function_names:
        total_length = int(find_function_in_contract(contract_ast, function_name).src.split(":")[1])
        lines = contract_code.split("\n")
        for i, line in enumerate(lines, 1):
            if "function" in line and function_name in line:
                curr_length = 0
                for j in range(i - 1, len(lines)):
                    curr_length += len(lines[j]) + 1
                    if curr_length >= total_length:
                        return (i, j + 1)

                raise ValueError(
                    f"Something went wrong with length calculation: lines: {lines}, total_length: {total_length}, curr_length: {curr_length}"
                )

    raise ValueError(f"Function(-s) {function_names} not found or length mismatch.")


def create_contract(pseudocode: str) -> str:
    if "contract" in pseudocode:
        return pseudocode
    return f"// SPDX-License-Identifier: MIT\npragma solidity ^0.8.30;\ncontract PseudoContract {{\n\n{pseudocode}\n}}"


def insert_vulnerability_to_contract(
    contract_ast: SourceUnit,
    vulnerability_ast: SourceUnit,
) -> SourceUnit:
    vuln_nodes = get_contract_nodes(vulnerability_ast)
    for node in vuln_nodes:
        if (
            node.node_type == NodeType.FUNCTION_DEFINITION
            and node.kind == "constructor"
            or node.node_type in (NodeType.COMMENT, NodeType.MULTILINE_COMMENT)
        ):
            continue
        elif node.node_type == NodeType.FUNCTION_DEFINITION and check_node_in_contract(
            contract_ast, NodeType.FUNCTION_DEFINITION, name=node.name
        ):
            change_function_in_contract(contract_ast, node)
        elif not check_node_in_contract(contract_ast, node.node_type, name=node.name):
            contract_ast = append_node_to_contract(contract_ast, node)

    return contract_ast


def check_for_safe_math(ast: SourceUnit) -> bool:
    return bool(
        find_node_with_properties(ast, node_type=NodeType.MEMBER_ACCESS, member_name="add")
        or find_node_with_properties(ast, node_type=NodeType.MEMBER_ACCESS, member_name="sub")
        or find_node_with_properties(ast, node_type=NodeType.MEMBER_ACCESS, member_name="mul")
        or find_node_with_properties(ast, node_type=NodeType.MEMBER_ACCESS, member_name="div")
    ) and not bool(
        find_node_with_properties(ast, node_type=NodeType.CONTRACT_DEFINITION, contract_kind="library", name="SafeMath")
    )


def insert_safe_math(ast: SourceUnit) -> SourceUnit:
    if not check_for_safe_math(ast):
        print("SafeMath not needed, skipping insertion.")
        return ast

    safe_math_code = """
    library SafeMath {
        function add(uint256 a, uint256 b) internal pure returns (uint256) {
            uint256 c = a + b;
            require(c >= a, "SafeMath: addition overflow");
            return c;
        }

        function sub(uint256 a, uint256 b) internal pure returns (uint256) {
            require(b <= a, "SafeMath: subtraction overflow");
            return a - b;
        }

        function mul(uint256 a, uint256 b) internal pure returns (uint256) {
            if (a == 0) {
                return 0;
            }
            uint256 c = a * b;  
            require(c / a == b, "SafeMath: multiplication overflow");
            return c;
        }

        function div(uint256 a, uint256 b) internal pure returns (uint256) {
            require(b > 0, "SafeMath: division by zero");
            uint256 c = a / b;
            return c;
        }
    }
    """
    contract_code = ast.to_solidity()
    for line in contract_code.splitlines():
        if "pragma" in line:
            pragma_last_index = contract_code.splitlines().index(line) + len(line)

    contract_code = contract_code[:pragma_last_index] + "\n" + safe_math_code + "\n" + contract_code[pragma_last_index:]

    ast = create_ast_with_standart_input(contract_code)
    using_for_directive = UsingForDirective(
        id=999995,
        src="0:30:0",
        nodeType=NodeType.USING_FOR_DIRECTIVE,
        libraryName=IdentifierPath(
            id=999994,
            src="6:8:0",
            nodeType=NodeType.IDENTIFIER_PATH,
            name="SafeMath",
            nameLocations=["6:8:0"],
        ),
        typeName=ElementaryTypeName(id=999993, src="15:4:0", nodeType=NodeType.ELEMENTARY_TYPE_NAME, name="uint256"),
    )
    for contract in find_node_with_properties(ast, node_type=NodeType.CONTRACT_DEFINITION, contract_kind="contract"):
        insert_node(ast, contract.id, using_for_directive, "child_first")

    print(f"Inserting SafeMath library into contract:\n{ast.to_solidity()}")

    return ast


def inline_constructor(ast: SourceUnit, function_replacement_name: str = "initialize") -> SourceUnit:
    initialize_identifier = find_node_with_properties(
        ast,
        node_type=NodeType.IDENTIFIER,
        name=function_replacement_name,
    )

    if len(initialize_identifier) != 1:
        print(
            f"Error: Expected one identifier with name '{function_replacement_name}', found {len(initialize_identifier)}"
        )
        return ast

    intialize_call = find_node_with_properties(
        ast,
        node_type=NodeType.FUNCTION_CALL,
        expression=initialize_identifier[0],
    )

    if len(intialize_call) != 1:
        print(
            f"Error: Expected one function call with expression '{function_replacement_name}', found {len(intialize_call)}"
        )
        return ast

    initialize_expression = find_node_with_properties(
        ast,
        node_type=NodeType.EXPRESSION_STATEMENT,
        expression=intialize_call[0],
    )

    if len(initialize_expression) != 1:
        print(
            f"Error: Expected one expression statement with expression '{function_replacement_name}', found {len(initialize_expression)}"
        )
        return ast

    intialize_definition = find_node_with_properties(
        ast,
        node_type=NodeType.FUNCTION_DEFINITION,
        name=function_replacement_name,
    )

    if len(intialize_definition) != 1:
        print(
            f"Error: Expected one function definition with name '{function_replacement_name}', found {len(intialize_definition)}"
        )
        return ast

    if not replace_node_to_multiple(ast, initialize_expression[0].id, intialize_definition[0].body):
        print(
            f"Error: Failed to replace node with id {initialize_expression[0].id} with body of {intialize_definition[0].name}"
        )

    if not remove_node(ast, intialize_definition[0].id):
        print(f"Error: Failed to remove node with id {intialize_definition[0].id}")

    return ast


class Vulnerability(BaseModel):
    vulnerabilityClass: str
    code: str


def extract_storages_functions(vulnerability_source: str) -> tuple[list[str], list[str]]:
    try:
        vulnerability_ast = create_ast_with_standart_input(vulnerability_source)
    except SolcError as e:
        print(f"Error during vulnerability compilation: {e}")
        raise ValueError(f"Error during vulnerability compilation")

    ast_with_restored_storages = restore_storages(vulnerability_ast)

    return [
        node.to_solidity()
        for node in get_contract_nodes(ast_with_restored_storages, node_type=NodeType.VARIABLE_DECLARATION)
    ], [build_function_header(function) for function in restore_function_definitions(ast_with_restored_storages)]


def normalize_contract_name(contract_source: str) -> str:
    pattern = r"(contract\s+)([A-Za-z_][A-Za-z0-9_]*)"
    replacement = r"\1TaskContract_{}".format(int(time.time()))

    normalized_code = re.sub(pattern, replacement, contract_source, count=1)
    return normalized_code


def normalize_contract_code(contract_source: str) -> tuple[str, int]:
    lines = contract_source.lstrip().splitlines()
    new_lines = []

    license_pattern = r"^// SPDX-License-Identifier: .+"
    solidity_pattern = r"^pragma solidity\s+[^;]+;"

    filtered_lines = [
        line for line in lines if not re.match(license_pattern, line) and not re.match(solidity_pattern, line)
    ]

    new_lines.append("// SPDX-License-Identifier: MIT")
    new_lines.append("pragma solidity ^0.8.30;")
    new_lines.append("")

    new_lines.extend(filtered_lines)

    normalized_code = "\n".join(new_lines).lstrip("\n")
    normalized_code = normalize_contract_name(normalized_code)

    added_lines = len(new_lines) - len(lines)

    return normalized_code, added_lines


def normalize_task(task: ValidatorTask):
    # TODO: check code again after normalization ?
    normalized_code, added_lines = normalize_contract_code(task.contract_code)
    task.contract_code = normalized_code
    task.from_line += added_lines
    task.to_line += added_lines


def create_task(contract_source: str, raw_vulnerability: Vulnerability) -> ValidatorTask:
    try:
        ast_obj_contract = insert_comments_into_ast(contract_source, create_ast_from_source(contract_source))
    except SolcError as e:
        print(f"Error during valid contract compilation: {e}")
        raise ValueError(f"Error during valid contract compilation")

    vulnerability_contract = create_contract(raw_vulnerability.code)

    ast_obj_vulnerability = insert_comments_into_ast(
        vulnerability_contract, create_ast_with_standart_input(vulnerability_contract)
    )

    ast_obj_contract = inline_constructor(ast_obj_contract)
    ast_contract_with_vul = insert_vulnerability_to_contract(ast_obj_contract, ast_obj_vulnerability)
    ast_contract_with_vul = insert_safe_math(ast_contract_with_vul)
    contract_source = ast_contract_with_vul.to_solidity()

    print(f"Contract with vulnerability: {repr(contract_source)}")

    try:
        ast_contract_with_vul = create_ast_from_source(contract_source.replace("override", ""))
    except SolcError as e:
        print(f"Error during contract with vulnerability compilation: {e}")
        raise ValueError(f"Error during contract with vulnerability compilation")

    if not shuffle_functions_and_storages(ast_contract_with_vul):
        print("Error: Failed to shuffle functions and storages in the contract with vulnerability.")
    
    contract_source = ast_contract_with_vul.to_solidity(config=SolidityConfig(quote_preference=random.choice([QuotePreference.SINGLE, QuotePreference.DOUBLE])))
    from_line, to_line = find_function_boundaries(
        ast_contract_with_vul,
        contract_source,
        [node.name for node in get_contract_nodes(ast_obj_vulnerability, NodeType.FUNCTION_DEFINITION)],
    )

    return ValidatorTask(
        contract_code=contract_source,
        from_line=from_line,
        to_line=to_line,
        vulnerability_class=raw_vulnerability.vulnerabilityClass,
        task_type=TaskType.HYBRID,
    )
